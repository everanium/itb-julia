# Surface parity checks for the Julia binding; the deep suite lives
# in Go under the shipped tree.

using Test
using ITB

const CANONICAL_HASHES = [
    "areion256", "areion512", "blake2b256", "blake2b512", "blake2s",
    "blake3", "aescmac", "siphash24", "chacha20",
]

# Deterministic non-trivial payload (xorshift fill).
function payload(n::Int, seed::Integer)::Vector{UInt8}
    x = UInt64(seed) | 0x01
    out = Vector{UInt8}(undef, n)
    @inbounds for i in 1:n
        x ⊻= x << 13
        x ⊻= x >> 7
        x ⊻= x << 17
        out[i] = UInt8(x & 0xff)
    end
    return out
end

# Runs `f`, returning the thrown ITBError (fails the enclosing test on
# no throw or a foreign exception type).
function capture_itberror(f::Function)::ITBError
    try
        f()
    catch e
        e isa ITBError && return e
        rethrow()
    end
    error("expected ITBError, nothing was thrown")
end

@testset "ITB binding" begin
    @testset "version" begin
        v = version()
        @test !isempty(v)
        @test occursin(r"^\d+\.\d+", v)
    end

    @testset "hashes canonical order" begin
        hs = hashes()
        @test [h.name for h in hs] == CANONICAL_HASHES
        @test all(h -> h.width >= 128, hs)
    end

    @testset "profiles list" begin
        ps = profiles()
        @test "singlemsg-triple-mac-v1" in ps
        @test "streaming-noaead-triple-v1" in ps
        # Every listed profile initialises on the Go side.
        for p in ps
            pipe = Pipeline(p)
            @test !isempty(blob(pipe))
            free!(pipe)
        end
    end

    @testset "message round trip" begin
        sender = Pipeline("singlemsg-triple-mac-v1")
        receiver = Pipeline("singlemsg-triple-mac-v1"; blob=blob(sender))
        for size in (4 * 1024, 256 * 1024)
            plain = payload(size, size)
            wire = encrypt_message(sender, plain)
            @test wire != plain
            back = decrypt_message(receiver, wire)
            @test plain == back
        end
        free!(sender)
        free!(receiver)
    end

    @testset "stream round trip" begin
        sender = Pipeline("streaming-noaead-triple-v1")
        receiver = Pipeline("streaming-noaead-triple-v1"; blob=blob(sender))
        plain = payload(3 * 1024 * 1024 + 17, 42)

        wire = encrypt_stream(sender) do enc
            # Feed in uneven slices to exercise incremental writes.
            off = 0
            for upto in (1_000_000, 1_700_001, length(plain))
                write!(enc, plain[(off + 1):upto])
                off = upto
            end
            drain_all!(enc)
        end
        @test !isempty(wire)

        back = decrypt_stream(receiver) do dec
            write!(dec, wire)
            drain_all!(dec)
        end
        @test plain == back
        free!(sender)
        free!(receiver)
    end

    @testset "stream pump round trip" begin
        sender = Pipeline("streaming-aead-triple-mac-v1")
        receiver = Pipeline("streaming-aead-triple-mac-v1"; blob=blob(sender))
        plain = payload(2 * 1024 * 1024 + 3, 7)

        wire_io = IOBuffer()
        encrypt_stream(sender) do enc
            pump!(enc, IOBuffer(plain), wire_io)
        end
        back_io = IOBuffer()
        decrypt_stream(receiver) do dec
            pump!(dec, IOBuffer(take!(wire_io)), back_io)
        end
        @test plain == take!(back_io)
        free!(sender)
        free!(receiver)
    end

    @testset "read_into! partial drains" begin
        sender = Pipeline("streaming-noaead-triple-v1")
        receiver = Pipeline("streaming-noaead-triple-v1"; blob=blob(sender))
        plain = payload(1024 * 1024 + 13, 21)

        wire = UInt8[]
        encrypt_stream(sender) do enc
            # Feed through contiguous views so the zero-copy write!
            # method is exercised outside pump!.
            mid = length(plain) ÷ 2
            write!(enc, view(plain, 1:mid))
            write!(enc, view(plain, (mid + 1):length(plain)))
            end_stream!(enc)
            # Drain through a deliberately small reusable buffer so
            # every read is a partial fill.
            buf = Vector{UInt8}(undef, 4096)
            while true
                n, finished = read_into!(enc, buf)
                @test n <= length(buf)
                n > 0 && append!(wire, view(buf, 1:n))
                finished && break
            end
            # A drain after the finished flag stays clean: (0, true).
            n, finished = read_into!(enc, buf)
            @test n == 0
            @test finished
        end
        @test !isempty(wire)

        back = UInt8[]
        decrypt_stream(receiver) do dec
            write!(dec, wire)
            end_stream!(dec)
            buf = Vector{UInt8}(undef, 4096)
            while true
                n, finished = read_into!(dec, buf)
                n > 0 && append!(back, view(buf, 1:n))
                finished && break
            end
        end
        @test plain == back
        free!(sender)
        free!(receiver)
    end

    @testset "read! wrapper trims to the drained count" begin
        sender = Pipeline("streaming-noaead-triple-v1")
        plain = payload(64 * 1024, 3)
        encrypt_stream(sender) do enc
            write!(enc, plain)
            end_stream!(enc)
            total = 0
            while true
                chunk, finished = read!(enc; max_bytes=4096)
                @test length(chunk) <= 4096
                total += length(chunk)
                finished && break
            end
            @test total > 0
        end
        free!(sender)
    end

    @testset "bad profile maps to BAD_INPUT" begin
        err = capture_itberror(() -> Pipeline("no-such-profile"))
        @test err.status_code == ITB.STATUS_BAD_INPUT
        @test !isempty(sprint(showerror, err))
    end

    @testset "tampered wire fails decrypt" begin
        sender = Pipeline("singlemsg-triple-mac-v1")
        receiver = Pipeline("singlemsg-triple-mac-v1"; blob=blob(sender))
        wire = encrypt_message(sender, payload(8 * 1024, 3))
        # XOR a 64-byte span so the corruption is guaranteed to hit
        # data bits (a single flipped bit can land in a noise-bit
        # position the decode path ignores).
        mid = length(wire) ÷ 2
        for i in 1:64
            wire[mid + i] ⊻= 0xFF
        end
        err = capture_itberror(() -> decrypt_message(receiver, wire))
        @test err.status_code == ITB.STATUS_MAC_FAILURE
        free!(sender)
        free!(receiver)
    end

    @testset "closed pipeline reports TRIPLE_CLOSED" begin
        pipe = Pipeline("singlemsg-triple-mac-v1")
        close!(pipe)
        close!(pipe) # idempotent
        err = capture_itberror(() -> encrypt_message(pipe, payload(64, 1)))
        @test err.status_code == ITB.STATUS_TRIPLE_CLOSED
        free!(pipe)
    end

    @testset "large plaintext round trip" begin
        # Pattern P1: the pre-allocated output buffer plus a single
        # retry gated on strict len > cap must cover a > 1 MiB
        # payload.
        sender = Pipeline("singlemsg-triple-nomac-v1")
        receiver = Pipeline("singlemsg-triple-nomac-v1"; blob=blob(sender))
        plain = payload((1 << 20) + 4321, 9)
        wire = encrypt_message(sender, plain)
        back = decrypt_message(receiver, wire)
        @test plain == back
        free!(sender)
        free!(receiver)
    end

    @testset "rekey refreshes blob" begin
        sender = Pipeline("singlemsg-triple-mac-v1")
        old_blob = copy(blob(sender))
        rekey!(sender, fill(0x01, 32), fill(0x02, 32))
        @test blob(sender) != old_blob
        receiver = Pipeline("singlemsg-triple-mac-v1"; blob=blob(sender))
        wire = encrypt_message(sender, Vector{UInt8}("after rekey"))
        @test decrypt_message(receiver, wire) == Vector{UInt8}("after rekey")
        free!(sender)
        free!(receiver)
    end

    @testset "register profile and duplicate" begin
        name = "julia-binding-test-$(getpid())"
        opts = Opts()
        with_raw!(opts, "mode", "singlemsg-nomac")
        with_raw!(opts, "width", "256")
        with_raw!(opts, "innerHashes",
                  "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256")
        with_raw!(opts, "keyBits", "1024")
        with_raw!(opts, "parallaxOn", "false")
        with_raw!(opts, "wrapperOn", "false")
        register_profile(name, opts)
        sender = Pipeline(name)
        receiver = Pipeline(name; blob=blob(sender))
        wire = encrypt_message(sender, Vector{UInt8}("custom profile"))
        @test decrypt_message(receiver, wire) == Vector{UInt8}("custom profile")

        err = capture_itberror(() -> register_profile(name, opts))
        @test err.status_code == ITB.STATUS_PROFILE_EXISTS
        free!(sender)
        free!(receiver)
    end

    @testset "opts builder renders query pairs" begin
        o = Opts()
        with_key_bits!(o, 1024)
        with_parallax!(o, false)
        with_inner_hash!(o, "areion512")
        @test build(o) == "keyBits=1024&withParallax=false&innerHash=areion512"
    end

    @testset "runtime knobs report previous values" begin
        @test set_memory_limit(-1) isa Int
        @test set_gc_percent(-1) isa Int
    end
end
