# Surface parity checks for the Julia binding; the deep suite lives
# in Go under the shipped tree.

using Test
using ITB

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

    @testset "profiles list" begin
        ps = profiles()
        @test "singlemsg-triple-mac-v1" in ps
        @test "streaming-noaead-triple-v1" in ps
        @test ps == sort(ps)
        # Every listed profile initialises on the Go side and resolves
        # through lookup.
        for p in ps
            pipe = Pipeline(p)
            @test !isempty(save(pipe))
            @test occursin("\"name\":\"$p\"", lookup(p))
            free!(pipe)
        end
        err = capture_itberror(() -> lookup("no-such-profile"))
        @test err.status_code == ITB.STATUS_UNKNOWN_PROFILE
    end

    @testset "message round trip" begin
        sender = Pipeline("singlemsg-triple-mac-v1")
        receiver = load(save(sender))
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
        receiver = load(save(sender))
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
        receiver = load(save(sender))
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
        receiver = load(save(sender))
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

    @testset "bad profile maps to UNKNOWN_PROFILE" begin
        err = capture_itberror(() -> Pipeline("no-such-profile"))
        @test err.status_code == ITB.STATUS_UNKNOWN_PROFILE
        @test !isempty(sprint(showerror, err))
    end

    @testset "tampered wire fails decrypt" begin
        sender = Pipeline("singlemsg-triple-mac-v1")
        receiver = load(save(sender))
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
        receiver = load(save(sender))
        plain = payload((1 << 20) + 4321, 9)
        wire = encrypt_message(sender, plain)
        back = decrypt_message(receiver, wire)
        @test plain == back
        free!(sender)
        free!(receiver)
    end

    @testset "rekey refreshes blob" begin
        sender = Pipeline("singlemsg-triple-mac-v1")
        old_blob = save(sender)
        rotated = rekey!(sender, fill(0x01, 32), fill(0x02, 32))
        @test rotated != old_blob
        @test save(sender) == rotated
        receiver = load(rotated)
        wire = encrypt_message(sender, Vector{UInt8}("after rekey"))
        @test decrypt_message(receiver, wire) == Vector{UInt8}("after rekey")
        free!(sender)
        free!(receiver)
    end

    @testset "register and duplicate" begin
        name = "julia-binding-test-$(getpid())"
        profile = """{
            "mode": "singlemsg-nomac",
            "width": 256,
            "hashes": ["blake3", "blake2s", "areion256", "blake2b256",
                       "chacha20", "blake3", "blake2s", "areion256"],
            "keybits": 1024,
            "parallax": false,
            "wrapper": false
        }"""
        register(name, profile)
        @test name in profiles()
        @test occursin("\"hashes\":[\"blake3\"", lookup(name))
        sender = Pipeline(name)
        receiver = load(save(sender))
        wire = encrypt_message(sender, Vector{UInt8}("custom profile"))
        @test decrypt_message(receiver, wire) == Vector{UInt8}("custom profile")

        err = capture_itberror(() -> register(name, profile))
        @test err.status_code == ITB.STATUS_PROFILE_EXISTS
        # Strict record decode on the Go side: an unknown key is
        # rejected there, not by the binding.
        err = capture_itberror(() -> register("$name-bad", "{\"mode\":\"singlemsg-nomac\",\"bogus\":1}"))
        @test err.status_code == ITB.STATUS_BAD_INPUT
        free!(sender)
        free!(receiver)
    end

    @testset "save / load round trip" begin
        sender = Pipeline("singlemsg-triple-mac-v1")
        blob = save(sender)
        @test !isempty(blob)
        @test save(sender) == blob
        receiver = load(blob)
        @test save(receiver) == blob
        wire = encrypt_message(sender, Vector{UInt8}("in-memory persist"))
        @test decrypt_message(receiver, wire) == Vector{UInt8}("in-memory persist")
        free!(sender)
        free!(receiver)
    end

    @testset "save_f / load_f round trip" begin
        mktempdir() do dir
            path = joinpath(dir, "session.blob")
            sender = Pipeline("singlemsg-triple-mac-v1")
            save_f(sender, path)
            @test filemode(path) & 0o777 == 0o600
            receiver = load_f(path)
            @test save(receiver) == save(sender)
            wire = encrypt_message(sender, Vector{UInt8}("file persist"))
            @test decrypt_message(receiver, wire) == Vector{UInt8}("file persist")
            err = capture_itberror(() -> load_f(joinpath(dir, "absent.blob")))
            @test err.status_code == ITB.STATUS_BAD_INPUT
            free!(sender)
            free!(receiver)
        end
    end

    @testset "load with master override" begin
        sender = Pipeline("singlemsg-triple-mac-v1")
        rotated = rekey!(sender, fill(0x31, 32), fill(0x32, 32))
        receiver = load(save(sender); masters=(fill(0x31, 32), fill(0x32, 32)))
        @test save(receiver) == rotated
        wire = encrypt_message(sender, Vector{UInt8}("master override"))
        @test decrypt_message(receiver, wire) == Vector{UInt8}("master override")
        free!(sender)
        free!(receiver)
    end

    @testset "inspect matches lookup" begin
        pipe = Pipeline("singlemsg-triple-mac-v1")
        record = inspect(save(pipe))
        @test occursin("\"name\":\"singlemsg-triple-mac-v1\"", record)
        @test occursin("\"mode\":\"singlemsg-mac\"", record)
        @test record == lookup("singlemsg-triple-mac-v1")
        err = capture_itberror(() -> inspect(Vector{UInt8}("not a blob")))
        @test err.status_code == ITB.STATUS_BAD_INPUT
        free!(pipe)
    end

    @testset "max_workers!" begin
        pipe = Pipeline("singlemsg-triple-mac-v1")
        max_workers!(pipe, 2)
        max_workers!(pipe, -1)     # clamped to auto, never rejected
        max_workers!(pipe, 10_000) # clamped to 256
        wire = encrypt_message(pipe, Vector{UInt8}("after cap change"))
        @test decrypt_message(pipe, wire) == Vector{UInt8}("after cap change")
        close!(pipe)
        err = capture_itberror(() -> max_workers!(pipe, 2))
        @test err.status_code == ITB.STATUS_TRIPLE_CLOSED
        free!(pipe)
        # A negative init-time cap is clamped as well.
        neg = Pipeline("singlemsg-triple-mac-v1"; opts=with_max_workers!(Opts(), -1))
        @test decrypt_message(neg, encrypt_message(neg, Vector{UInt8}("negative cap"))) ==
              Vector{UInt8}("negative cap")
        free!(neg)
    end

    @testset "opts builder renders query pairs" begin
        o = Opts()
        with_key_bits!(o, 1024)
        with_parallax!(o, false)
        with_inner_hash!(o, "areion512")
        @test build(o) == "keyBits=1024&withParallax=false&innerHash=areion512"
    end

    @testset "opts innerHashes override round trips on width-512 profile" begin
        # Per-call Opts.MixedHashes override over a width-512 shipped
        # base profile; the override lands in the blob's profile
        # record, so the receiver loads with no opts of its own.
        mix = Opts()
        with_inner_hashes!(mix, [
            "areion512", "blake2b512", "areion512", "blake2b512",
            "areion512", "blake2b512", "areion512", "blake2b512",
        ])
        sender = Pipeline("singlemsg-triple-mac-v1"; opts=mix)
        @test occursin("\"hashes\":[\"areion512\",\"blake2b512\"", inspect(save(sender)))
        receiver = load(save(sender))
        plain = payload(4096, 42)
        wire = encrypt_message(sender, plain)
        @test decrypt_message(receiver, wire) == plain
        free!(sender)
        free!(receiver)
    end

    @testset "runtime knobs report previous values" begin
        @test set_memory_limit(-1) isa Int
        @test set_gc_percent(-1) isa Int
    end
end
