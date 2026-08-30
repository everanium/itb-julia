# Micro-benchmarks for the Julia binding: encrypt_message (Single
# Message profile) and stream-session encrypt (Streaming Non-AEAD
# profile) throughput at 1 MiB / 16 MiB / 64 MiB. Wall-clock via
# time_ns(); output is a fixed-width table:
#
#   bench             size     mb_per_sec
#   message           1 MiB    <n>
#   ...
#
# Configuration is driven by environment variables so a side-by-side
# comparison with the root Go bench harness is straightforward:
#
#   ITB_NONCE_BITS      512         shipped secure default
#   ITB_KEY_BITS        1024        matches root Go BENCH3.md table
#   ITB_WITH_PARALLAX   false       root Go bench runs without parallax
#   ITB_WITH_WRAPPER    false       root Go bench runs without the wrapper
#   ITB_INNER_HASH      (profile)   opaque hash name
#   ITB_MSG_PROFILE     (fallback ITB_PROFILE, then singlemsg-triple-nomac-v1)
#   ITB_STREAM_PROFILE  (fallback ITB_PROFILE, then streaming-noaead-triple-v1)
#   ITB_BENCH_MIN_SEC   5           per-case wall-clock budget (seconds)

using Random
using ITB

# Per-case iteration floor alongside the wall-clock budget.
const BENCH_MIN_ITERS = 3
const SIZES = [1 << 20, 16 << 20, 64 << 20]

function bench_min_seconds()::Float64
    v = tryparse(Float64, get(ENV, "ITB_BENCH_MIN_SEC", ""))
    return (v !== nothing && v > 0) ? v : 5.0
end

# Reads the bench-shape env vars and builds the Opts. Defaults match
# root Go BENCH3.md so numbers are directly comparable.
function build_opts()::Opts
    o = Opts()
    with_raw!(o, "nonceBits", get(ENV, "ITB_NONCE_BITS", "512"))
    with_raw!(o, "keyBits", get(ENV, "ITB_KEY_BITS", "1024"))
    with_raw!(o, "withParallax",
              get(ENV, "ITB_WITH_PARALLAX", "false") in ("true", "1") ? "true" : "false")
    with_raw!(o, "withWrapper",
              get(ENV, "ITB_WITH_WRAPPER", "false") in ("true", "1") ? "true" : "false")
    inner = get(ENV, "ITB_INNER_HASH", "")
    isempty(inner) || with_raw!(o, "innerHash", inner)
    mac = get(ENV, "ITB_MAC_NAME", "")
    isempty(mac) || with_raw!(o, "macName", mac)
    return o
end

function profile_name(shape_env::String, fallback::String)::String
    p = get(ENV, shape_env, "")
    isempty(p) || return p
    p = get(ENV, "ITB_PROFILE", "")
    return isempty(p) ? fallback : p
end

size_label(size::Int) =
    size >= (1 << 20) ? "$(size >> 20) MiB" : "$(size >> 10) KiB"

mono() = time_ns() / 1.0e9

# Runs `f` until the wall-clock budget is spent (with an iteration
# floor + one untimed warm-up), then prints one table row.
function bench_case(f::Function, name::String, size::Int)
    f() # warm-up (also absorbs the first-call JIT compile)
    budget = bench_min_seconds()
    start = mono()
    elapsed = 0.0
    iters = 0
    while elapsed < budget || iters < BENCH_MIN_ITERS
        f()
        iters += 1
        elapsed = mono() - start
    end
    mb = size * iters / (1024.0 * 1024.0)
    println(rpad(name, 18), rpad(size_label(size), 9),
            round(mb / elapsed, digits=1))
end

function bench_message()
    pipe = Pipeline(profile_name("ITB_MSG_PROFILE", "singlemsg-triple-nomac-v1"); opts=build_opts())
    for size in SIZES
        # CSPRNG-fill so plaintext content matches the root Go bench
        # (crypto/rand). Not in the timing loop.
        plain = rand(RandomDevice(), UInt8, size)
        bench_case("message", size) do
            encrypt_message(pipe, plain)
        end
        # Pre-encrypt one wire outside the decrypt timing loop.
        dec_wire = encrypt_message(pipe, plain)
        bench_case("message-dec", size) do
            decrypt_message(pipe, dec_wire)
        end
    end
    free!(pipe)
end

function bench_stream()
    pipe = Pipeline(profile_name("ITB_STREAM_PROFILE", "streaming-noaead-triple-v1"); opts=build_opts())
    slice = ITB.PUMP_BUF
    # One reusable drain buffer across every iteration: the consumer
    # side of a real pump (socket / file sink) reads into a stable
    # buffer, so the bench does the same via read_into! instead of
    # allocating a fresh chunk vector per drain call.
    out = Vector{UInt8}(undef, slice)
    for size in SIZES
        plain = rand(RandomDevice(), UInt8, size)
        bench_case("stream", size) do
            encrypt_stream(pipe) do enc
                off = 0
                while off < length(plain)
                    hi = min(off + slice, length(plain))
                    write!(enc, view(plain, (off + 1):hi))
                    off = hi
                    # Drain available output so the spool stays
                    # bounded.
                    while true
                        n, _ = read_into!(enc, out)
                        n == 0 && break
                    end
                end
                end_stream!(enc)
                while true
                    n, finished = read_into!(enc, out)
                    finished && break
                end
            end
        end
        # Pre-encrypt one wire outside the decrypt timing loop.
        parts = UInt8[]
        encrypt_stream(pipe) do enc
            off = 0
            while off < length(plain)
                hi = min(off + slice, length(plain))
                write!(enc, view(plain, (off + 1):hi))
                off = hi
                while true
                    n, _ = read_into!(enc, out)
                    n == 0 && break
                    append!(parts, view(out, 1:n))
                end
            end
            end_stream!(enc)
            while true
                n, finished = read_into!(enc, out)
                n > 0 && append!(parts, view(out, 1:n))
                finished && break
            end
        end
        dec_wire = parts
        bench_case("stream-dec", size) do
            decrypt_stream(pipe) do dec
                off = 0
                while off < length(dec_wire)
                    hi = min(off + slice, length(dec_wire))
                    write!(dec, view(dec_wire, (off + 1):hi))
                    off = hi
                    while true
                        n, _ = read_into!(dec, out)
                        n == 0 && break
                    end
                end
                end_stream!(dec)
                while true
                    n, finished = read_into!(dec, out)
                    finished && break
                end
            end
        end
    end
    free!(pipe)
end

# Bench-scale allocation churn leaks Go scratch heap unboundedly
# without a soft memory cap + aggressive GC; the return values report
# the previous settings, not an error.
set_memory_limit(512 << 20)
set_gc_percent(20)

function bench_stream_one_shot()
    # Whole-buffer stream: one FFI round trip through
    # encrypt_stream_one_shot / decrypt_stream_one_shot per iteration.
    pipe = Pipeline(profile_name("ITB_STREAM_PROFILE", "streaming-noaead-triple-v1"); opts=build_opts())
    for size in SIZES
        plain = rand(RandomDevice(), UInt8, size)
        bench_case("stream_one_shot", size) do
            encrypt_stream_one_shot(pipe, plain)
        end
        # Pre-encrypt one wire outside the decrypt timing loop.
        dec_wire = encrypt_stream_one_shot(pipe, plain)
        bench_case("stream_one_shot-dec", size) do
            decrypt_stream_one_shot(pipe, dec_wire)
        end
    end
    free!(pipe)
end

println(rpad("bench", 18), rpad("size", 9), "mb_per_sec")
bench_message()
bench_stream()
bench_stream_one_shot()
