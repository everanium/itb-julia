# Plaintext content: the payload modes, the seeded per-worker
# generator, and the buffer fill from the operating-system CSPRNG.

# Payload mode selector values for the --payload-mode flag.
#
#   - fixed: one CSPRNG-generated buffer per worker, held unchanged
#     for the whole run (the default).
#   - rotating: the buffer is regenerated before every iteration, so
#     no two encrypt calls see the same plaintext.
#   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
#     all 0xFF) probing minimum-entropy plaintext handling.
#   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
#     structured text.
const PAYLOAD_FIXED = 1
const PAYLOAD_ROTATING = 2
const PAYLOAD_PATTERN_ZERO = 3
const PAYLOAD_PATTERN_FF = 4
const PAYLOAD_PATTERN_ASCII = 5

const PAYLOAD_NAMES = ("fixed", "rotating", "pattern-zero", "pattern-ff", "pattern-ascii")

payload_mode_name(mode::Integer) = PAYLOAD_NAMES[mode]

function parse_payload_mode(s::AbstractString)
    idx = findfirst(==(s), PAYLOAD_NAMES)
    return idx === nothing ? nothing : Int(idx)
end

"""
Seeded plaintext. The seed makes plaintext content reproducible so a
failing iteration can be replayed with the same bytes; it governs
nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn, so
a seeded run is a reproduction aid and never a security test. Each
worker's stream is domain-separated by its id so seeded workers still
hold pairwise-distinct buffers under the fixed and rotating modes. The
generator is splitmix64: a few lines in any language, which is why it
is the one every binding uses.
"""
seed_worker(seed::UInt64, worker_id::Integer) = seed + UInt64(worker_id) + UInt64(1)

# One splitmix64 draw; returns the advanced state and the output.
function _splitmix64(state::UInt64)
    state += 0x9E3779B97F4A7C15
    z = state
    z = (z ⊻ (z >> 30)) * 0xBF58476D1CE4E5B9
    z = (z ⊻ (z >> 27)) * 0x94D049BB133111EB
    return state, z ⊻ (z >> 31)
end

"""
Fills the first `n` bytes of `buf` from the operating-system CSPRNG.
Returns `false` when the draw failed.

Julia-specific. The draw goes to `/dev/urandom` through the raw
descriptor calls rather than through the runtime's random-device
wrapper, for two reasons: the read loop here is bounded by the
caller's own buffer, where a wrapper's per-call ceiling is an internal
detail a 64 MiB payload would run into; and an unbuffered descriptor
reads exactly the requested count, where a buffered stream would pull
a block of read-ahead the caller never asked for.
"""
function fill_random!(buf::Vector{UInt8}, n::Integer)
    n <= 0 && return true
    # O_RDONLY, which is zero on every platform the shared library
    # ships for.
    fd = ccall(:open, Cint, (Cstring, Cint), "/dev/urandom", Cint(0))
    fd < 0 && return false
    try
        off = 0
        GC.@preserve buf while off < n
            got = ccall(:read, Cssize_t, (Cint, Ptr{UInt8}, Csize_t),
                        fd, pointer(buf, off + 1), n - off)
            got <= 0 && return false
            off += Int(got)
        end
    finally
        ccall(:close, Cint, (Cint,), fd)
    end
    return true
end

"""
Writes one plaintext buffer according to the payload mode and returns
the advanced generator state, or `nothing` when the CSPRNG failed. The
fixed and rotating modes draw from the seeded generator when the run is
seeded and from the OS CSPRNG otherwise; the pattern modes are
deterministic regardless of the seed.
"""
function fill_payload!(buf::Vector{UInt8}, mode::Integer, seeded::Bool, rng::UInt64)
    n = length(buf)
    if mode == PAYLOAD_FIXED || mode == PAYLOAD_ROTATING
        if !seeded
            return fill_random!(buf, n) ? rng : nothing
        end
        i = 1
        while i <= n
            rng, value = _splitmix64(rng)
            take = min(n - i + 1, 8)
            for k in 0:(take - 1)
                buf[i + k] = UInt8((value >> (8 * k)) & 0xFF)
            end
            i += take
        end
        return rng
    elseif mode == PAYLOAD_PATTERN_ZERO
        fill!(buf, 0x00)
    elseif mode == PAYLOAD_PATTERN_FF
        fill!(buf, 0xFF)
    else
        for i in 1:n
            buf[i] = UInt8(0x41 + ((i - 1) % 26))
        end
    end
    return rng
end
