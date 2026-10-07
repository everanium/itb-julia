# Size and duration parsing, the monotonic clock, and the human
# renderings of sizes, rates and durations. Every rendering here is
# part of the output contract shared with the Go harness and the other
# bindings' loop utilities, so the formats are fixed to the character,
# not to taste.

# Byte-size suffixes, longest first so "KIB" is matched before "K" and
# "B" never swallows the tail of another suffix. Every multiple is
# binary.
const _SIZE_SUFFIXES = (
    ("KIB", 1 << 10), ("KB", 1 << 10), ("K", 1 << 10),
    ("MIB", 1 << 20), ("MB", 1 << 20), ("M", 1 << 20),
    ("GIB", 1 << 30), ("GB", 1 << 30), ("G", 1 << 30),
    ("B", 1),
)

# Duration units in the order the grammar probes them, so "ms" is
# taken before "m" and "s".
const _DURATION_UNITS = (
    ("ns", 1.0), ("us", 1e3), ("ms", 1e6),
    ("s", 1e9), ("m", 60e9), ("h", 3600e9),
)

const _INT64_MAX = typemax(Int64)

"""
Parses a human byte-size string ("16MB", "1MiB", "512K", "1073741824")
into a byte count. Every suffix is a binary multiple: K/KB/KiB = 1024,
M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none = bytes; matching is
case-insensitive and surrounding whitespace is trimmed. Returns
`nothing` on a malformed or negative value.
"""
function parse_size(s::AbstractString)
    upper = uppercase(strip(s))
    isempty(upper) && return nothing
    mult = 1
    digits = upper
    for (suffix, m) in _SIZE_SUFFIXES
        if endswith(upper, suffix)
            mult = m
            digits = upper[1:(lastindex(upper) - length(suffix))]
            break
        end
    end
    digits = rstrip(digits)
    isempty(digits) && return nothing
    all(c -> '0' <= c <= '9', digits) || return nothing
    n = tryparse(Int64, digits)
    n === nothing && return nothing
    mult > 1 && n > div(_INT64_MAX, mult) && return nothing
    return Int(n * mult)
end

"""
Parses the Go duration grammar — a sequence of decimal numbers each
followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m", "1h30m",
"1.5s" — into nanoseconds. Returns `nothing` on a malformed string.
"""
function parse_duration(s::AbstractString)
    isempty(s) && return nothing
    total = 0.0
    pos = 1
    stop = lastindex(s)
    while pos <= stop
        start = pos
        while pos <= stop && (('0' <= s[pos] <= '9') || s[pos] == '.')
            pos = nextind(s, pos)
        end
        pos == start && return nothing
        value = tryparse(Float64, s[start:prevind(s, pos)])
        (value === nothing || value < 0.0) && return nothing
        mult = 0.0
        for (unit, ns) in _DURATION_UNITS
            tail = pos + length(unit) - 1
            if tail <= stop && s[pos:tail] == unit &&
               !(tail < stop && isletter(s[tail + 1]))
                mult = ns
                pos = tail + 1
                break
            end
        end
        mult == 0.0 && return nothing
        total += value * mult
    end
    total > 9.2e18 && return nothing
    return Int(trunc(total))
end

"""
Monotonic wall clock in nanoseconds.
"""
now_ns() = Int(time_ns())

"""
Renders a byte count with a binary-unit suffix: "1.0GiB", "16.0MiB",
"4.0KiB", "512B".
"""
function human_bytes(n::Integer)
    n >= (1 << 30) && return @sprintf("%.1fGiB", n / (1 << 30))
    n >= (1 << 20) && return @sprintf("%.1fMiB", n / (1 << 20))
    n >= (1 << 10) && return @sprintf("%.1fKiB", n / (1 << 10))
    return string(n, "B")
end

"""
Renders a possibly-negative byte delta with an explicit sign.
"""
human_bytes_signed(n::Integer) = n < 0 ? "-" * human_bytes(-n) : "+" * human_bytes(n)

"""
Binary MiB per second over a nanosecond window; 0 when the window is
unmeasured.
"""
function mb_per_sec(bytes::Integer, ns::Integer)
    ns <= 0 && return 0.0
    return bytes / (1 << 20) / (ns / 1e9)
end

"""
Renders a throughput as "123.4MB/s" (binary MiB per second) or "n/a"
for an unmeasured window.
"""
function human_rate(bytes::Integer, ns::Integer)
    ns <= 0 && return "n/a"
    return @sprintf("%.1fMB/s", mb_per_sec(bytes, ns))
end

# The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
# with trailing zeros removed; empty for zero.
function _fraction(frac_ns::Integer)
    frac_ns == 0 && return ""
    return "." * rstrip(@sprintf("%09d", frac_ns), '0')
end

"""
Renders a duration the way Go's time.Duration prints: below one second
as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss" where the
hour part appears when non-zero, the minute part when the hour part
appears or the minutes are non-zero, and the seconds carry their
fraction with trailing zeros removed ("5s", "5.003s", "1m0s",
"1m5.25s", "1h0m0s"). The caller rounds first.
"""
function human_duration(ns::Integer)
    ns = abs(ns)
    ns == 0 && return "0s"
    if ns < 1_000_000_000
        # Scale the sub-millisecond remainder to nine digits so the
        # fraction renderer sees the same shape it does for seconds.
        return string(div(ns, 1_000_000), _fraction(rem(ns, 1_000_000) * 1000), "ms")
    end
    hours, rest = divrem(ns, 3_600_000_000_000)
    minutes, rest = divrem(rest, 60_000_000_000)
    seconds, frac = divrem(rest, 1_000_000_000)
    out = hours > 0 ? string(hours, "h") : ""
    if hours > 0 || minutes > 0
        out *= string(minutes, "m")
    end
    return string(out, seconds, _fraction(frac), "s")
end
