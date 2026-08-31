# URL-query builder for the opts pass-through string.
#
# The builder performs no validation — every key and value is
# rendered into a percent-encoded query string and passed through to
# Go verbatim; libitb rejects unknown keys or bad values with a
# diagnostic surfaced via `ITBError`. Primitive / MAC / cipher /
# palette names are opaque strings.

"""
    Opts()

Builder producing the URL-query-encoded opts string consumed by
[`Pipeline`](@ref) and [`register_profile`](@ref). Every `with_*!`
setter returns the builder for fluent chaining; [`build`](@ref)
renders the accumulated pairs.
"""
struct Opts
    pairs::Vector{Pair{String,String}}
end

Opts() = Opts(Pair{String,String}[])

"""
    with_raw!(o::Opts, key, value) -> Opts

Escape hatch appending a raw `key=value` pair. Covers every key the
Go side accepts, including the register-profile grammar (`mode`,
`width`, `innerHashes`, `parallaxOn`, `wrapperOn`, …).
"""
function with_raw!(o::Opts, key::AbstractString, value::AbstractString)
    push!(o.pairs, String(key) => String(value))
    return o
end

"Hex-encodes the parallax master override (`pm`)."
with_perm_master!(o::Opts, master::AbstractVector{UInt8}) =
    with_raw!(o, "pm", bytes2hex(master))

"Hex-encodes the wrapper master override (`wm`)."
with_wrap_master!(o::Opts, master::AbstractVector{UInt8}) =
    with_raw!(o, "wm", bytes2hex(master))

with_parallax!(o::Opts, on::Bool) = with_raw!(o, "withParallax", string(on))
with_wrapper!(o::Opts, on::Bool) = with_raw!(o, "withWrapper", string(on))
with_max_workers!(o::Opts, n::Integer) = with_raw!(o, "maxWorkers", string(n))
with_nonce_bits!(o::Opts, n::Integer) = with_raw!(o, "nonceBits", string(n))
with_barrier_fill!(o::Opts, n::Integer) = with_raw!(o, "barrierFill", string(n))
with_chunk_size!(o::Opts, n::Integer) = with_raw!(o, "chunkSize", string(n))
with_key_bits!(o::Opts, n::Integer) = with_raw!(o, "keyBits", string(n))
with_parallax_segment_size!(o::Opts, n::Integer) =
    with_raw!(o, "parallaxSegmentSize", string(n))
with_mac_name!(o::Opts, name::AbstractString) = with_raw!(o, "macName", name)
with_inner_hash!(o::Opts, name::AbstractString) = with_raw!(o, "innerHash", name)

"""
    with_inner_hashes!(o::Opts, names) -> Opts

Per-call override for `Opts.MixedHashes [8]string` on the Go side.
Comma-joins the 8 slot names into the `innerHashes` opts-string key.
Slot ordering is `[noise, lock, data1, data2, data3, start1, start2, start3]`.
Fail-fast validation surfaces at Init on the Go side; a typo'd slot
or width mismatch surfaces with an error naming the offending slot.
When both this and `with_inner_hash!` are set, the mixed override
wins on the Go side.
"""
with_inner_hashes!(o::Opts, names) =
    with_raw!(o, "innerHashes", join(names, ","))

with_outer_cipher!(o::Opts, name::AbstractString) = with_raw!(o, "outerCipher", name)

"Comma-joins the palette names (`parallaxPalette`)."
with_parallax_palette!(o::Opts, names) =
    with_raw!(o, "parallaxPalette", join(names, ","))

# Unreserved query characters kept verbatim; the accepted values are
# ASCII names, decimal integers, `true` / `false`, hex, and
# comma-separated lists, so everything outside the URL-safe subset
# (plus `,`) is percent-escaped byte-wise.
_is_safe(b::UInt8) =
    (UInt8('A') <= b <= UInt8('Z')) || (UInt8('a') <= b <= UInt8('z')) ||
    (UInt8('0') <= b <= UInt8('9')) ||
    b in (UInt8('-'), UInt8('.'), UInt8('_'), UInt8('~'), UInt8(','))

function _enc(s::AbstractString)::String
    io = IOBuffer()
    for b in codeunits(s)
        if _is_safe(b)
            write(io, b)
        else
            print(io, '%', uppercase(string(b, base=16, pad=2)))
        end
    end
    return String(take!(io))
end

"""
    build(o::Opts) -> String

Renders the accumulated pairs as a percent-encoded query string.
"""
build(o::Opts) = join(("$(_enc(k))=$(_enc(v))" for (k, v) in o.pairs), "&")

"""
    render_opts(opts) -> String

Renders `nothing` / `AbstractString` / `Opts` / `AbstractDict` opts to
the URL-query pass-through string. The binding performs no validation
— libitb rejects unknown keys or bad values with a diagnostic
surfaced via `ITBError`.
"""
render_opts(::Nothing) = ""
render_opts(s::AbstractString) = String(s)
render_opts(o::Opts) = build(o)
render_opts(d::AbstractDict) =
    join(("$(_enc(string(k)))=$(_enc(string(v)))" for (k, v) in d), "&")
