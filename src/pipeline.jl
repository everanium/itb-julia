# Handle-lifetime wrapper around the Triple Pipeline surface.

# Floor capacity for blob output buffers (Init / Rekey).
const _BLOB_CAP = 64 * 1024

# Pre-allocation formula for Message / one-shot stream outputs:
# payload * 5/4 + 65536.
_out_cap(payload::Int) = payload + payload ÷ 4 + 65_536

"""
    _retry_once(f, cap) -> Vector{UInt8}

Single retry-once dispatch site for every variable-size output
buffer: pre-allocate `cap`, and on `BUFFER_TOO_SMALL` retry once with
the exact size the FFI reported through the length out-param. The
retry is gated on the reported length strictly exceeding the current
capacity.
"""
function _retry_once(f::Function, cap::Int)::Vector{UInt8}
    buf = Vector{UInt8}(undef, cap)
    need = Ref{Csize_t}(0)
    rc = f(buf, need)
    if Int(rc) == STATUS_BUFFER_TOO_SMALL && Int(need[]) > length(buf)
        buf = Vector{UInt8}(undef, Int(need[]))
        rc = f(buf, need)
    end
    check(rc)
    resize!(buf, Int(need[]))
    return buf
end

"""
    Pipeline(profile; opts=nothing, blob=nothing, masters=nothing)

A Triple Pipeline session plus its exported blob bytes.

With `blob === nothing` a fresh session is initialised
(`ITB_Triple_Init`); with `blob` given the session is reconstructed
from a bundle produced by a prior init or [`rekey!`](@ref)
(`ITB_Triple_Open`). `opts` is `nothing`, an opts string, an
[`Opts`](@ref) builder, or a `Dict` rendered to the URL-query grammar
libitb validates; `masters` is `nothing` to use the blob-embedded
masters or a `(perm, wrap)` pair of byte vectors to override them
(open path only).

The blob carries the session bundle the receiver feeds back through
the `blob` keyword; [`rekey!`](@ref) refreshes it. [`close!`](@ref)
zeroes key material inside libitb; [`free!`](@ref) releases the
Go-side handle (a GC finalizer covers the non-explicit path).

Streaming-decrypt caveat: chunked Streaming AEAD verifies per chunk,
so plaintext of verified chunks is released before a later chunk can
fail authentication.
"""
mutable struct Pipeline
    handle::Csize_t
    blob::Vector{UInt8}

    function Pipeline(profile::AbstractString;
                      opts=nothing, blob=nothing, masters=nothing)
        opts_s = render_opts(opts)
        href = Ref{Csize_t}(0)
        local blob_out::Vector{UInt8}
        if blob === nothing
            # On a blob-buffer retry the Init re-runs and yields a
            # fresh session (the undersized attempt is closed by
            # libitb before returning).
            blob_out = _retry_once(_BLOB_CAP) do buf, need
                _ITB_Triple_Init(profile, opts_s, buf, length(buf), need, href)
            end
        else
            blob_b = _as_bytes(blob)
            if masters === nothing
                pm, wm, count = UInt8[], UInt8[], 0
            else
                pm = _as_bytes(masters[1])
                wm = _as_bytes(masters[2])
                (isempty(pm) || isempty(wm)) &&
                    throw(ITBError("master override buffers must be non-empty"))
                count = 2
            end
            check(_ITB_Triple_Open(profile, blob_b, length(blob_b), opts_s,
                                   pm, length(pm), wm, length(wm), count, href))
            blob_out = blob_b
        end
        p = new(href[], blob_out)
        finalizer(free!, p)
        return p
    end
end

"""
    blob(p::Pipeline) -> Vector{UInt8}

The exported session bundle bytes for the receiver side.
"""
blob(p::Pipeline) = p.blob

"""
    rekey!(p::Pipeline, perm, wrap)

Rotates the parallax + wrapper masters and refreshes [`blob`](@ref).
Must not run concurrently with cipher calls or open stream sessions
on the same Pipeline.
"""
function rekey!(p::Pipeline, perm, wrap)
    pm = _as_bytes(perm)
    wm = _as_bytes(wrap)
    p.blob = _retry_once(max(_BLOB_CAP, length(p.blob))) do buf, need
        _ITB_Triple_Rekey(p.handle, pm, length(pm), wm, length(wm),
                          buf, length(buf), need)
    end
    return nothing
end

"""
    close!(p::Pipeline)

Zeroes the Pipeline's key material and marks it closed. Idempotent;
subsequent cipher calls throw [`ITBError`](@ref) with
`STATUS_TRIPLE_CLOSED`.
"""
function close!(p::Pipeline)
    check(_ITB_Triple_Close(p.handle))
    return nothing
end

"Single Message encrypt: one call, one self-contained wire."
encrypt_message(p::Pipeline, plain) = _cipher(_ITB_Triple_EncryptMessage, p, plain)

"Receive-side counterpart of [`encrypt_message`](@ref)."
decrypt_message(p::Pipeline, wire) = _cipher(_ITB_Triple_DecryptMessage, p, wire)

"""
    encrypt_stream_one_shot(p::Pipeline, plain) -> Vector{UInt8}

One-shot stream encrypt for callers holding the whole plaintext in
memory. For bounded-memory streaming use [`encrypt_stream`](@ref).
"""
encrypt_stream_one_shot(p::Pipeline, plain) =
    _cipher(_ITB_Triple_EncryptStream, p, plain)

"Receive-side counterpart of [`encrypt_stream_one_shot`](@ref)."
decrypt_stream_one_shot(p::Pipeline, wire) =
    _cipher(_ITB_Triple_DecryptStream, p, wire)

# Shared body for the buffer-in / buffer-out cipher entries.
function _cipher(f::Function, p::Pipeline, src)::Vector{UInt8}
    src_b = _as_bytes(src)
    return _retry_once(_out_cap(length(src_b))) do buf, need
        f(p.handle, src_b, length(src_b), buf, length(buf), need)
    end
end

"""
    free!(p::Pipeline)

Releases the Pipeline handle (libitb closes and zeroes key material
first). Safe to call more than once; a GC finalizer covers the
non-explicit path.
"""
function free!(p::Pipeline)
    h = p.handle
    h == 0 && return nothing
    p.handle = 0
    try
        _ITB_Triple_Free(h)
    catch
        # Finalizer context: the library was loaded to obtain the
        # handle, so a failure here means process teardown — the OS
        # reclaims the library either way.
    end
    return nothing
end

# The blob bytes are elided — session-bundle material does not belong
# in debug logs.
Base.show(io::IO, p::Pipeline) = print(io, "Pipeline(blob_len=", length(p.blob), ")")

"""
    register_profile(name, opts)

Registers a user-defined Triple profile under `name` so subsequent
[`Pipeline`](@ref) constructions resolve it. `opts` follows the
register-profile grammar validated by Go (`mode`, `width`,
`innerHash` / `innerHashes`, `keyBits`, `macName`, `outerCipher`,
`parallaxPalette`, `parallaxSegmentSize`, `chunkSize`, `parallaxOn`,
`wrapperOn`). A duplicate name fails with `STATUS_PROFILE_EXISTS`.
"""
function register_profile(name::AbstractString, opts)
    check(_ITB_Triple_RegisterProfile(name, render_opts(opts)))
    return nothing
end
