# Handle-lifetime wrapper around the Triple Pipeline surface plus the
# profile-catalogue entries (inspect / register / lookup / profiles).

# Floor capacity for blob output buffers (Init / Save / Rekey).
const _BLOB_CAP = 64 * 1024

# Floor capacity for profile-JSON output buffers (Inspect / Lookup /
# Profiles).
const _JSON_CAP = 4 * 1024

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

# Folds the optional `(perm, wrap)` master pair into the
# (perm_master, wrap_master, masters_count) triple the Load entries
# take: count 0 selects the blob-embedded masters, count 2 overrides
# them.
function _masters(masters)
    masters === nothing && return (UInt8[], UInt8[], 0)
    return (_as_bytes(masters[1]), _as_bytes(masters[2]), 2)
end

"""
    Pipeline(profile; opts=nothing)

A Triple Pipeline session constructed against the named profile
(`ITB_Triple_Init`). `opts` is `nothing`, an opts string, an
[`Opts`](@ref) builder, or a `Dict` rendered to the URL-query grammar
libitb validates. The session blob is available through
[`save`](@ref); [`load`](@ref) / [`load_f`](@ref) reopen a session
from it and [`rekey!`](@ref) refreshes it. [`close!`](@ref) zeroes
key material inside libitb; [`free!`](@ref) releases the Go-side
handle (a GC finalizer covers the non-explicit path).

Streaming-decrypt caveat: chunked Streaming AEAD verifies per chunk,
so plaintext of verified chunks is released before a later chunk can
fail authentication.
"""
mutable struct Pipeline
    handle::Csize_t

    # Wraps an already-open libitb handle; not part of the public
    # API — use the profile constructor, `load`, or `load_f`.
    function Pipeline(handle::Csize_t)
        p = new(handle)
        finalizer(free!, p)
        return p
    end
end

function Pipeline(profile::AbstractString; opts=nothing)
    opts_s = render_opts(opts)
    href = Ref{Csize_t}(0)
    # On a blob-buffer retry the Init re-runs and yields a fresh
    # session (the undersized attempt is closed by libitb before
    # returning). The Init-time blob copy is dropped; `save` re-reads
    # it from the handle.
    _retry_once(_BLOB_CAP) do buf, need
        _ITB_Triple_Init(profile, opts_s, buf, length(buf), need, href)
    end
    return Pipeline(href[])
end

"""
    load(blob; masters=nothing) -> Pipeline

Reconstructs a Pipeline from a blob produced by [`save`](@ref) or
[`rekey!`](@ref) (`ITB_Triple_Load`). The blob's embedded profile
record is the sole structural source — no profile name, no opts.
`masters` is `nothing` to use the blob-embedded masters or a
`(perm, wrap)` pair of byte vectors to override them.
"""
function load(blob; masters=nothing)::Pipeline
    blob_b = _as_bytes(blob)
    pm, wm, count = _masters(masters)
    href = Ref{Csize_t}(0)
    check(_ITB_Triple_Load(blob_b, length(blob_b), pm, length(pm), wm, length(wm),
                           count, href))
    return Pipeline(href[])
end

"""
    load_f(path; masters=nothing) -> Pipeline

[`load`](@ref) for a blob stored in a file (`ITB_Triple_LoadF`); the
file is read inside the library.
"""
function load_f(path::AbstractString; masters=nothing)::Pipeline
    pm, wm, count = _masters(masters)
    href = Ref{Csize_t}(0)
    check(_ITB_Triple_LoadF(path, pm, length(pm), wm, length(wm), count, href))
    return Pipeline(href[])
end

"""
    save(p::Pipeline) -> Vector{UInt8}

The current serialised session blob — the bytes the constructor
produced, the bytes `load` re-marshalled, or the bytes of the latest
[`rekey!`](@ref).
"""
function save(p::Pipeline)::Vector{UInt8}
    return _retry_once(_BLOB_CAP) do buf, need
        _ITB_Triple_Save(p.handle, buf, length(buf), need)
    end
end

"""
    save_f(p::Pipeline, path)

Writes the current session blob to `path` inside the library (mode
`0600`; the containing directory must exist).
"""
function save_f(p::Pipeline, path::AbstractString)
    check(_ITB_Triple_SaveF(p.handle, path))
    return nothing
end

"""
    rekey!(p::Pipeline, perm, wrap) -> Vector{UInt8}

Rotates the parallax + wrapper masters and returns the refreshed
session blob (also observable through [`save`](@ref)). Must not run
concurrently with cipher calls or open stream sessions on the same
Pipeline.
"""
function rekey!(p::Pipeline, perm, wrap)::Vector{UInt8}
    pm = _as_bytes(perm)
    wm = _as_bytes(wrap)
    return _retry_once(_BLOB_CAP) do buf, need
        _ITB_Triple_Rekey(p.handle, pm, length(pm), wm, length(wm),
                          buf, length(buf), need)
    end
end

"""
    max_workers!(p::Pipeline, n::Integer)

Sets the worker cap for every subsequent cipher call. `n` is clamped,
never rejected: `n <= 0` selects auto (`runtime.NumCPU`), `1..256`
pins the cap, larger values are treated as 256. The cap is
per-machine tuning and is never written to the blob.
"""
function max_workers!(p::Pipeline, n::Integer)
    check(_ITB_Triple_MaxWorkers(p.handle, n))
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

Base.show(io::IO, p::Pipeline) =
    print(io, "Pipeline(", p.handle == 0 ? "freed" : "open", ")")

# --- profile catalogue ---------------------------------------------------

# Shared body for the JSON-returning catalogue entries: retry-once
# buffer, returned as the JSON text libitb wrote.
_json_out(f::Function)::String = String(_retry_once(f, _JSON_CAP))

"""
    inspect(blob) -> String

Decodes the blob's embedded profile record without opening a Pipeline
and returns it as the JSON text libitb emits (keys `name`, `mode`,
`width`, `hash`, `hashes`, `keybits`, `mac`, `tagstub`, `chunk`,
`wrapper`, `outer`, `parallax`, `palette`, `segment`; absent keys are
optional fields at their zero value). No registry read, no primitive
probe — a primitive name the local build lacks is returned unchanged.
"""
function inspect(blob)::String
    blob_b = _as_bytes(blob)
    return _json_out() do buf, need
        _ITB_Triple_Inspect(blob_b, length(blob_b), buf, length(buf), need)
    end
end

"""
    register(name, profile_json)

Registers a profile record under `name` so subsequent
[`Pipeline`](@ref) constructions and [`lookup`](@ref) calls resolve
it. `profile_json` is the record as JSON text — the shape
[`inspect`](@ref) / [`lookup`](@ref) return; a `name` key inside it,
if present, must be empty or equal to `name`. Validation (name
pattern, reserved prefixes, field rules) is performed by libitb; a
duplicate name fails with `STATUS_PROFILE_EXISTS`.
"""
function register(name::AbstractString, profile_json::AbstractString)
    check(_ITB_Triple_Register(name, profile_json))
    return nothing
end

"""
    lookup(name) -> String

Returns the profile record registered under `name` (a shipped
catalogue entry or a prior [`register`](@ref)) as JSON text. An
unknown name throws [`ITBError`](@ref) with `STATUS_UNKNOWN_PROFILE`.
"""
function lookup(name::AbstractString)::String
    return _json_out() do buf, need
        _ITB_Triple_Lookup(name, buf, length(buf), need)
    end
end

"""
    profiles() -> Vector{String}

The sorted list of every registered profile name. libitb writes a
JSON array of strings; profile names are restricted to `[a-z0-9-]`,
so the array unpacks by collecting the quoted items.
"""
function profiles()::Vector{String}
    text = _json_out() do buf, need
        _ITB_Triple_Profiles(buf, length(buf), need)
    end
    return [String(m.captures[1]) for m in eachmatch(r"\"([^\"]*)\"", text)]
end
