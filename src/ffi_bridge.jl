# Runtime symbol loading over the libitb shared library (Libdl +
# `ccall` through resolved function pointers).
#
# The library is loaded once per process and never unloaded, so the
# `dlsym`-resolved pointers stay valid for the process lifetime.
# Search order:
#
# 1. `ITB_LIBITB_PATH` environment variable (path to the shared
#    library file).
# 2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking up
#    from this file (in-repo builds).
# 3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
#    `DYLD_LIBRARY_PATH`, `PATH`).
#
# A resolve failure surfaces as `ITBError` at the first FFI call
# rather than a load-time crash. Every prototype below mirrors the
# ITB_Triple_* exports of cmd/cshared. `uintptr_t` handles cross as `Csize_t` (same
# width on every supported platform); input buffers cross as
# `Vector{UInt8}` borrowed for the duration of the call (`ccall`
# GC-roots its arguments); output buffers are freshly-allocated
# `Vector{UInt8}` resized to the reported length.

# The canonical library name; the resolved path is computed lazily on
# first use (see `_lib_handle`).
const LIBITB = "libitb"

function _lib_filename()::String
    Sys.iswindows() && return "libitb.dll"
    Sys.isapple() && return "libitb.dylib"
    return "libitb.so"
end

function _dist_subdir()::String
    os = Sys.iswindows() ? "windows" : Sys.isapple() ? "darwin" : "linux"
    arch = Sys.ARCH === :x86_64 ? "amd64" :
           Sys.ARCH === :aarch64 ? "arm64" : lowercase(String(Sys.ARCH))
    return "$os-$arch"
end

function _resolve_library_path()::String
    env = get(ENV, "ITB_LIBITB_PATH", "")
    isempty(env) || return env
    # src/ffi_bridge.jl -> bindings/julia/src; the repo root is three
    # levels up.
    repo = normpath(joinpath(@__DIR__, "..", "..", ".."))
    cand = joinpath(repo, "dist", _dist_subdir(), _lib_filename())
    isfile(cand) && return cand
    return _lib_filename()
end

# Process-wide handle of the loaded shared library (C_NULL until the
# first FFI call).
const _lib_handle = Ref{Ptr{Cvoid}}(C_NULL)
const _lib_lock = ReentrantLock()

function _handle()::Ptr{Cvoid}
    h = _lib_handle[]
    h != C_NULL && return h
    lock(_lib_lock) do
        h = _lib_handle[]
        h != C_NULL && return h
        path = _resolve_library_path()
        opened = Libdl.dlopen(path; throw_error=false)
        opened === nothing && throw(ITBError("failed to load libitb ($path)"))
        _lib_handle[] = opened
        return opened
    end
end

function _sym(name::Symbol)::Ptr{Cvoid}
    p = Libdl.dlsym(_handle(), name; throw_error=false)
    p === nothing && throw(ITBError("missing symbol $name in libitb"))
    return p
end

# --- roster / diagnostics ------------------------------------------------

_ITB_Version(buf, cap, need) =
    ccall(_sym(:ITB_Version), Cint, (Ptr{UInt8}, Csize_t, Ptr{Csize_t}), buf, cap, need)

_ITB_LastError(buf, cap, need) =
    ccall(_sym(:ITB_LastError), Cint, (Ptr{UInt8}, Csize_t, Ptr{Csize_t}), buf, cap, need)

_ITB_SetMemoryLimit(limit) =
    ccall(_sym(:ITB_SetMemoryLimit), Int64, (Int64,), limit)

_ITB_SetGCPercent(pct) =
    ccall(_sym(:ITB_SetGCPercent), Cint, (Cint,), pct)

# --- Triple Pipeline -----------------------------------------------------

_ITB_Triple_Init(profile, opts, blob_out, blob_cap, blob_len, out_handle) =
    ccall(_sym(:ITB_Triple_Init), Cint,
          (Cstring, Cstring, Ptr{UInt8}, Csize_t, Ptr{Csize_t}, Ptr{Csize_t}),
          profile, opts, blob_out, blob_cap, blob_len, out_handle)

_ITB_Triple_Load(blob, blob_len, pm, pm_len, wm, wm_len, count, out_handle) =
    ccall(_sym(:ITB_Triple_Load), Cint,
          (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t,
           Ptr{UInt8}, Csize_t, Csize_t, Ptr{Csize_t}),
          blob, blob_len, pm, pm_len, wm, wm_len, count, out_handle)

_ITB_Triple_LoadF(path, pm, pm_len, wm, wm_len, count, out_handle) =
    ccall(_sym(:ITB_Triple_LoadF), Cint,
          (Cstring, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Csize_t, Ptr{Csize_t}),
          path, pm, pm_len, wm, wm_len, count, out_handle)

_ITB_Triple_Save(h, blob_out, blob_cap, blob_len) =
    ccall(_sym(:ITB_Triple_Save), Cint,
          (Csize_t, Ptr{UInt8}, Csize_t, Ptr{Csize_t}),
          h, blob_out, blob_cap, blob_len)

_ITB_Triple_SaveF(h, path) =
    ccall(_sym(:ITB_Triple_SaveF), Cint, (Csize_t, Cstring), h, path)

_ITB_Triple_Inspect(blob, blob_len, json_out, json_cap, json_len) =
    ccall(_sym(:ITB_Triple_Inspect), Cint,
          (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{Csize_t}),
          blob, blob_len, json_out, json_cap, json_len)

_ITB_Triple_MaxWorkers(h, n) =
    ccall(_sym(:ITB_Triple_MaxWorkers), Cint, (Csize_t, Cint), h, n)

_ITB_Triple_Rekey(h, pm, pm_len, wm, wm_len, blob_out, blob_cap, blob_len) =
    ccall(_sym(:ITB_Triple_Rekey), Cint,
          (Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t,
           Ptr{UInt8}, Csize_t, Ptr{Csize_t}),
          h, pm, pm_len, wm, wm_len, blob_out, blob_cap, blob_len)

_ITB_Triple_Close(h) = ccall(_sym(:ITB_Triple_Close), Cint, (Csize_t,), h)

_ITB_Triple_Free(h) = ccall(_sym(:ITB_Triple_Free), Cint, (Csize_t,), h)

for (jl, c) in (
    (:_ITB_Triple_EncryptMessage, :ITB_Triple_EncryptMessage),
    (:_ITB_Triple_DecryptMessage, :ITB_Triple_DecryptMessage),
    (:_ITB_Triple_EncryptStream, :ITB_Triple_EncryptStream),
    (:_ITB_Triple_DecryptStream, :ITB_Triple_DecryptStream),
)
    @eval $jl(h, src, src_len, out, out_cap, out_len) =
        ccall(_sym($(QuoteNode(c))), Cint,
              (Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{Csize_t}),
              h, src, src_len, out, out_cap, out_len)
end

_ITB_Triple_Register(name, profile_json) =
    ccall(_sym(:ITB_Triple_Register), Cint, (Cstring, Cstring), name, profile_json)

_ITB_Triple_Lookup(name, json_out, json_cap, json_len) =
    ccall(_sym(:ITB_Triple_Lookup), Cint,
          (Cstring, Ptr{UInt8}, Csize_t, Ptr{Csize_t}),
          name, json_out, json_cap, json_len)

_ITB_Triple_Profiles(json_out, json_cap, json_len) =
    ccall(_sym(:ITB_Triple_Profiles), Cint,
          (Ptr{UInt8}, Csize_t, Ptr{Csize_t}),
          json_out, json_cap, json_len)

# --- incremental stream sessions ----------------------------------------

_ITB_Triple_EncryptStreamBegin(pipe, out_stream) =
    ccall(_sym(:ITB_Triple_EncryptStreamBegin), Cint, (Csize_t, Ptr{Csize_t}),
          pipe, out_stream)

_ITB_Triple_DecryptStreamBegin(pipe, out_stream) =
    ccall(_sym(:ITB_Triple_DecryptStreamBegin), Cint, (Csize_t, Ptr{Csize_t}),
          pipe, out_stream)

_ITB_Triple_StreamWrite(stream, src, src_len) =
    ccall(_sym(:ITB_Triple_StreamWrite), Cint, (Csize_t, Ptr{UInt8}, Csize_t),
          stream, src, src_len)

_ITB_Triple_StreamEnd(stream) =
    ccall(_sym(:ITB_Triple_StreamEnd), Cint, (Csize_t,), stream)

_ITB_Triple_StreamRead(stream, out, out_cap, out_len, finished) =
    ccall(_sym(:ITB_Triple_StreamRead), Cint,
          (Csize_t, Ptr{UInt8}, Csize_t, Ptr{Csize_t}, Ptr{Cint}),
          stream, out, out_cap, out_len, finished)

_ITB_Triple_StreamFree(stream) =
    ccall(_sym(:ITB_Triple_StreamFree), Cint, (Csize_t,), stream)

# --- helpers -------------------------------------------------------------

"""
    _as_bytes(data) -> Vector{UInt8}

Normalises the accepted buffer types to `Vector{UInt8}` for a
borrowed FFI input pointer. Non-`Vector` byte containers (views,
ranges) and strings are copied.
"""
_as_bytes(data::Vector{UInt8}) = data
_as_bytes(data::AbstractVector{UInt8}) = Vector{UInt8}(data)
_as_bytes(data::AbstractString) = Vector{UInt8}(codeunits(data))

"""
    last_error() -> String

Reads the `ITB_LastError` diagnostic (NUL-stripped). Returns the
empty string when no diagnostic is recorded or the library is
unavailable.
"""
function last_error()::String
    need = Ref{Csize_t}(0)
    rc = try
        Int(_ITB_LastError(C_NULL, 0, need))
    catch
        return ""
    end
    (rc == STATUS_OK || rc == STATUS_BUFFER_TOO_SMALL) || return ""
    n = Int(need[])
    n <= 1 && return ""
    buf = Vector{UInt8}(undef, n)
    rc = Int(_ITB_LastError(buf, length(buf), need))
    rc == STATUS_OK || return ""
    return String(buf[1:max(Int(need[]) - 1, 0)])
end

"""
    check(rc)

Maps a raw FFI return code onto `nothing` / a thrown [`ITBError`](@ref).
"""
function check(rc::Integer)
    Int(rc) == STATUS_OK && return nothing
    throw(ITBError(Int(rc), last_error()))
end
