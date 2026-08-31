"""
Thin Julia proxy over the libitb shared library's Triple Pipeline
surface.

The package wraps the `ITB_Triple_*` C ABI exported by `cmd/cshared`
(libitb.so / .dylib / .dll) through `Libdl` + `ccall` — runtime FFI,
no compile-time link, no C compiler at install time. Every hash-name
/ MAC-name / cipher-name / profile-name is an opaque string passed
through to Go for validation; the binding carries no ITB construction
logic of its own.

Example:

```julia
using ITB

sender = Pipeline("singlemsg-triple-mac-v1")
receiver = Pipeline("singlemsg-triple-mac-v1"; blob=blob(sender))
wire = encrypt_message(sender, Vector{UInt8}("hello"))
@assert decrypt_message(receiver, wire) == Vector{UInt8}("hello")
```
"""
module ITB

using Libdl

import Base: read!

export ITBError, Opts, Pipeline, StreamEncryptor, StreamDecryptor, HashInfo,
    hashes, profiles, version, register_profile,
    set_memory_limit, set_gc_percent,
    blob, rekey!, close!, free!,
    encrypt_message, decrypt_message,
    encrypt_stream_one_shot, decrypt_stream_one_shot,
    encrypt_stream, decrypt_stream,
    write!, end_stream!, read!, read_into!, drain_all!, pump!,
    with_raw!, with_perm_master!, with_wrap_master!, with_parallax!,
    with_wrapper!, with_max_workers!, with_nonce_bits!, with_barrier_fill!,
    with_chunk_size!, with_key_bits!, with_parallax_segment_size!,
    with_mac_name!, with_inner_hash!, with_inner_hashes!,
    with_outer_cipher!, with_parallax_palette!, build

"The binding's own version (the library version is [`version`](@ref))."
const BINDING_VERSION = v"0.3.1"

include("errors.jl")
include("ffi_bridge.jl")
include("opts.jl")
include("pipeline.jl")
include("stream.jl")

"One shipped hash primitive: name + native width in bits."
struct HashInfo
    name::String
    width::Int
end

"""
    hashes() -> Vector{HashInfo}

The shipped hash primitive roster in registry order.
"""
function hashes()::Vector{HashInfo}
    out = HashInfo[]
    for i in 0:(Int(_ITB_HashCount()) - 1)
        need = Ref{Csize_t}(0)
        buf = Vector{UInt8}(undef, 128)
        check(_ITB_HashName(i, buf, length(buf), need))
        name = String(buf[1:max(Int(need[]) - 1, 0)])
        push!(out, HashInfo(name, Int(_ITB_HashWidth(i))))
    end
    return out
end

# Shipped Triple profile names accepted by the Pipeline constructor.
# The authoritative registry lives in Go; this roster mirrors it for
# discovery from the shell and tests.
const PROFILES = [
    "streaming-aead-triple-mac-v1",
    "streaming-noaead-triple-v1",
    "singlemsg-triple-mac-v1",
    "singlemsg-triple-nomac-v1",
    "blob-triple-mac-v1",
    "streaming-aead-triple-mac-mixed-v1",
    "streaming-noaead-triple-mixed-v1",
    "singlemsg-triple-mac-mixed-v1",
    "singlemsg-triple-nomac-mixed-v1",
]

"""
    profiles() -> Vector{String}

The shipped Triple profile names.
"""
profiles() = copy(PROFILES)

"""
    version() -> String

Returns the libitb library version string.
"""
function version()::String
    need = Ref{Csize_t}(0)
    rc = Int(_ITB_Version(C_NULL, 0, need))
    (rc == STATUS_OK || rc == STATUS_BUFFER_TOO_SMALL) ||
        throw(ITBError(rc, last_error()))
    n = Int(need[])
    n <= 1 && return ""
    buf = Vector{UInt8}(undef, n)
    check(_ITB_Version(buf, length(buf), need))
    return String(buf[1:max(Int(need[]) - 1, 0)])
end

"""
    set_memory_limit(limit_bytes::Integer) -> Int

Sets the Go runtime's soft heap limit in bytes and returns the
previous limit. A negative value queries without changing.
"""
set_memory_limit(limit_bytes::Integer) = Int(_ITB_SetMemoryLimit(limit_bytes))

"""
    set_gc_percent(pct::Integer) -> Int

Sets the Go GC trigger percentage and returns the previous value. A
negative value queries without changing.
"""
set_gc_percent(pct::Integer) = Int(_ITB_SetGCPercent(pct))

end # module ITB
