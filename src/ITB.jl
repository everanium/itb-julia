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
receiver = load(save(sender))
wire = encrypt_message(sender, Vector{UInt8}("hello"))
@assert decrypt_message(receiver, wire) == Vector{UInt8}("hello")
```
"""
module ITB

using Libdl

import Base: read!

export ITBError, Opts, Pipeline, StreamEncryptor, StreamDecryptor,
    profiles, version,
    load, load_f, save, save_f, inspect, register, lookup,
    set_memory_limit, set_gc_percent,
    rekey!, max_workers!, close!, free!,
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
const BINDING_VERSION = v"0.4.1"

include("errors.jl")
include("ffi_bridge.jl")
include("opts.jl")
include("pipeline.jl")
include("stream.jl")

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
