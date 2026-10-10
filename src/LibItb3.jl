"""
Thin Julia proxy over the libitb3 shared library's Triple Pipeline
surface.

The package wraps the `ITB_Triple_*` C ABI exported by `cmd/cshared`
(libitb3.so / .dylib / .dll) through `Libdl` + `ccall` — runtime FFI,
no compile-time link, no C compiler at install time. Every hash-name
/ MAC-name / cipher-name / profile-name is an opaque string passed
through to Go for validation; the binding carries no ITB construction
logic of its own.

Example:

```julia
using LibItb3

sender = Pipeline("singlemsg-triple-mac-v1")
receiver = load(save(sender))
wire = encrypt_message(sender, Vector{UInt8}("hello"))
@assert decrypt_message(receiver, wire) == Vector{UInt8}("hello")
```
"""
module LibItb3

using Libdl

import Base: read!

export ITBError, Opts, Pipeline, StreamEncryptor, StreamDecryptor,
    profiles, version, drbg_auto_tier,
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
    with_outer_cipher!, with_drbg!, with_parallax_palette!, build

"The binding's own version (the library version is [`version`](@ref))."
const BINDING_VERSION = v"0.5.5"

include("errors.jl")
include("ffi_bridge.jl")
include("opts.jl")
include("pipeline.jl")
include("stream.jl")

"""
    version() -> String

Returns the libitb3 library version string.
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
    drbg_auto_tier() -> String

Returns the fill cipher the auto DRBG tier selected on this host
(`"aes-256-ctr"` or `"chacha20"`): the tier a Pipeline uses when its
`drbg` option is empty, resolved per host and recorded in no blob.
"""
function drbg_auto_tier()::String
    need = Ref{Csize_t}(0)
    rc = Int(_ITB_DRBGAutoTier(C_NULL, 0, need))
    (rc == STATUS_OK || rc == STATUS_BUFFER_TOO_SMALL) ||
        throw(ITBError(rc, last_error()))
    n = Int(need[])
    n <= 1 && return ""
    buf = Vector{UInt8}(undef, n)
    check(_ITB_DRBGAutoTier(buf, length(buf), need))
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

export set_gomaxprocs, write_heap_profile, pool_stats_len, pool_stats, hash_names

"""
    set_gomaxprocs(n::Integer) -> Int

Sets the Go runtime's `GOMAXPROCS` and returns the previous value. A
value of `n <= 0` queries without changing.
"""
set_gomaxprocs(n::Integer) = Int(_ITB_SetGOMAXPROCS(n))

"""
    write_heap_profile(path::AbstractString)

Writes a Go runtime heap profile (pprof format) to `path` after one
forced collection inside the library. A failure throws
[`ITBError`](@ref) carrying the diagnostic.
"""
function write_heap_profile(path::AbstractString)
    check(_ITB_WriteHeapProfile(path))
    return nothing
end

"""
    pool_stats_len() -> Int

The number of `Int64` slots [`pool_stats`](@ref) fills. Size a buffer
from this call rather than from a constant: the slot count follows the
number of hash-array pool tiers the library was built with.
"""
pool_stats_len() = Int(_ITB_PoolStatsLen())

"""
    pool_stats() -> Vector{Int64}

The library's pool counters as one `Int64` vector. Every entry is a
monotonically increasing total since library load, so a consumer
differences two snapshots. Slot 0 carries the hash-array tier count
`T`; tier `i` occupies the five slots at `1 + 5i` (starter width,
checkouts, constructor misses, regrows, bytes allocated); the scratch
byte pool and the parallax chunk pool occupy the eight slots at
`1 + 5T`.
"""
function pool_stats()::Vector{Int64}
    cap = pool_stats_len()
    cap <= 0 && return Int64[]
    buf = Vector{Int64}(undef, cap)
    need = Ref{Csize_t}(0)
    check(_ITB_PoolStats(buf, length(buf), need))
    resize!(buf, Int(need[]))
    return buf
end

"""
    hash_names() -> Vector{String}

The shipped inner-hash registry as a list of names. libitb3 writes a
JSON array of strings; primitive names are restricted to `[a-z0-9-]`,
so the array unpacks by collecting the quoted items.
"""
function hash_names()::Vector{String}
    text = String(_retry_once(_JSON_CAP) do buf, need
        _ITB_Triple_HashNames(buf, length(buf), need)
    end)
    return [String(m.captures[1]) for m in eachmatch(r"\"([^\"]*)\"", text)]
end

end # module LibItb3
