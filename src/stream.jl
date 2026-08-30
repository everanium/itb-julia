# Incremental stream sessions over an open Pipeline.
#
# A session is a dumb byte pump: `StreamEncryptor` takes plaintext in
# through `write!` and yields wire through `read!` / `drain_all!`;
# `StreamDecryptor` is the mirror (wire in, plaintext out). All
# chunking, MAC, envelope, and wire-format decisions stay inside
# libitb. `free!` (or garbage collection) cancels the session and
# frees the Go-side state.

"Feed / drain slice size used by the pump loops."
const PUMP_BUF = 1 << 20

abstract type StreamSession end

# Shared constructor body: begin the Go-side session and pin the
# parent Pipeline via the `parent` field so it cannot be
# garbage-collected (and its Go-side handle freed) while this session
# is still live. The Go handle registry would degrade a stale-pipe
# StreamWrite/Read to a bad-handle status, but the nondeterminism is
# a correctness trap for a caller that lets the parent go out of
# scope.
function _begin_stream(begin_fn::Function, parent::Pipeline)::Csize_t
    href = Ref{Csize_t}(0)
    check(begin_fn(parent.handle, href))
    return href[]
end

"""
    StreamEncryptor(parent::Pipeline)

Incremental encrypt session: plaintext in, wire out. Obtain via
[`encrypt_stream`](@ref).
"""
mutable struct StreamEncryptor <: StreamSession
    parent::Pipeline
    handle::Csize_t
    ended::Bool

    function StreamEncryptor(parent::Pipeline)
        s = new(parent, _begin_stream(_ITB_Triple_EncryptStreamBegin, parent), false)
        finalizer(free!, s)
        return s
    end
end

"""
    StreamDecryptor(parent::Pipeline)

Incremental decrypt session: wire in, plaintext out. Obtain via
[`decrypt_stream`](@ref).
"""
mutable struct StreamDecryptor <: StreamSession
    parent::Pipeline
    handle::Csize_t
    ended::Bool

    function StreamDecryptor(parent::Pipeline)
        s = new(parent, _begin_stream(_ITB_Triple_DecryptStreamBegin, parent), false)
        finalizer(free!, s)
        return s
    end
end

"""
    write!(s, src)

Feeds `src` into the session. Blocks until the cipher chain accepts
the bytes; errors are sticky.
"""
function write!(s::StreamSession, src)
    src_b = _as_bytes(src)
    check(_ITB_Triple_StreamWrite(s.handle, src_b, length(src_b)))
    return nothing
end

# Contiguous view over a Vector{UInt8}: the slice type produced by
# `view(v, a:b)`. Borrowed directly by the FFI call (`ccall` GC-roots
# the parent through the view), skipping the `_as_bytes` copy — the
# per-slice copy dominates the feed side of large pump loops.
const _ContigBytes = SubArray{UInt8,1,Vector{UInt8},Tuple{UnitRange{Int}},true}

function write!(s::StreamSession, src::_ContigBytes)
    check(_ITB_Triple_StreamWrite(s.handle, src, length(src)))
    return nothing
end

"""
    end_stream!(s)

Signals end-of-input. Idempotent; `write!` after `end_stream!` fails
with `STATUS_BAD_INPUT`.
"""
function end_stream!(s::StreamSession)
    check(_ITB_Triple_StreamEnd(s.handle))
    s.ended = true
    return nothing
end

"""
    read!(s; max_bytes=PUMP_BUF) -> (chunk::Vector{UInt8}, finished::Bool)

Drains up to `max_bytes` produced bytes. Partial drains are normal.
After [`end_stream!`](@ref), an empty-spool read blocks until the
terminal bytes arrive or the session errors.
"""
function Base.read!(s::StreamSession; max_bytes::Integer=PUMP_BUF)
    buf = Vector{UInt8}(undef, Int(max_bytes))
    n, finished = read_into!(s, buf)
    resize!(buf, n)
    return buf, finished
end

"""
    read_into!(s, buf::Vector{UInt8}) -> (n::Int, finished::Bool)

Allocation-free drain primitive: fills up to `length(buf)` bytes of
`buf` in place and returns the byte count plus the finished flag.
`buf` is reusable across calls, which keeps a high-throughput drain
loop free of per-iteration buffer churn ([`read!`](@ref) allocates a
fresh vector every call). Bytes past `n` are unspecified.
"""
function read_into!(s::StreamSession, buf::Vector{UInt8})
    need = Ref{Csize_t}(0)
    fin = Ref{Cint}(0)
    check(_ITB_Triple_StreamRead(s.handle, buf, length(buf), need, fin))
    return Int(need[]), fin[] != 0
end

"""
    drain_all!(s) -> Vector{UInt8}

Calls [`end_stream!`](@ref) (if not yet called) and returns every
remaining output byte.
"""
function drain_all!(s::StreamSession)::Vector{UInt8}
    s.ended || end_stream!(s)
    out = UInt8[]
    buf = Vector{UInt8}(undef, PUMP_BUF)
    while true
        n, finished = read_into!(s, buf)
        n > 0 && append!(out, view(buf, 1:n))
        finished && return out
    end
end

"""
    pump!(s, src::IO, dst::IO)

Moves `src` through the session into `dst` with bounded memory: feed
a slice, drain available output, repeat; end + final drain on source
EOF.
"""
function pump!(s::StreamSession, src::IO, dst::IO)
    piece = Vector{UInt8}(undef, PUMP_BUF)
    out = Vector{UInt8}(undef, PUMP_BUF)
    while !eof(src)
        n = readbytes!(src, piece, PUMP_BUF)
        n == 0 && break
        write!(s, view(piece, 1:n))
        # Drain whatever the chain has produced so far; a read before
        # end_stream! never blocks.
        while true
            m, _ = read_into!(s, out)
            m == 0 && break
            write(dst, view(out, 1:m))
        end
    end
    end_stream!(s)
    while true
        m, finished = read_into!(s, out)
        m == 0 || write(dst, view(out, 1:m))
        finished && break
    end
    flush(dst)
    return nothing
end

"""
    free!(s::StreamSession)

Cancels (if still running) and releases the session. Safe to call
from any state and more than once; a GC finalizer covers the
non-explicit path.
"""
function free!(s::StreamSession)
    h = s.handle
    h == 0 && return nothing
    s.handle = 0
    try
        _ITB_Triple_StreamFree(h)
    catch
        # Finalizer context: see free!(::Pipeline).
    end
    return nothing
end

"""
    encrypt_stream(p::Pipeline) -> StreamEncryptor
    encrypt_stream(f::Function, p::Pipeline)

Opens an incremental encrypt session (plaintext in, wire out). The
`do`-block form passes the session to `f` and frees it on return.
"""
encrypt_stream(p::Pipeline) = StreamEncryptor(p)

function encrypt_stream(f::Function, p::Pipeline)
    s = StreamEncryptor(p)
    try
        return f(s)
    finally
        free!(s)
    end
end

"""
    decrypt_stream(p::Pipeline) -> StreamDecryptor
    decrypt_stream(f::Function, p::Pipeline)

Opens an incremental decrypt session (wire in, plaintext out). The
`do`-block form passes the session to `f` and frees it on return.
"""
decrypt_stream(p::Pipeline) = StreamDecryptor(p)

function decrypt_stream(f::Function, p::Pipeline)
    s = StreamDecryptor(p)
    try
        return f(s)
    finally
        free!(s)
    end
end
