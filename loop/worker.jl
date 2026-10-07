# The worker: its task body (one warmup iteration, the warmup barrier,
# the main loop), one iteration, the session pump loop the stream shape
# drives, and the round-trip comparison that decides between a worker
# error and a data mismatch.

shape_name(shape::Integer) = SHAPE_NAMES[shape]

function parse_shape(s::AbstractString)
    idx = findfirst(==(s), SHAPE_NAMES)
    return idx === nothing ? nothing : Int(idx)
end

"""
Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair and
ITB drives the chunk loop internally; the C ABI has no reader / writer
entry, so the caller drives it: open a session, feed slices of at most
1 MiB, drain whatever the session has produced after every write (a
read before end never blocks), end, then drain until the session
reports finished (after end, a read on an empty spool blocks until the
terminal bytes arrive). The whole produced output lands in the worker's
reusable accumulator. The loop is written here rather than delegated to
the binding's pump convenience so it stands in the utility, at the same
place, in every language.
"""
function pump(pipe, encrypt::Bool, src::Vector{UInt8}, src_len::Int,
              out::Vector{UInt8}, scratch::Vector{UInt8})
    session = encrypt ? ITB.encrypt_stream(pipe) : ITB.decrypt_stream(pipe)
    try
        resize!(out, 0)
        off = 0
        while off < src_len
            slice = min(PUMP_SLICE, src_len - off)
            ITB.write!(session, view(src, (off + 1):(off + slice)))
            off += slice
            while true
                n, _ = ITB.read_into!(session, scratch)
                n == 0 && break
                append!(out, view(scratch, 1:n))
            end
        end
        ITB.end_stream!(session)
        while true
            n, finished = ITB.read_into!(session, scratch)
            n > 0 && append!(out, view(scratch, 1:n))
            finished && break
        end
    finally
        ITB.free!(session)
    end
    return nothing
end

# First offset at which the two buffers differ; the shorter length when
# one is a prefix of the other.
function first_difference(a::Vector{UInt8}, alen::Int, b::Vector{UInt8}, blen::Int)
    n = min(alen, blen)
    for i in 1:n
        a[i] == b[i] || return i - 1
    end
    return n
end

# Up to 16 bytes of buf from off (zero-based) as lowercase hex, or "-"
# when buf has no bytes there.
function hex_window(buf::Vector{UInt8}, len::Int, off::Int)
    off >= len && return "-"
    last = min(off + 16, len)
    return bytes2hex(view(buf, (off + 1):last))
end

# Records a worker error for a failed cipher call.
function cipher_fail(w::Worker, iter::Integer, shape::Integer, direction::AbstractString, err)
    worker_fail(w, "g$(w.id) iter $iter shape=$(shape_name(shape)): $direction: $(status_detail(err))")
    return nothing
end

"""
One iteration. In order: refill the plaintext under rotating mode; take
the read lock; pick the surface; encrypt (timed); decrypt (timed);
compare the round-trip with the plaintext; bump the counters; release
the lock. The whole round-trip runs under the read lock so
handle-mutating maintenance (rekey, blob reopen) never lands between an
encrypt and its matching decrypt — maintenance runs after this returns,
from the worker loop. Returns false after recording the worker error.
"""
function iterate_once(w::Worker, iter::Integer)
    r = w.run

    if w.payload_mode == PAYLOAD_ROTATING
        advanced = fill_payload!(w.plaintext, PAYLOAD_ROTATING, w.seeded, w.rng)
        if advanced === nothing
            worker_fail(w, "g$(w.id) iter $iter: payload refill: csprng")
            return false
        end
        w.rng = advanced
    end

    acquire_read(r.pipe_lock)
    try
        # Shape dispatch. message is one whole-buffer call on the Single
        # Message Pipeline; stream_one_shot is one whole-buffer call on
        # the streaming Pipeline (the C ABI's ITB_Triple_EncryptStream,
        # which routes to the same one-shot stream entry the Go
        # harness calls by name); stream opens a session on the same
        # streaming Pipeline and drives the chunk loop from here. Under
        # both the three rotate by iteration number so the session path
        # and the whole-buffer path alternate on one handle inside every
        # worker — the cross-path state-reuse hazard this harness exists
        # to catch.
        shape = r.cfg.shape
        if shape == SHAPE_BOTH
            shape = (SHAPE_STREAM, SHAPE_MESSAGE, SHAPE_STREAM_ONE_SHOT)[iter % 3 + 1]
        end

        want = w.plaintext
        want_len = length(want)
        got = want
        got_len = 0

        if shape == SHAPE_STREAM
            t0 = now_ns()
            try
                pump(r.stream_pipe, true, want, want_len, w.wire, w.scratch)
            catch err
                err isa ITB.ITBError || rethrow()
                cipher_fail(w, iter, shape, "encrypt", err)
                return false
            end
            w.nanos_enc += now_ns() - t0
            t0 = now_ns()
            try
                pump(r.stream_pipe, false, w.wire, length(w.wire), w.plain, w.scratch)
            catch err
                err isa ITB.ITBError || rethrow()
                cipher_fail(w, iter, shape, "decrypt", err)
                return false
            end
            w.nanos_dec += now_ns() - t0
            got = w.plain
            got_len = length(w.plain)
        else
            pipe = shape == SHAPE_MESSAGE ? r.msg_pipe : r.stream_pipe
            enc = shape == SHAPE_MESSAGE ? ITB.encrypt_message : ITB.encrypt_stream_one_shot
            dec = shape == SHAPE_MESSAGE ? ITB.decrypt_message : ITB.decrypt_stream_one_shot
            wire = UInt8[]
            t0 = now_ns()
            try
                wire = enc(pipe, want)
            catch err
                err isa ITB.ITBError || rethrow()
                cipher_fail(w, iter, shape, "encrypt", err)
                return false
            end
            w.nanos_enc += now_ns() - t0
            t0 = now_ns()
            try
                got = dec(pipe, wire)
            catch err
                err isa ITB.ITBError || rethrow()
                cipher_fail(w, iter, shape, "decrypt", err)
                return false
            end
            w.nanos_dec += now_ns() - t0
            got_len = length(got)
        end

        # Failure model. A cipher call that returns a non-OK status is a
        # worker error: it is recorded, the run is asked to stop, the
        # other workers finish their in-flight iteration, and the error
        # is listed in the summary with the FAIL verdict. A round-trip
        # that returns OK with different bytes is a data mismatch: the
        # process terminates here, without summary or cleanup, because
        # the Pipeline state that produced the wrong bytes is the
        # evidence and nothing that runs afterwards may touch it.
        if got_len != want_len || view(got, 1:got_len) != view(want, 1:want_len)
            off = first_difference(want, want_len, got, got_len)
            err_line(string("DATA MISMATCH g", w.id, " iter ", iter,
                            " shape=", shape_name(shape),
                            ": want ", want_len, " bytes, got ", got_len,
                            " bytes, first difference at offset ", off,
                            ": want ", hex_window(want, want_len, off),
                            " got ", hex_window(got, got_len, off)))
            # Julia-specific. _exit leaves the process on the spot
            # without running a finalizer, an atexit hook or another
            # task's buffered output, which is what "no summary, no
            # cleanup" asks for; exit would unwind and let the run carry
            # on around it.
            ccall(:_exit, Cvoid, (Cint,), Cint(3))
        end

        w.iters += 1
        w.bytes_enc += want_len
        w.bytes_dec += got_len
        return true
    finally
        release_read(r.pipe_lock)
    end
end

"""
The worker task body: one warmup iteration, the warmup barrier, then
the main loop until a stop is requested or the fixed per-worker
iteration budget (warmup included) is spent. A failing warmup still
passes both barriers so the launcher never waits on a worker that has
already given up.
"""
function worker_main(w::Worker)
    r = w.run
    try
        # Warmup iteration — counted in the totals; its completion feeds
        # the post-warmup baselines. Anything that escapes an iteration
        # other than a library status becomes a worker error rather than
        # a lost task: the barriers below have a fixed party count, so a
        # worker that unwound past them would leave the launcher waiting
        # for a rendezvous that can no longer happen.
        ok = false
        try
            ok = iterate_once(w, 0)
        catch err
            worker_fail(w, "g$(w.id) iter 0: $(typeof(err)): $err")
            ok = false
        end
        barrier_wait(r.warmup_done)
        barrier_wait(r.release)
        ok || return nothing

        iter = 1
        while true
            r.cfg.iterations > 0 && iter >= r.cfg.iterations && break
            r.stop[] && break
            try
                iterate_once(w, iter) || break
                worker_maintenance(w, iter) || break
            catch err
                worker_fail(w, "g$(w.id) iter $iter: $(typeof(err)): $err")
                break
            end
            iter += 1
        end
    finally
        worker_done(r)
    end
    return nothing
end

# Marks this worker returned; the last one to return stamps the finish
# instant the elapsed time is measured to.
function worker_done(r::RunState)
    if Threads.atomic_sub!(r.active, 1) == 1
        r.finish_ns = now_ns()
    end
    return nothing
end
