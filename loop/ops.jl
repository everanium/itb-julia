# The maintenance operations that mutate a live Pipeline handle between
# iterations: master rotation (--rekey-every) and blob reopen
# (--blob-cycle-every).

# Byte length of each fresh master drawn for a rotation. Matches the
# size Init auto-generates for both the parallax and the wrapper
# master.
const REKEY_MASTER_SIZE = 32

"""
Master rotation. Rotates the parallax + wrapper masters on every active
Pipeline under the write lock and retains the refreshed blob for
subsequent blob reopens. Masters are drawn fresh from the OS CSPRNG on
every rotation regardless of --seed (master rotation is pipeline
keying, not plaintext content); a disabled layer passes no bytes, which
Rekey ignores. The eight inner seeds and the MAC key are untouched by
design — Rekey targets only the two outer-layer master secrets.
"""
function rekey_pipes(w::Worker, iter::Integer)
    r = w.run
    perm = Vector{UInt8}(undef, r.cfg.parallax ? REKEY_MASTER_SIZE : 0)
    wrap = Vector{UInt8}(undef, r.cfg.wrapper ? REKEY_MASTER_SIZE : 0)
    if !fill_random!(perm, length(perm))
        worker_fail(w, "g$(w.id) iter $iter: csprng: parallax master")
        return false
    end
    if !fill_random!(wrap, length(wrap))
        worker_fail(w, "g$(w.id) iter $iter: csprng: wrapper master")
        return false
    end

    acquire_write(r.pipe_lock)
    count = 0
    try
        if r.stream_pipe !== nothing
            try
                r.stream_blob = ITB.rekey!(r.stream_pipe, perm, wrap)
            catch err
                err isa ITB.ITBError || rethrow()
                worker_fail(w, "g$(w.id) iter $iter: Rekey($(r.stream_profile)): $(status_detail(err))")
                return false
            end
        end
        if r.msg_pipe !== nothing
            try
                r.msg_blob = ITB.rekey!(r.msg_pipe, perm, wrap)
            catch err
                err isa ITB.ITBError || rethrow()
                worker_fail(w, "g$(w.id) iter $iter: Rekey($(r.msg_profile)): $(status_detail(err))")
                return false
            end
        end
        r.rekeys += 1
        count = r.rekeys
    finally
        release_write(r.pipe_lock)
    end
    log_line("rekey: g$(w.id) iter $iter rotated parallax + wrapper masters (rekey #$count)")
    return true
end

"""
Blob reopen. Reopens every active Pipeline from its retained blob under
the write lock: a fresh handle is loaded from the blob, the running
handle is freed, and the fresh one is swapped in, so every later
iteration round-trips through seeds and masters that survived a blob
crossing. The input is the blob Init or the latest Rekey handed out,
not a fresh Save: that is what a receiver holds, and reopening from it
proves the handed-out bytes rather than the live state. The blob
carries the Pipeline's full shape, so no override reaches the reopen.
On a Load failure the running handle stays and the failure aborts the
run.
"""
function blob_cycle_pipes(w::Worker, iter::Integer)
    r = w.run
    acquire_write(r.pipe_lock)
    count = 0
    try
        if r.stream_pipe !== nothing
            fresh = nothing
            try
                fresh = ITB.load(r.stream_blob)
            catch err
                err isa ITB.ITBError || rethrow()
                worker_fail(w, "g$(w.id) iter $iter: Load($(r.stream_profile)): $(status_detail(err))")
                return false
            end
            ITB.free!(r.stream_pipe)
            r.stream_pipe = fresh
        end
        if r.msg_pipe !== nothing
            fresh = nothing
            try
                fresh = ITB.load(r.msg_blob)
            catch err
                err isa ITB.ITBError || rethrow()
                worker_fail(w, "g$(w.id) iter $iter: Load($(r.msg_profile)): $(status_detail(err))")
                return false
            end
            ITB.free!(r.msg_pipe)
            r.msg_pipe = fresh
        end
        r.blob_cycles += 1
        count = r.blob_cycles
    finally
        release_write(r.pipe_lock)
    end
    log_line("blob-cycle: g$(w.id) iter $iter reopened from session blob (cycle #$count)")
    return true
end

"""
Handle mutation. Runs the periodic Pipeline-mutating operations after a
completed iteration: master rotation (--rekey-every) and blob reopen
(--blob-cycle-every). Both intervals count per-worker iterations; the
warmup iteration (iter 0) never triggers because the worker loop calls
this for iter >= 1 only. Rekey rewrites the outer-layer keying of a
live handle and a blob reopen replaces the handle outright; each takes
the write lock, so in-flight cipher calls on other workers drain before
anything changes and no encrypt is separated from its decrypt by
either. Returns false after recording a worker error.
"""
function worker_maintenance(w::Worker, iter::Integer)
    cfg = w.run.cfg
    if cfg.rekey_every > 0 && iter % cfg.rekey_every == 0
        rekey_pipes(w, iter) || return false
    end
    if cfg.blob_cycle_every > 0 && iter % cfg.blob_cycle_every == 0
        blob_cycle_pipes(w, iter) || return false
    end
    return true
end
