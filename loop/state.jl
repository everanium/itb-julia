# Shared declarations of the loop stress harness: the resolved
# configuration, the per-worker state, the run state every worker
# shares, the read-write lock and barrier that keep iterations clear of
# handle mutation, and the shared output helpers every unit logs
# through.
#
# Julia-specific. A method signature naming a type is resolved when the
# method is defined, so two units that each name a type the other
# defines cannot both be loaded first; the worker unit drives
# maintenance and the ops unit reads the run state, which is exactly
# that shape. A declarations unit holding what both sides need is the
# same answer the C reference reaches with its header.

# Cipher surfaces the --shape flag selects.
const SHAPE_STREAM = 1          # session pump: begin / write / read / end
const SHAPE_MESSAGE = 2         # Single Message: one whole-buffer call
const SHAPE_STREAM_ONE_SHOT = 3 # stream surface, one whole-buffer call
const SHAPE_BOTH = 4            # all three, rotating by iteration number

const SHAPE_NAMES = ("stream", "message", "stream_one_shot", "both")

# --goroutines ceiling; the harness targets modest hosts and each
# worker pins payload-sized buffers for the whole run.
const MAX_WORKERS = 10

# The concurrency mode this binding implements, as the summary reports
# it (shared-handle / independent-handles / single).
const CONCURRENCY = "shared-handle"

# Largest slice fed to a stream session per write; the drain after
# every write uses the same bound.
const PUMP_SLICE = 1 << 20

# Signal numbers used below. Linux and the BSDs agree on all three,
# and those are the platforms the shared library ships for. The
# mask-operation selector does not agree between them, so it is read
# from the platform rather than written as one number.
const SIGINT_NO = Cint(2)
const SIGPIPE_NO = Cint(13)
const SIGTERM_NO = Cint(15)
const SIG_UNBLOCK = Sys.isapple() ? Cint(2) : Cint(1)

"""
The resolved command line.
"""
mutable struct Config
    duration_ns::Int        # run duration; ignored when iterations > 0
    iterations::Int         # per-worker count incl. warmup; 0 = duration-based
    workers_requested::Int  # the --goroutines value as given
    workers::Int            # the effective worker count
    shape::Int
    hash::String
    mac::String
    payload::Int            # bytes per iteration
    memlimit::Int           # resolved bytes; the effective limit once shaped
    memlimit_auto::Bool     # --memlimit auto: cap only when the runtime has none
    gogc::Int               # 0 = leave the runtime default
    parallax::Bool
    wrapper::Bool

    profile::String         # empty = shape-based profile pair
    key_bits::Int           # 0 = profile default
    nonce_bits::Int         # 0 = profile default
    blob_mode::Int          # container floor sizing mode: 1 (per-region, default) | 2 (per-container)
    chunk_size::Int         # 0 = profile default
    barrier_fill::Int       # 0 = profile default
    drbg::String            # DRBG fill primitive; "" = profile default (auto tier)
    gomaxprocs::Int         # 0 = inherit from the environment
    rekey_every::Int        # per-worker iterations between rotations; 0 = never
    blob_cycle_every::Int   # per-worker iterations between reopens; 0 = never
    payload_mode::Int
    seed::UInt64            # 0 = OS CSPRNG plaintexts
    json_output::Bool
    memprofile::String      # empty = none
end

Config() = Config(0, 0, 0, 0, SHAPE_STREAM, "", "", 0, 0, false, 0, true, true,
                  "", 0, 0, 1, 0, 0, "", 0, 0, 0, 1, UInt64(0), false, "")

"""
A reader-preferring read-write lock.

Julia-specific. The standard library ships a reentrant mutex and a
condition variable but no read-write lock, so the semantics the
contract calls for are built from them: readers admit each other while
no writer holds the lock, a writer waits for every reader to leave, and
the whole waiting set is woken on release. Waiting is a task yield
rather than a spin, so a worker blocked here releases its thread to
another worker.
"""
mutable struct RWLock
    cond::Threads.Condition
    readers::Int
    writer::Bool
end

RWLock() = RWLock(Threads.Condition(), 0, false)

function acquire_read(l::RWLock)
    lock(l.cond)
    try
        while l.writer
            wait(l.cond)
        end
        l.readers += 1
    finally
        unlock(l.cond)
    end
    return nothing
end

function release_read(l::RWLock)
    lock(l.cond)
    try
        l.readers -= 1
        l.readers == 0 && notify(l.cond)
    finally
        unlock(l.cond)
    end
    return nothing
end

function acquire_write(l::RWLock)
    lock(l.cond)
    try
        while l.writer || l.readers > 0
            wait(l.cond)
        end
        l.writer = true
    finally
        unlock(l.cond)
    end
    return nothing
end

function release_write(l::RWLock)
    lock(l.cond)
    try
        l.writer = false
        notify(l.cond)
    finally
        unlock(l.cond)
    end
    return nothing
end

"""
A reusable rendezvous for a fixed party count. The generation counter
is what a woken party checks, so a task that arrives at the next
rendezvous before a previous one has finished waking cannot slip
through the first.
"""
mutable struct Barrier
    parties::Int
    arrived::Int
    generation::Int
    cond::Threads.Condition
end

Barrier(parties::Int) = Barrier(parties, 0, 0, Threads.Condition())

function barrier_wait(b::Barrier)
    lock(b.cond)
    try
        g = b.generation
        b.arrived += 1
        if b.arrived == b.parties
            b.arrived = 0
            b.generation += 1
            notify(b.cond)
        else
            while b.generation == g
                wait(b.cond)
            end
        end
    finally
        unlock(b.cond)
    end
    return nothing
end

"""
One worker's private state: its plaintext, its generator, its
counters, and the error it stopped on.
"""
mutable struct Worker
    id::Int
    run::Any
    task::Any

    plaintext::Vector{UInt8}
    payload_mode::Int
    seeded::Bool
    rng::UInt64             # splitmix64 state when seeded

    wire::Vector{UInt8}     # pump-loop wire accumulator
    plain::Vector{UInt8}    # pump-loop round-trip accumulator
    scratch::Vector{UInt8}  # pump-loop drain slice

    # Counters written by this worker alone. The summary reads them
    # after every worker's task has been waited on, which orders the
    # writes ahead of the read.
    iters::Int
    bytes_enc::Int
    bytes_dec::Int
    nanos_enc::Int
    nanos_dec::Int

    failed::Bool
    error::String
end

Worker(id::Int, run) = Worker(id, run, nothing, UInt8[], 1, false, UInt64(0),
                              UInt8[], UInt8[], Vector{UInt8}(undef, PUMP_SLICE),
                              0, 0, 0, 0, 0, false, "")

"""
The state every worker shares: the Pipeline handles, the retained
blobs, the lock that keeps iterations clear of handle mutation, the
stop request, the barriers, and the baselines the summary reads.
"""
mutable struct RunState
    cfg::Config

    stream_pipe::Any        # nothing unless the shape uses it
    msg_pipe::Any           # nothing unless the shape uses it
    stream_profile::String
    msg_profile::String

    # Handle mutation. Iterations hold the read side for their whole
    # encrypt -> decrypt -> compare; rekey and blob reopen take the
    # write side, so no cipher call is in flight while a handle's
    # keying changes or the handle itself is swapped, and no encrypt is
    # separated from its decrypt by either.
    pipe_lock::RWLock

    # The blob Init handed out, replaced by every rekey; the input of
    # the next blob reopen. Guarded by pipe_lock.
    stream_blob::Vector{UInt8}
    msg_blob::Vector{UInt8}

    rekeys::Int
    blob_cycles::Int

    workers::Vector{Worker}

    # Warmup barrier: workers arrive at warmup_done after iteration 0
    # and at release once main has taken the baselines.
    warmup_done::Any
    release::Any

    # Set by the duration deadline, by a signal, or by a failing
    # worker; checked by every worker before it starts an iteration.
    stop::Threads.Atomic{Bool}

    # The last returning worker stamps finish_ns, so elapsed excludes
    # the wake-up latency of the waiter polling active.
    active::Threads.Atomic{Int}
    start_ns::Int
    finish_ns::Int

    # Baselines taken after the warmup barrier and at shutdown.
    rss_warmup::Int
    rss_peak::Int
    rss_final::Int
    pool_warmup::Vector{Int64}
    pool_steady::Vector{Int64}
end

RunState(cfg::Config) = RunState(cfg, nothing, nothing, "", "", RWLock(),
                                 UInt8[], UInt8[], 0, 0, Worker[], nothing, nothing,
                                 Threads.Atomic{Bool}(false), Threads.Atomic{Int}(0),
                                 0, 0, 0, 0, 0, Int64[], Int64[])

# Serialises the two emitters below. Workers log concurrently during
# maintenance, so the text and its newline have to reach the descriptor
# as one write.
const _OUT_LOCK = ReentrantLock()

# Julia-specific. Both emitters write to the descriptor directly rather
# than through the runtime's own streams. Two properties follow and
# both are required here: the whole terminated line leaves in a single
# write syscall, so a line from another worker cannot land between a
# text and its newline; and the write is synchronous, so a closed
# consumer delivers SIGPIPE to the writing thread at the moment of the
# write instead of surfacing later as an asynchronous error from the
# event loop, by which time the report would already be on its way.
function _write_all(fd::Cint, data::Vector{UInt8})
    off = 0
    total = length(data)
    GC.@preserve data while off < total
        n = ccall(:write, Cssize_t, (Cint, Ptr{UInt8}, Csize_t),
                  fd, pointer(data, off + 1), total - off)
        n <= 0 && break
        off += Int(n)
    end
    return nothing
end

"""
Prints one prefixed status line to stdout.
"""
function log_line(text::AbstractString)
    bytes = Vector{UInt8}(codeunits("[loop] " * text * "\n"))
    lock(_OUT_LOCK) do
        _write_all(Cint(1), bytes)
    end
    return nothing
end

"""
Prints one prefixed diagnostic to stderr.
"""
function err_line(text::AbstractString)
    bytes = Vector{UInt8}(codeunits("loop: " * text * "\n"))
    lock(_OUT_LOCK) do
        _write_all(Cint(2), bytes)
    end
    return nothing
end

on_off(b::Bool) = b ? "on" : "off"

"""
Renders an encoder policy env value for the summary: the raw string
when set, "default" when the shipped ladder applies.
"""
function policy_label(name::AbstractString)
    raw = get(ENV, name, nothing)
    raw === nothing && return "default"
    trimmed = lstrip(raw, (' ', '\t'))
    return isempty(trimmed) ? "default" : trimmed
end

"""
The failure detail a log line carries: the numeric status the binding's
own surface exposes and the finished sentence the library left behind.
Nothing is composed here — the wording arrives whole from the failing
call.
"""
function status_detail(err)
    err isa ITB.ITBError || return string(err)
    return "status $(err.status_code): $(err.last_error)"
end

"""
Records the worker's error text (first error wins) and requests a stop
of the whole run.
"""
function worker_fail(w::Worker, text::AbstractString)
    if !w.failed
        w.error = String(text)
        w.failed = true
    end
    w.run.stop[] = true
    return nothing
end
