# Long-run stress harness. The loop utility holds one Pipeline handle
# per exercised cipher surface for minutes, hammers it with concurrent
# encrypt -> decrypt -> compare round-trips from N worker tasks,
# rotates the outer masters and reopens the handle from its session
# blob on a schedule, and reports whether the process survived with
# every byte intact. It is the Julia binding's counterpart of the Go
# harness under tools/loop: the same flags, the same round structure,
# the same summary in both renderings.
#
# The default shape is full production: the Streaming AEAD profile with
# parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner hash,
# 1024-bit keys, and the compile-in 512-bit nonce width, driven through
# a stream session by three workers for five minutes on 16 MiB
# plaintexts. Every worker owns a distinct CSPRNG-generated plaintext
# held for the whole run, so any cross-call state leakage inside the
# Pipeline surfaces as a data mismatch between workers rather than
# cancelling out.
#
# A failure is one of two things. A cipher, rekey or load call that
# returns a non-OK status is a worker error: the run stops, the summary
# lists it, the verdict is FAIL and the exit code 1. A round-trip that
# returns without error but with different bytes is a data mismatch:
# the process terminates on the spot with exit code 3, printing the
# worker, the iteration and the first differing offset, and no summary
# — the state that produced the wrong bytes is the evidence. A crash
# inside the shared library or the host runtime has no exit code of its
# own here; surfacing it is what the utility is for.
#
# Usage:
#
#   ./run_loop.sh --duration 5m --goroutines 3 --shape stream \
#       --hash areion512 --mac hmac-blake3 --payload-size 16MB \
#       --memlimit auto --parallax on --wrapper on
#
# Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
# then the partial summary prints.

module Loop

import LibItb3 as ITB
using Printf

include("state.jl")
include("size.jl")
include("payload.jl")
include("ops.jl")
include("worker.jl")
include("summary.jl")

# Profiles the shape-based pair is built against when --profile is
# empty.
const DEFAULT_STREAM_PROFILE = "streaming-aead-triple-mac-v1"
const DEFAULT_MESSAGE_PROFILE = "singlemsg-triple-mac-v1"

# The primitive supplied for the parallax palette and the outer cipher
# when a profile leaves them unnamed. AES-CMAC is PRF-grade, so it is
# sound outside the Interlocked Barrier, and it is the closest relative
# of the AES-based inner primitive whose profiles need this fill.
const KEYSTREAM_FILL_CIPHER = "aescmac"

# ------------------------------------------------------------------ #
# Flags                                                              #
# ------------------------------------------------------------------ #

const KIND_INT = 1
const KIND_INT64 = 2
const KIND_UINT64 = 3
const KIND_STRING = 4
const KIND_BOOL = 5

# One command-line flag: its name, the type label the usage prints, its
# kind, its default, and its help text. Values are validated after the
# whole line is parsed. The table is in alphabetical order, which is
# the order the usage prints.
const FLAGS = (
    ("barrier-fill", "int", KIND_INT, 0,
     "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)"),
    ("blob-cycle-every", "int", KIND_INT64, 0,
     "reopen each pipeline from its session blob every N iterations per worker; 0 = never"),
    ("blob-mode", "int", KIND_INT, 1,
     "container floor sizing mode: 1 (per-region, default) | 2 (per-container)"),
    ("chunk-size", "string", KIND_STRING, "0",
     "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape"),
    ("drbg", "string", KIND_STRING, "",
     "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)"),
    ("duration", "duration", KIND_STRING, "5m",
     "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0"),
    ("gogc", "int", KIND_INT, 0,
     "GC trigger percentage; 0 = leave the runtime default"),
    ("gomaxprocs", "int", KIND_INT, 0,
     "Go runtime GOMAXPROCS override; 0 = inherit from the environment"),
    ("goroutines", "int", KIND_INT, 3,
     "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1"),
    ("hash", "string", KIND_STRING, "areion512",
     "inner ITB hash primitive name"),
    ("iterations", "int", KIND_INT64, 0,
     "fixed per-worker iteration count; 0 = duration-based"),
    ("json-output", "", KIND_BOOL, false,
     "print the final summary as one compact JSON object instead of log lines"),
    ("key-bits", "int", KIND_INT, 0,
     "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)"),
    ("mac", "string", KIND_STRING, "hmac-blake3",
     "MAC primitive name"),
    ("memlimit", "string", KIND_STRING, "auto",
     "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)"),
    ("memprofile", "string", KIND_STRING, "",
     "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none"),
    ("nonce-bits", "int", KIND_INT, 0,
     "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)"),
    ("parallax", "string", KIND_STRING, "on",
     "parallax layer: on | off"),
    ("payload-mode", "string", KIND_STRING, "fixed",
     "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii"),
    ("payload-size", "string", KIND_STRING, "16MB",
     "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)"),
    ("profile", "string", KIND_STRING, "",
     "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair"),
    ("rekey-every", "int", KIND_INT64, 0,
     "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never"),
    ("seed", "uint", KIND_UINT64, 0,
     "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts"),
    ("shape", "string", KIND_STRING, "stream",
     "cipher surface to exercise: stream | message | stream_one_shot | both"),
    ("wrapper", "string", KIND_STRING, "on",
     "wrapper layer: on | off"),
)

const INT32_MAX = 2147483647

function usage()
    out = IOBuffer()
    print(out, "Usage of loop:\n")
    for (name, label, kind, default, help) in FLAGS
        print(out, "  -", name, isempty(label) ? "" : " ", label, "\n")
        print(out, "    \t", help)
        # The default-value suffix follows the shape a Go flag set
        # prints: an integer default only when it is non-zero, a string
        # default only when it is non-empty.
        if kind == KIND_INT && default != 0
            print(out, " (default ", default, ")")
        elseif kind == KIND_STRING && !isempty(default)
            print(out, " (default \"", default, "\")")
        end
        print(out, "\n")
    end
    bytes = take!(out)
    lock(_OUT_LOCK) do
        _write_all(Cint(2), bytes)
    end
    return nothing
end

# Parses one value into its flag slot; nothing on a malformed value.
function assign_flag(kind::Int, value::AbstractString)
    if kind == KIND_INT || kind == KIND_INT64
        body = (startswith(value, '-') || startswith(value, '+')) ? value[2:end] : value
        (isempty(body) || !all(c -> '0' <= c <= '9', body)) && return nothing
        n = tryparse(Int64, value)
        n === nothing && return nothing
        kind == KIND_INT && (n > INT32_MAX || n < -INT32_MAX) && return nothing
        return Int(n)
    elseif kind == KIND_UINT64
        startswith(value, '-') && return nothing
        body = startswith(value, '+') ? value[2:end] : value
        (isempty(body) || !all(c -> '0' <= c <= '9', body)) && return nothing
        n = tryparse(UInt64, body)
        return n === nothing ? nothing : n
    elseif kind == KIND_STRING
        return String(value)
    end
    value == "true" && return true
    value == "false" && return false
    return nothing
end

"""
Parses argv into the raw flag values. Accepts -name value, --name
value, -name=value and --name=value; a boolean flag takes no value
unless given as -name=true / -name=false. Returns (0, values), (1,
values) for -h / --help (usage printed), or (-1, values) after printing
the error.
"""
function parse_argv(argv::Vector{String})
    raw = Dict{String,Any}(name => default for (name, _, _, default, _) in FLAGS)
    kinds = Dict{String,Int}(name => kind for (name, _, kind, _, _) in FLAGS)
    i = 1
    while i <= length(argv)
        arg = argv[i]
        if !startswith(arg, '-') || arg == "-"
            err_line("unexpected positional arguments: [$arg]")
            return -1, raw
        end
        name = startswith(arg, "--") ? arg[3:end] : arg[2:end]
        if name == "h" || name == "help"
            usage()
            return 1, raw
        end
        value = nothing
        eq = findfirst('=', name)
        if eq !== nothing
            value = name[(eq + 1):end]
            name = name[1:(eq - 1)]
        end
        if !haskey(kinds, name)
            err_line("flag provided but not defined: -$name")
            usage()
            return -1, raw
        end
        kind = kinds[name]
        if value === nothing
            if kind == KIND_BOOL
                value = "true"
            elseif i + 1 <= length(argv)
                i += 1
                value = argv[i]
            else
                err_line("flag needs an argument: -$name")
                return -1, raw
            end
        end
        parsed = assign_flag(kind, value)
        if parsed === nothing
            err_line("invalid value \"$value\" for flag -$name")
            return -1, raw
        end
        raw[name] = parsed
        i += 1
    end
    return 0, raw
end

# Maps "on" / "off" to a Bool; nothing otherwise.
function parse_on_off(v::AbstractString)
    v == "on" && return true
    v == "off" && return false
    return nothing
end

# Whether name is in the shipped hash registry the binding enumerates.
function hash_registered(name::AbstractString)
    try
        return name in ITB.hash_names()
    catch err
        err isa ITB.ITBError || rethrow()
        return false
    end
end

# Julia-specific. The binding returns a profile record as the JSON text
# the library wrote, so the three readers below probe that text
# directly. Record keys are fixed and record strings are restricted to
# [a-z0-9-], so a quoted run is one complete value and a key match is
# unambiguous.
function record_int(json::AbstractString, key::AbstractString)
    m = match(Regex("\"" * key * "\":(-?[0-9]+)"), json)
    return m === nothing ? 0 : parse(Int, m.captures[1])
end

function record_str(json::AbstractString, key::AbstractString)
    m = match(Regex("\"" * key * "\":\"([^\"]*)\""), json)
    (m === nothing || isempty(m.captures[1])) && return "-"
    return String(m.captures[1])
end

record_bool(json::AbstractString, key::AbstractString) = occursin("\"$key\":true", json)

record_has(json::AbstractString, key::AbstractString) = occursin("\"$key\":", json)

"""
Folds a keystream primitive into opts for any layer the named profile
leaves unfilled but the operator asked for.

A profile built around a primitive that is safe only inside the
Interlocked Barrier ships with no parallax palette and no outer cipher:
both layers run outside the barrier, where that primitive would stand
bare, so the recipe leaves them unnamed rather than naming a primitive
that must not key them. Engaging either layer therefore needs a
keystream-capable primitive supplied from outside the recipe; without
it construction fails on a palette below its minimum or an unnamed
outer cipher, and the primitive that most deserves stressing becomes
the one that cannot be stressed with those layers engaged.

Overrides fold into the resolved record the blob carries, so the
receiver rebuilds the same shape from the blob alone.

Returns 1 when a layer was filled, 0 when none needed it, -1 on a
lookup failure (message already printed).
"""
function fill_keystream_layers(name::AbstractString, opts, want_parallax::Bool,
                               want_wrapper::Bool)
    json = ""
    try
        json = ITB.lookup(name)
    catch err
        err isa ITB.ITBError || rethrow()
        err_line("--profile \"$name\" is not a registered triple profile")
        return -1
    end
    filled = 0
    if want_parallax && !record_has(json, "palette")
        ITB.with_parallax_palette!(opts, fill(KEYSTREAM_FILL_CIPHER, 3))
        if !record_has(json, "segment")
            # A recipe that never carried a palette never carried a
            # segment size either, and the schedule rejects zero.
            ITB.with_parallax_segment_size!(opts, 4093)
        end
        filled = 1
    end
    if want_wrapper && !record_has(json, "outer")
        ITB.with_outer_cipher!(opts, KEYSTREAM_FILL_CIPHER)
        filled = 1
    end
    return filled
end

"""
Resolves a registered profile to the shape family its record's mode
exposes by reading the record through the binding's lookup: a mode
beginning with "streaming" exposes the stream surfaces, one beginning
with "singlemsg" the message surface, "blob-only" none. Prints the
validation message and returns nothing on rejection.
"""
function profile_surface(name::AbstractString)
    json = ""
    try
        json = ITB.lookup(name)
    catch err
        err isa ITB.ITBError || rethrow()
        err_line("--profile \"$name\" is not a registered triple profile")
        return nothing
    end
    mode = record_str(json, "mode")
    startswith(mode, "streaming") && return SHAPE_STREAM
    startswith(mode, "singlemsg") && return SHAPE_MESSAGE
    err_line("--profile \"$name\" carries no cipher surface (blob-only mode)")
    return nothing
end

"""
Applies a --profile's surface to the requested shape: a
message-surface profile forces message; a stream-surface profile keeps
stream or stream_one_shot as requested and turns message or both into
stream.
"""
function narrow_shape(requested::Int, surface::Int)
    surface == SHAPE_MESSAGE && return SHAPE_MESSAGE
    return requested == SHAPE_STREAM_ONE_SHOT ? SHAPE_STREAM_ONE_SHOT : SHAPE_STREAM
end

"""
Builds the resolved config from argv. Returns (0, cfg), (1, cfg) for
help, or (-1, cfg) after printing "loop: <message>" for the first
failing rule.
"""
function parse_flags(argv::Vector{String})
    cfg = Config()
    rc, raw = parse_argv(argv)
    rc != 0 && return rc, cfg

    duration_ns = parse_duration(string(raw["duration"]))
    if duration_ns === nothing || duration_ns <= 0
        err_line("--duration must be positive, got $(raw["duration"])")
        return -1, cfg
    end
    cfg.duration_ns = duration_ns
    cfg.iterations = Int(raw["iterations"])
    if cfg.iterations < 0
        err_line("--iterations must be >= 0, got $(cfg.iterations)")
        return -1, cfg
    end
    goroutines = Int(raw["goroutines"])
    if goroutines < 1 || goroutines > MAX_WORKERS
        err_line("--goroutines must be in 1..$MAX_WORKERS, got $goroutines")
        return -1, cfg
    end
    # Concurrency mode. This binding runs shared-handle: the binding's
    # calls cross the FFI boundary without holding any interpreter-wide
    # lock, so worker tasks on separate threads of the default pool
    # call into one Pipeline handle concurrently, which the shared
    # library permits after construction. --goroutines is the worker
    # count verbatim, never clamped.
    #
    # The thread pool itself is fixed when the process starts and
    # cannot be widened afterwards, so the launcher requests the
    # harness's worker ceiling and the check below refuses a run that
    # would declare more workers than there are threads to carry them:
    # tasks on a short pool would take turns rather than run together,
    # and the summary would report a parallelism the run never had.
    pool = Threads.nthreads(:default)
    if pool < goroutines
        err_line("--goroutines $goroutines needs $goroutines worker threads, this process has " *
                 "$pool; start the utility through run_loop.sh, or pass julia --threads=$goroutines")
        return -1, cfg
    end
    cfg.workers_requested = goroutines
    cfg.workers = goroutines
    shape = parse_shape(string(raw["shape"]))
    if shape === nothing
        err_line("--shape must be stream | message | stream_one_shot | both, got \"$(raw["shape"])\"")
        return -1, cfg
    end
    cfg.shape = shape
    if !hash_registered(string(raw["hash"]))
        err_line("--hash \"$(raw["hash"])\" is not a registered hash primitive")
        return -1, cfg
    end
    cfg.hash = string(raw["hash"])
    # Validated by Init: the C ABI enumerates no MAC names.
    cfg.mac = string(raw["mac"])
    payload = parse_size(string(raw["payload-size"]))
    if payload === nothing
        err_line("--payload-size: invalid size \"$(raw["payload-size"])\"")
        return -1, cfg
    end
    cfg.payload = payload
    if cfg.payload < 1
        err_line("--payload-size must be at least 1 byte")
        return -1, cfg
    end
    if string(raw["memlimit"]) == "auto"
        cfg.memlimit_auto = true
        cfg.memlimit = cfg.workers <= 3 ? (1 << 30) : (256 << 20)
    else
        memlimit = parse_size(string(raw["memlimit"]))
        if memlimit === nothing
            err_line("--memlimit: invalid size \"$(raw["memlimit"])\"")
            return -1, cfg
        end
        cfg.memlimit = memlimit
    end
    cfg.gogc = Int(raw["gogc"])
    if cfg.gogc < 0
        err_line("--gogc must be >= 0, got $(cfg.gogc)")
        return -1, cfg
    end
    parallax = parse_on_off(string(raw["parallax"]))
    if parallax === nothing
        err_line("--parallax must be on | off, got \"$(raw["parallax"])\"")
        return -1, cfg
    end
    cfg.parallax = parallax
    wrapper = parse_on_off(string(raw["wrapper"]))
    if wrapper === nothing
        err_line("--wrapper must be on | off, got \"$(raw["wrapper"])\"")
        return -1, cfg
    end
    cfg.wrapper = wrapper
    cfg.profile = string(raw["profile"])
    if !isempty(cfg.profile)
        surface = profile_surface(cfg.profile)
        surface === nothing && return -1, cfg
        cfg.shape = narrow_shape(cfg.shape, surface)
    end
    cfg.key_bits = Int(raw["key-bits"])
    if !(cfg.key_bits in (0, 512, 1024, 2048))
        err_line("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got $(cfg.key_bits)")
        return -1, cfg
    end
    cfg.nonce_bits = Int(raw["nonce-bits"])
    if !(cfg.nonce_bits in (0, 128, 256, 512))
        err_line("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got $(cfg.nonce_bits)")
        return -1, cfg
    end
    cfg.blob_mode = Int(raw["blob-mode"])
    if !(cfg.blob_mode in (1, 2))
        err_line("--blob-mode must be 1 (per-region) | 2 (per-container), got $(cfg.blob_mode)")
        return -1, cfg
    end
    cfg.barrier_fill = Int(raw["barrier-fill"])
    if !(cfg.barrier_fill in (0, 1, 2, 4, 8, 16, 32))
        err_line("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got $(cfg.barrier_fill)")
        return -1, cfg
    end
    # Validated by Init: the C ABI enumerates no DRBG names.
    cfg.drbg = string(raw["drbg"])
    chunk_size = parse_size(string(raw["chunk-size"]))
    if chunk_size === nothing
        err_line("--chunk-size: invalid size \"$(raw["chunk-size"])\"")
        return -1, cfg
    end
    cfg.chunk_size = chunk_size
    cfg.gomaxprocs = Int(raw["gomaxprocs"])
    if cfg.gomaxprocs < 0
        err_line("--gomaxprocs must be > 0 when specified, got $(cfg.gomaxprocs)")
        return -1, cfg
    end
    cfg.rekey_every = Int(raw["rekey-every"])
    if cfg.rekey_every < 0
        err_line("--rekey-every must be >= 0, got $(cfg.rekey_every)")
        return -1, cfg
    end
    cfg.blob_cycle_every = Int(raw["blob-cycle-every"])
    if cfg.blob_cycle_every < 0
        err_line("--blob-cycle-every must be >= 0, got $(cfg.blob_cycle_every)")
        return -1, cfg
    end
    payload_mode = parse_payload_mode(string(raw["payload-mode"]))
    if payload_mode === nothing
        err_line("--payload-mode must be " * join(PAYLOAD_NAMES, " | ") *
                 ", got \"$(raw["payload-mode"])\"")
        return -1, cfg
    end
    cfg.payload_mode = payload_mode
    cfg.seed = UInt64(raw["seed"])
    cfg.json_output = Bool(raw["json-output"])
    cfg.memprofile = string(raw["memprofile"])
    return 0, cfg
end

# ------------------------------------------------------------------ #
# Signals                                                            #
# ------------------------------------------------------------------ #

# The stop request a signal leaves behind, in storage the handler can
# reach with a single machine store.
#
# Julia-specific. A handler runs on whatever thread the signal landed
# on and must not allocate or re-enter the runtime from there, so the
# flag lives in a raw cell whose address is a constant in the handler's
# compiled code rather than in a managed object the collector owns.
const _STOP_CELL = convert(Ptr{Cint}, Libc.malloc(sizeof(Cint)))

function _signal_handler(signum::Cint)::Nothing
    unsafe_store!(_STOP_CELL, Cint(1))
    return nothing
end

const _SIGNAL_HANDLER = @cfunction(_signal_handler, Nothing, (Cint,))

stop_requested() = unsafe_load(_STOP_CELL) != 0

"""
Graceful stop. SIGINT / SIGTERM set a flag the main task polls while it
waits for the workers; it turns the flag into the stop request every
worker checks before starting an iteration, so a signal interrupts
nothing mid-call — the in-flight encrypt / decrypt / compare completes,
the worker returns, and the partial summary prints with the verdict the
completed iterations earned. The runtime's own SIGINT disposition
(which raises in the root task, or terminates a script outright) is
replaced here, because neither of those lets an in-flight iteration
finish.
"""
function install_signals()
    unsafe_store!(_STOP_CELL, Cint(0))
    ccall(:signal, Ptr{Cvoid}, (Cint, Ptr{Cvoid}), SIGINT_NO, _SIGNAL_HANDLER)
    ccall(:signal, Ptr{Cvoid}, (Cint, Ptr{Cvoid}), SIGTERM_NO, _SIGNAL_HANDLER)
    # Installing the disposition is not enough on its own. The runtime
    # blocks both signals in every thread it starts and consumes them
    # in a listener thread of its own, so a handler installed over them
    # is never reached: a blocked signal is not delivered, and the
    # listener takes it first. Unblocking the pair in this one thread
    # makes it the only thread eligible for delivery, which is what
    # puts the handler above back in the path. Measured on this host:
    # without this, a termination request ends the process outright
    # with the runtime's own report on stderr; with it, the stop is
    # graceful.
    mask = zeros(UInt8, 128)
    ccall(:sigemptyset, Cint, (Ptr{UInt8},), mask)
    ccall(:sigaddset, Cint, (Ptr{UInt8}, Cint), mask, SIGINT_NO)
    ccall(:sigaddset, Cint, (Ptr{UInt8}, Cint), mask, SIGTERM_NO)
    ccall(:pthread_sigmask, Cint, (Cint, Ptr{UInt8}, Ptr{UInt8}),
          SIG_UNBLOCK, mask, C_NULL)
    return nothing
end

"""
A consumer that stops reading ends the run. The default disposition for
SIGPIPE is restored so the process dies from the signal with status 141
and prints nothing — the reference behaviour, and what anyone piping
into head or less expects. The runtime ignores the signal from its own
startup onwards, which would turn the failed write into an error return
no one reads, so restoring the default is an explicit step here rather
than something inherited.

It runs before anything else, because the first line is already a write
that can fail and because the shared library captures the disposition
in force when it loads.
"""
function restore_sigpipe()
    ccall(:signal, Ptr{Cvoid}, (Cint, Ptr{Cvoid}), SIGPIPE_NO, C_NULL)
    return nothing
end

# ------------------------------------------------------------------ #
# Pipelines                                                          #
# ------------------------------------------------------------------ #

"""
Prints the construction line with the recipe read back from the blob
the Pipeline handed out, not echoed from the flags: every construction
override is proven to have reached the library by the value the
receiver would see. Record values that are empty (a No MAC profile's
MAC, a mixed profile's single hash) print as "-".
"""
function log_pipeline_initialised(profile::AbstractString, blob::Vector{UInt8})
    json = ""
    try
        json = ITB.inspect(blob)
    catch err
        err isa ITB.ITBError || rethrow()
        log_line("pipeline initialised: profile=$profile blob=$(length(blob)) bytes " *
                 "(inspect: $(err.last_error))")
        return nothing
    end
    line = "pipeline initialised: profile=$profile blob=$(length(blob)) bytes " *
           "hash=$(record_str(json, "hash")) " *
           "key-bits=$(record_int(json, "keybits")) " *
           "nonce-bits=$(record_int(json, "nonce_bits")) " *
           "barrier-fill=$(record_int(json, "barrier_fill")) " *
           "chunk-size=$(record_int(json, "chunk")) " *
           "mac=$(record_str(json, "mac")) " *
           "parallax=$(on_off(record_bool(json, "parallax"))) " *
           "wrapper=$(on_off(record_bool(json, "wrapper")))"
    container_mode = record_int(json, "container_mode")
    if container_mode == 2
        line *= " container-mode=$container_mode"
    end
    drbg = record_str(json, "drbg")
    if drbg != "-"
        line *= " drbg=$drbg"
    end
    log_line(line)
    return nothing
end

"""
Sets the inner blob's "mode" field of a wrap-layer session blob to
target_mode (1 = per-region, 2 = per-container) in place. The binding
carries no JSON library, so the edit is a targeted one: the wrap layer's
profile record carries its own "mode" (a string), so the search starts
at the inner blob ("ib"), and nothing before it is touched; both shipped
modes are one digit wide, so the blob length does not change. Returns
false when the inner blob or its mode field is not found.
"""
function edit_inner_blob_mode!(blob::Vector{UInt8}, target_mode::Integer)
    ib_key = codeunits("\"ib\":{")
    mode_key = codeunits("\"mode\":")
    ib = findfirst(ib_key, blob)
    ib === nothing && return false
    off = last(ib) + 1
    mode = findnext(mode_key, blob, off)
    mode === nothing && return false
    at = last(mode) + 1
    at + 1 > length(blob) && return false
    UInt8('1') <= blob[at] <= UInt8('2') || return false
    UInt8('0') <= blob[at + 1] <= UInt8('9') && return false
    blob[at] = UInt8('0') + UInt8(target_mode)
    return true
end

"""
Constructs one Pipeline against profile with every flag-carried
override in the opts string (zero values included — the shared library
treats zero as "profile default"), then obtains the Init blob once
through save: the binding's init entry does not hand the blob back, and
the bytes are the ones Init produced. Later blob reopens use the
retained blob; save is never called again.
"""
function build_pipeline(cfg::Config, profile::AbstractString)
    opts = ITB.Opts()
    ITB.with_inner_hash!(opts, cfg.hash)
    ITB.with_mac_name!(opts, cfg.mac)
    ITB.with_parallax!(opts, cfg.parallax)
    ITB.with_wrapper!(opts, cfg.wrapper)
    ITB.with_key_bits!(opts, cfg.key_bits)
    ITB.with_nonce_bits!(opts, cfg.nonce_bits)
    ITB.with_barrier_fill!(opts, cfg.barrier_fill)
    ITB.with_drbg!(opts, cfg.drbg)
    ITB.with_chunk_size!(opts, cfg.chunk_size)
    if !isempty(cfg.profile)
        filled = fill_keystream_layers(cfg.profile, opts, cfg.parallax, cfg.wrapper)
        filled < 0 && return nothing
        if filled > 0
            err_line("$(cfg.profile) leaves the requested keystream layers unnamed; " *
                     "$KEYSTREAM_FILL_CIPHER supplied for them")
        end
    end
    pipe = nothing
    try
        pipe = ITB.Pipeline(profile; opts=opts)
    catch err
        err isa ITB.ITBError || rethrow()
        err_line("Init($profile): $(status_detail(err))")
        return nothing
    end
    blob = UInt8[]
    try
        blob = ITB.save(pipe)
    catch err
        err isa ITB.ITBError || rethrow()
        err_line("Save($profile): $(status_detail(err))")
        ITB.free!(pipe)
        return nothing
    end
    if cfg.blob_mode == 2
        # The sizing mode is not an Opts knob: the Init blob is edited
        # and the pipeline reopened from it, so the retained blob (the
        # one blob-cycle reopens from) carries the edited mode.
        if !edit_inner_blob_mode!(blob, 2)
            err_line("rewrite blob mode: inner blob mode field not found")
            ITB.free!(pipe)
            return nothing
        end
        ITB.free!(pipe)
        try
            pipe = ITB.load(blob)
        catch err
            err isa ITB.ITBError || rethrow()
            err_line("reload Mode 2 blob: $(status_detail(err))")
            return nothing
        end
    end
    log_pipeline_initialised(profile, blob)
    return pipe, blob
end

# ------------------------------------------------------------------ #
# Run                                                                #
# ------------------------------------------------------------------ #

function run_loop(argv::Vector{String})
    rc, cfg = parse_flags(argv)
    rc == 1 && return 0
    rc != 0 && return 2

    r = RunState(cfg)

    # Runtime shaping. A long run under allocation churn grows the Go
    # heap inside the shared library without bound unless a soft limit
    # paces the collector, so a limit is always in force: an explicit
    # --memlimit is set as given, and auto caps the heap only when the
    # runtime reports no limit at all (a limit already installed from
    # the environment is left standing). The GC percentage and
    # GOMAXPROCS are set only when their flag is non-zero — a zero flag
    # skips the setter rather than calling it with zero, because zero
    # is a real value to the GC-percent setter, and a call would clobber
    # whatever the environment installed. All of it lands before any
    # Pipeline exists so the baselines are taken under the shaped
    # runtime.
    if cfg.memlimit_auto
        if ITB.set_memory_limit(-1) == typemax(Int64)
            ITB.set_memory_limit(cfg.memlimit)
        end
    else
        ITB.set_memory_limit(cfg.memlimit)
    end
    cfg.memlimit = ITB.set_memory_limit(-1)
    cfg.gogc > 0 && ITB.set_gc_percent(cfg.gogc)
    cfg.gomaxprocs > 0 && ITB.set_gomaxprocs(cfg.gomaxprocs)

    log_line("start: duration=$(human_duration(cfg.duration_ns)) iterations=$(cfg.iterations) " *
             "goroutines=$(cfg.workers_requested) workers=$(cfg.workers) " *
             "concurrency=$CONCURRENCY shape=$(shape_name(cfg.shape)) hash=$(cfg.hash) " *
             "mac=$(cfg.mac) payload=$(human_bytes(cfg.payload)) " *
             "memlimit=$(human_bytes(cfg.memlimit)) parallax=$(on_off(cfg.parallax)) " *
             "wrapper=$(on_off(cfg.wrapper))")
    log_line("overrides: profile=\"$(cfg.profile)\" key-bits=$(cfg.key_bits) " *
             "nonce-bits=$(cfg.nonce_bits) chunk-size=$(human_bytes(cfg.chunk_size)) " *
             "barrier-fill=$(cfg.barrier_fill) gomaxprocs=$(cfg.gomaxprocs) " *
             "rekey-every=$(cfg.rekey_every) blob-cycle-every=$(cfg.blob_cycle_every) " *
             "payload-mode=$(payload_mode_name(cfg.payload_mode)) seed=$(cfg.seed) " *
             "json-output=$(cfg.json_output ? "true" : "false")" *
             (cfg.blob_mode != 1 ? " blob-mode=$(cfg.blob_mode)" : "") *
             (isempty(cfg.drbg) ? "" : " drbg=$(cfg.drbg)"))
    log_line("policy: microbatch-tiers=$(policy_label("ITB_MICROBATCH_TIERS")) " *
             "hashpool-starters=$(policy_label("ITB_HASHPOOL_STARTERS"))")

    # Pipeline construction — one shared handle per exercised shape.
    # stream and stream_one_shot share the streaming handle.
    r.stream_profile = isempty(cfg.profile) ? DEFAULT_STREAM_PROFILE : cfg.profile
    r.msg_profile = isempty(cfg.profile) ? DEFAULT_MESSAGE_PROFILE : cfg.profile
    if cfg.shape in (SHAPE_STREAM, SHAPE_STREAM_ONE_SHOT, SHAPE_BOTH)
        built = build_pipeline(cfg, r.stream_profile)
        built === nothing && return 1
        r.stream_pipe, r.stream_blob = built
    end
    if cfg.shape in (SHAPE_MESSAGE, SHAPE_BOTH)
        built = build_pipeline(cfg, r.msg_profile)
        built === nothing && return 1
        r.msg_pipe, r.msg_blob = built
    end

    # Allocation posture. Per-worker plaintexts are allocated once and
    # held for the whole run (rotating mode refills them in place per
    # iteration); the pump accumulators and the drain slice live inside
    # each worker and are reused across iterations; the message and
    # one-shot outputs are the vectors the binding returns per call and
    # the collector reclaims them when the iteration drops them. Under
    # the default fixed CSPRNG mode every worker's buffer is distinct,
    # so cross-worker data crossover is detectable; pattern modes trade
    # that property for content edge-case coverage.
    for i in 0:(cfg.workers - 1)
        w = Worker(i, r)
        w.payload_mode = cfg.payload_mode
        w.seeded = cfg.seed != 0
        w.rng = seed_worker(cfg.seed, i)
        try
            w.plaintext = Vector{UInt8}(undef, cfg.payload)
        catch err
            err isa OutOfMemoryError || rethrow()
            err_line("payload alloc: out of memory")
            return 1
        end
        advanced = fill_payload!(w.plaintext, cfg.payload_mode, w.seeded, w.rng)
        if advanced === nothing
            err_line("payload fill: csprng")
            return 1
        end
        w.rng = advanced
        push!(r.workers, w)
    end

    r.pool_warmup = pool_snapshot()
    r.pool_steady = copy(r.pool_warmup)
    if isempty(r.pool_warmup)
        err_line("pool snapshot alloc failed")
        return 1
    end

    install_signals()
    r.warmup_done = Barrier(cfg.workers + 1)
    r.release = Barrier(cfg.workers + 1)
    r.stop[] = false
    r.active[] = cfg.workers

    # Warmup barrier. Every worker runs one iteration and waits; the
    # clock starts only once all of them have paid their first-call
    # costs (pool warm-up, lazy kernel dispatch, page faults on the
    # payload buffers), and the RSS and pool baselines taken here
    # describe a process that has already run the whole cipher path
    # once per worker.
    warmup_start = now_ns()
    for w in r.workers
        w.task = Threads.@spawn worker_main($w)
    end
    barrier_wait(r.warmup_done)
    r.rss_warmup, r.rss_peak = read_rss()
    r.pool_warmup = pool_snapshot()
    warmup_ns = now_ns() - warmup_start
    log_line("warmup: $(cfg.workers) workers x 1 iter completed in " *
             human_duration(div(warmup_ns + 50_000_000, 100_000_000) * 100_000_000) *
             " (baseline rss=$(human_bytes(r.rss_warmup)))")

    # Open the gate; the duration deadline is enforced by the waiter
    # below in duration mode.
    r.start_ns = now_ns()
    r.finish_ns = r.start_ns
    barrier_wait(r.release)

    # Wait for every worker, polling every 50 ms so the deadline and a
    # signal are both noticed promptly.
    while r.active[] > 0
        stop_requested() && (r.stop[] = true)
        if cfg.iterations == 0 && now_ns() - r.start_ns >= cfg.duration_ns
            r.stop[] = true
        end
        sleep(0.05)
    end
    for w in r.workers
        wait(w.task)
    end
    elapsed_ns = r.finish_ns - r.start_ns
    r.rss_final, peak = read_rss()
    r.rss_peak = max(r.rss_peak, peak)
    r.pool_steady = pool_snapshot()

    if !isempty(cfg.memprofile)
        try
            ITB.write_heap_profile(cfg.memprofile)
            log_line("memprofile: heap profile written to $(cfg.memprofile)")
        catch err
            err isa ITB.ITBError || rethrow()
            err_line("memprofile: $(err.last_error)")
        end
    end

    rc = final_summary(r, elapsed_ns)

    r.stream_pipe !== nothing && ITB.free!(r.stream_pipe)
    r.msg_pipe !== nothing && ITB.free!(r.msg_pipe)
    return rc
end

function main(argv::Vector{String})
    restore_sigpipe()
    return run_loop(argv)
end

end # module Loop

exit(Loop.main(ARGS))
