# The final summary in both renderings, and the two measurements it
# folds in that are not per-worker counters: the process resident set
# and the shared library's pool counters.

# --- resident set --------------------------------------------------------

# Parses one "Vm...:   1234 kB" line of /proc/self/status into bytes;
# zero on any parse failure.
function _status_kb(line::AbstractString)
    fields = split(line)
    length(fields) < 2 && return 0
    value = tryparse(Int, fields[2])
    return value === nothing ? 0 : value * 1024
end

"""
The process's current resident set and its high-water mark in bytes,
from /proc/self/status (VmRSS and VmHWM, reported in kB). Both are zero
on a platform without that file; the figures are informational and
never enter the verdict.
"""
function read_rss()
    current = 0
    peak = 0
    try
        for line in eachline("/proc/self/status")
            if startswith(line, "VmRSS:")
                current = _status_kb(line)
            elseif startswith(line, "VmHWM:")
                peak = _status_kb(line)
            end
        end
    catch
        return 0, 0
    end
    return current, peak
end

# --- pool counters -------------------------------------------------------

"""
Pool counters. The shared library keeps process-wide monotonic totals
at every pool checkout of its cipher core: per hash-array tier the
starter width, checkouts, constructor misses, regrow replacements and
bytes allocated; for the scratch byte pool and the parallax chunk pool
the checkouts, constructor misses, regrows and regrow bytes. Two
snapshots bracketing the main loop are differenced into per-run hit /
miss figures that tell whether a pool keeps its items warm between
calls or evicts them across GC cycles. The slot layout is read from the
library: slot 0 carries the tier count T, tier i occupies the five
slots at 1 + 5*i, and the two byte pools occupy the eight slots at
1 + 5*T; the vector is sized from the binding's length query, never
from a constant.
"""
function pool_snapshot()
    try
        return ITB.pool_stats()
    catch err
        err isa ITB.ITBError || rethrow()
        return Int64[]
    end
end

"""
The differenced pool figures of one run.
"""
struct PoolDelta
    tiers::Int
    starter::Vector{Int}
    get::Vector{Int}
    new::Vector{Int}
    regrow::Vector{Int}
    new_bytes::Vector{Int}
    buf::NTuple{4,Int}
    chunk::NTuple{4,Int}
end

function PoolDelta(warmup::Vector{Int64}, steady::Vector{Int64})
    empty_delta = PoolDelta(0, Int[], Int[], Int[], Int[], Int[], (0, 0, 0, 0), (0, 0, 0, 0))
    (isempty(warmup) || isempty(steady)) && return empty_delta
    (length(steady) < 9 || length(warmup) != length(steady)) && return empty_delta
    tiers = Int(steady[1])
    (tiers < 0 || 1 + 5 * tiers + 8 > length(steady)) && return empty_delta
    starter = Int[]
    get = Int[]
    fresh = Int[]
    regrow = Int[]
    new_bytes = Int[]
    for i in 0:(tiers - 1)
        base = 1 + 5 * i + 1
        push!(starter, Int(steady[base]))
        push!(get, Int(steady[base + 1] - warmup[base + 1]))
        push!(fresh, Int(steady[base + 2] - warmup[base + 2]))
        push!(regrow, Int(steady[base + 3] - warmup[base + 3]))
        push!(new_bytes, Int(steady[base + 4] - warmup[base + 4]))
    end
    tail = 1 + 5 * tiers + 1
    buf = ntuple(k -> Int(steady[tail + k - 1] - warmup[tail + k - 1]), 4)
    chunk = ntuple(k -> Int(steady[tail + 4 + k - 1] - warmup[tail + 4 + k - 1]), 4)
    return PoolDelta(tiers, starter, get, fresh, regrow, new_bytes, buf, chunk)
end

# Misses over checkouts as a percentage; zero when nothing was checked
# out.
function miss_percent(miss::Integer, get::Integer)
    get <= 0 && return 0.0
    return 100.0 * miss / get
end

# The effective GC percentage as the runtime reports it: the query form
# of the setter (a set-and-restore round trip inside the library) so the
# field is the same whether the value came from the flag, the
# environment, or the runtime default.
effective_gogc(flag::Integer) = flag > 0 ? Int(flag) : ITB.set_gc_percent(-1)

# Renders a string as a JSON literal with the escapes JSON requires.
function json_string(s::AbstractString)
    out = IOBuffer()
    write(out, '"')
    for c in codeunits(s)
        if c == UInt8('"')
            write(out, "\\\"")
        elseif c == UInt8('\\')
            write(out, "\\\\")
        elseif c == UInt8('\n')
            write(out, "\\n")
        elseif c == UInt8('\r')
            write(out, "\\r")
        elseif c == UInt8('\t')
            write(out, "\\t")
        elseif c < 0x20
            write(out, @sprintf("\\u%04x", c))
        else
            write(out, c)
        end
    end
    write(out, '"')
    return String(take!(out))
end

"""
Output contract. Both renderings are shared with the Go harness and
every other binding's loop utility field for field: the same lines in
the same order, the same keys in the same order, floats with a fixed
number of decimals so the JSON is byte-identical across
implementations. The Go harness alone adds its runtime-internal lines
after rss: and its runtime-internal keys after parallax_chunk_pool;
nothing here reproduces them because nothing they read is reachable
through the C ABI.
"""
function final_summary(r::RunState, elapsed_ns::Int)
    cfg = r.cfg
    workers = r.workers
    total_iters = sum(w.iters for w in workers; init=0)
    total_enc = sum(w.bytes_enc for w in workers; init=0)
    total_dec = sum(w.bytes_dec for w in workers; init=0)
    nanos_enc = sum(w.nanos_enc for w in workers; init=0)
    nanos_dec = sum(w.nanos_dec for w in workers; init=0)
    errors = [w.error for w in workers if w.failed]

    # Throughput. Per-direction throughput divides the sum of every
    # worker's wall time in that direction by the worker count — the
    # equivalent single-stream wall time under N-way concurrency — so
    # each direction reports the aggregate rate it sustained rather than
    # collapsing to combined/2 (every iteration moves equal encrypt and
    # decrypt bytes, so a total-elapsed denominator would give both
    # directions the same figure). The combined rate keeps total elapsed
    # as the one-glance overall figure.
    avg_enc = nanos_enc > 0 ? div(nanos_enc, cfg.workers) : 0
    avg_dec = nanos_dec > 0 ? div(nanos_dec, cfg.workers) : 0

    rss_delta = r.rss_final - r.rss_warmup
    rss_growth = r.rss_warmup > 0 ? 100.0 * rss_delta / r.rss_warmup : 0.0

    pd = PoolDelta(r.pool_warmup, r.pool_steady)
    passed = isempty(errors)
    gomaxprocs = ITB.set_gomaxprocs(0)
    stream_profile = r.stream_pipe !== nothing ? r.stream_profile : ""
    msg_profile = r.msg_pipe !== nothing ? r.msg_profile : ""

    if cfg.json_output
        emit_json(r, elapsed_ns, total_iters, total_enc, total_dec, avg_enc, avg_dec,
                  errors, passed, pd, rss_growth, gomaxprocs, stream_profile, msg_profile)
        return passed ? 0 : 1
    end

    log_line("=== FINAL ===")
    log_line("  duration: " * human_duration(div(elapsed_ns + 500_000, 1_000_000) * 1_000_000))
    log_line("  iterations: " * join((string(w.iters) for w in workers), " + ") *
             " = $total_iters total")
    log_line("  throughput: encrypt " * human_rate(total_enc, avg_enc) *
             ", decrypt " * human_rate(total_dec, avg_dec) *
             ", combined " * human_rate(total_enc + total_dec, elapsed_ns))
    log_line("  bytes: " * human_bytes(total_enc) * " encrypted, " *
             human_bytes(total_dec) * " decrypted")
    log_line("  data integrity: $total_iters/$total_iters PASS")
    log_line("  concurrency: $CONCURRENCY, workers $(cfg.workers) (requested $(cfg.workers_requested))")
    log_line("  rss: warmup " * human_bytes(r.rss_warmup) * ", peak " * human_bytes(r.rss_peak) *
             ", final " * human_bytes(r.rss_final) *
             " (delta " * human_bytes_signed(rss_delta) * ", " *
             @sprintf("%.1f", rss_growth) * "% growth)")
    for i in 1:pd.tiers
        pd.starter[i] == 0 && continue
        miss = pd.new[i] + pd.regrow[i]
        log_line("  hash pool tier $(i - 1) (starter $(pd.starter[i])): get $(pd.get[i]), " *
                 "miss $miss (new $(pd.new[i]) + regrow $(pd.regrow[i])), " *
                 "miss " * @sprintf("%.2f", miss_percent(miss, pd.get[i])) * "%, " *
                 human_bytes(pd.new_bytes[i]) * " allocated")
    end
    log_line("  buf pool: get $(pd.buf[1]), regrow $(pd.buf[3]) (of which fresh $(pd.buf[2])), " *
             "miss " * @sprintf("%.2f", miss_percent(pd.buf[3], pd.buf[1])) * "%, " *
             human_bytes(pd.buf[4]) * " regrown")
    log_line("  parallax chunk pool: get $(pd.chunk[1]), regrow $(pd.chunk[3]) " *
             "(of which fresh $(pd.chunk[2])), " *
             "miss " * @sprintf("%.2f", miss_percent(pd.chunk[3], pd.chunk[1])) * "%, " *
             human_bytes(pd.chunk[4]) * " regrown")
    r.rekeys > 0 && log_line("  rekeys: $(r.rekeys)")
    r.blob_cycles > 0 && log_line("  blob cycles: $(r.blob_cycles)")
    for text in errors
        log_line("  ERROR: $text")
    end
    if passed
        log_line("  verdict: PASS")
        return 0
    end
    log_line("  verdict: FAIL (errors=$(length(errors)))")
    return 1
end

# One compact object on one line, keys in the contract's order, floats
# with the contract's decimal counts and never in exponent form.
function emit_json(r::RunState, elapsed_ns::Int, total_iters::Int, total_enc::Int,
                   total_dec::Int, avg_enc::Int, avg_dec::Int, errors::Vector{String},
                   passed::Bool, pd::PoolDelta, rss_growth::Float64, gomaxprocs::Int,
                   stream_profile::String, msg_profile::String)
    cfg = r.cfg
    tiers = String[]
    for i in 1:pd.tiers
        pd.starter[i] == 0 && continue
        push!(tiers, @sprintf("{\"tier\":%d,\"starter\":%d,\"get\":%d,\"new\":%d,\"regrow\":%d,\"new_bytes\":%d,\"miss_percent\":%.2f}",
                              i - 1, pd.starter[i], pd.get[i], pd.new[i], pd.regrow[i],
                              pd.new_bytes[i], miss_percent(pd.new[i] + pd.regrow[i], pd.get[i])))
    end
    out = IOBuffer()
    print(out, @sprintf("{\"duration_seconds\":%.3f", elapsed_ns / 1e9))
    print(out, ",\"iterations\":", total_iters)
    print(out, ",\"per_worker_iterations\":[", join((string(w.iters) for w in r.workers), ","), "]")
    print(out, ",\"bytes_encrypted\":", total_enc)
    print(out, ",\"bytes_decrypted\":", total_dec)
    print(out, @sprintf(",\"encrypt_mb_per_sec\":%.1f", mb_per_sec(total_enc, avg_enc)))
    print(out, @sprintf(",\"decrypt_mb_per_sec\":%.1f", mb_per_sec(total_dec, avg_dec)))
    print(out, @sprintf(",\"combined_mb_per_sec\":%.1f", mb_per_sec(total_enc + total_dec, elapsed_ns)))
    print(out, ",\"rekeys\":", r.rekeys)
    print(out, ",\"blob_cycles\":", r.blob_cycles)
    print(out, ",\"worker_errors\":[", join((json_string(e) for e in errors), ","), "]")
    print(out, ",\"verdict\":\"", passed ? "PASS" : "FAIL", "\"")
    print(out, ",\"shape\":\"", shape_name(cfg.shape), "\"")
    print(out, ",\"stream_profile\":", json_string(stream_profile))
    print(out, ",\"message_profile\":", json_string(msg_profile))
    print(out, ",\"hash\":", json_string(cfg.hash))
    print(out, ",\"mac\":", json_string(cfg.mac))
    print(out, ",\"payload_bytes\":", cfg.payload)
    print(out, ",\"payload_mode\":\"", payload_mode_name(cfg.payload_mode), "\"")
    print(out, ",\"seed\":", cfg.seed)
    print(out, ",\"key_bits\":", cfg.key_bits)
    print(out, ",\"nonce_bits\":", cfg.nonce_bits)
    print(out, ",\"blob_mode\":", cfg.blob_mode)
    print(out, ",\"drbg\":", json_string(cfg.drbg))
    print(out, ",\"drbg_auto_tier\":", json_string(ITB.drbg_auto_tier()))
    print(out, ",\"chunk_size_bytes\":", cfg.chunk_size)
    print(out, ",\"barrier_fill\":", cfg.barrier_fill)
    print(out, ",\"parallax\":\"", on_off(cfg.parallax), "\"")
    print(out, ",\"wrapper\":\"", on_off(cfg.wrapper), "\"")
    print(out, ",\"goroutines_requested\":", cfg.workers_requested)
    print(out, ",\"goroutines\":", cfg.workers)
    print(out, ",\"concurrency\":\"", CONCURRENCY, "\"")
    print(out, ",\"gogc\":\"", effective_gogc(cfg.gogc), "\"")
    print(out, ",\"memlimit_bytes\":", cfg.memlimit)
    print(out, ",\"gomaxprocs\":", gomaxprocs)
    print(out, ",\"microbatch_tiers\":", json_string(policy_label("ITB_MICROBATCH_TIERS")))
    print(out, ",\"hashpool_starters\":", json_string(policy_label("ITB_HASHPOOL_STARTERS")))
    print(out, ",\"rss_warmup_bytes\":", r.rss_warmup)
    print(out, ",\"rss_peak_bytes\":", r.rss_peak)
    print(out, ",\"rss_final_bytes\":", r.rss_final)
    print(out, @sprintf(",\"rss_growth_percent\":%.2f", rss_growth))
    print(out, ",\"hash_pool_tiers\":[", join(tiers, ","), "]")
    print(out, @sprintf(",\"buf_pool\":{\"get\":%d,\"new\":%d,\"regrow\":%d,\"regrow_bytes\":%d,\"miss_percent\":%.2f}",
                        pd.buf[1], pd.buf[2], pd.buf[3], pd.buf[4],
                        miss_percent(pd.buf[3], pd.buf[1])))
    print(out, @sprintf(",\"parallax_chunk_pool\":{\"get\":%d,\"new\":%d,\"regrow\":%d,\"regrow_bytes\":%d,\"miss_percent\":%.2f}",
                        pd.chunk[1], pd.chunk[2], pd.chunk[3], pd.chunk[4],
                        miss_percent(pd.chunk[3], pd.chunk[1])))
    print(out, "}\n")
    bytes = take!(out)
    lock(_OUT_LOCK) do
        _write_all(Cint(1), bytes)
    end
    return nothing
end
