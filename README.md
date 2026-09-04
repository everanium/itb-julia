# ITB Julia Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). Runtime FFI via the `Libdl` stdlib and `ccall` — no
C compiler at install time, no compile-time link; the `.so` /
`.dylib` / `.dll` is resolved at the first FFI call. Every hash-name
/ MAC-name / cipher-name / profile-name is an opaque string passed
through to Go for validation; the binding carries no ITB construction
logic. The public surface is the `ITB` module (`load` / `load_f` /
`save` / `save_f` / `inspect` / `register` / `lookup` / `profiles` /
`version` and the Go runtime knobs), the `Pipeline` type
(Single Message encrypt / decrypt, rekey, max_workers, close,
incremental stream sessions), the `StreamEncryptor` /
`StreamDecryptor` session types, and the fluent `Opts` builder.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go julia
```

Generic Linux / macOS: a Go toolchain and Julia 1.10+. Windows: the
same; libitb builds as `libitb.dll`. No third-party Julia packages
are required — the binding depends on the `Libdl` stdlib only, and
the tests use the `Test` stdlib.

## Build the shared library

The convenience driver builds `libitb.so` and resolves + precompiles
the Julia package in one step:

```bash
./bindings/julia/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

The package is loadable directly with
`julia --project=bindings/julia` (no further build step — `Libdl`
loads the shared library at the first FFI call).

## Library lookup order

1. `ITB_LIBITB_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking up
   from the package source (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`, `PATH`).

## Usage example

```julia
using ITB

sender = Pipeline("singlemsg-triple-mac-v1")
receiver = load(save(sender))

wire = encrypt_message(sender, Vector{UInt8}("any text or binary data"))
plain = decrypt_message(receiver, wire)
@assert plain == Vector{UInt8}("any text or binary data")

free!(sender)
free!(receiver)

# File-backed equivalent (persist across processes):
# sender = Pipeline("singlemsg-triple-mac-v1")
# save_f(sender, "session.blob")
# receiver = load_f("session.blob")
```

`Opts` overrides the profile default at construction (chunk size,
outer cipher, parallax on/off, wrapper on/off, MAC name, palette,
worker cap); the `with_*!` setters mutate the builder in place. The
resolved shape is written into the blob, so the receiver loads it
with no opts of its own:

```julia
opts = ITB.Opts()
ITB.with_chunk_size!(opts, 65536)
ITB.with_wrapper!(opts, false)
sender = Pipeline("singlemsg-triple-mac-v1"; opts=opts)
receiver = load(save(sender))
```

`rekey!` rotates the parallax + wrapper masters mid-session (the
eight ITB seeds and MAC key are fixed for the session lifetime by
design) and returns the refreshed blob; the receiver picks up the new
masters through a fresh `load`:

```julia
rotated = rekey!(sender, fill(UInt8(0x11), 32), fill(UInt8(0x22), 32))
receiver2 = load(rotated)
```

## Persisting sessions

The blob is self-describing: it carries the profile record (mode,
width, primitives, key bits, MAC, layer switches) alongside the key
material, so a session reopens from the blob alone.

```julia
blob = save(sender)                          # current blob (Vector{UInt8})
save_f(sender, "session.blob")               # written by libitb, mode 0600
receiver = load(blob)                        # reopen from bytes
receiver = load_f("session.blob")            # reopen from file
receiver = load(blob; masters=(perm, wrap))  # override the masters
record = inspect(blob)                       # profile record, no Pipeline
```

`inspect` returns the profile record as the JSON text libitb emits
(keys `name`, `mode`, `width`, `hash`, `hashes`, `keybits`, `mac`,
`tagstub`, `chunk`, `wrapper`, `outer`, `parallax`, `palette`,
`segment`; absent keys are optional fields at their zero value) — the
package carries no JSON dependency, so the text is handed over
verbatim for the caller's own decoder (e.g. `JSON.parse`).

The shipped `itb3` command-line utility (see `cmd/itb3`) generates
session blobs on disk (JSON files) that this binding reopens through
`load_f`, and also encrypts / decrypts files or stdio streams from the
shell. It is the openssl-style entry point for ITB; the binding is the
programmatic entry point.

Load works for blobs generated with shipped primitives (every entry
in the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to `load` such a blob through
this binding throws `ITBError` with
`ITB.STATUS_RECIPE_PRIMITIVE_UNKNOWN`.

## Profile registry

```julia
profiles()                                   # sorted Vector{String}
lookup("singlemsg-triple-mac-v1")            # record JSON; unknown -> STATUS_UNKNOWN_PROFILE
register("my-profile", """{
  "mode": "singlemsg-nomac",
  "width": 256,
  "hashes": ["blake3", "blake2s", "areion256", "blake2b256",
             "chacha20", "blake3", "blake2s", "areion256"],
  "keybits": 1024,
  "parallax": false,
  "wrapper": false
}""")
sender = Pipeline("my-profile")
```

`register` takes the same JSON record shape `inspect` / `lookup`
return; a `name` key inside it, if present, must be empty or equal to
the name argument. Every rule — name pattern, reserved prefixes,
field constraints, primitive names — is enforced by libitb; a
duplicate name throws `ITB.STATUS_PROFILE_EXISTS`.

## Runtime tuning

`max_workers!(pipe, n)` sets the worker cap on a live Pipeline
(`n <= 0` selects auto, values above 256 are clamped). The cap is
per-machine tuning and is never written to the blob, so the receiver
may pick its own worker cap after `load`. `with_max_workers!` sets
the same cap at construction.

`encrypt_stream` / `decrypt_stream` open incremental sessions
exposing `write!` / `end_stream!` / `read!` / `drain_all!` for
caller-driven loops, plus a `pump!(session, src, dst)` helper that
moves any readable `IO` into any writable one with bounded memory.
The `do`-block form frees the session on return:

```julia
pipe = Pipeline("streaming-noaead-triple-v1")
wire = encrypt_stream(pipe) do enc
    write!(enc, chunk_a)
    write!(enc, chunk_b)
    drain_all!(enc)
end
```

`Pipeline` and the stream sessions register GC finalizers, so
un-freed handles are reclaimed eventually; explicit `free!` (or the
`do`-block form) releases the Go-side state deterministically. Stream
sessions hold their parent `Pipeline` in a `parent` field, so the
parent cannot be garbage-collected while a session is live.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string throws `ITBError` carrying the status
code (`status_code`, values in the `ITB.STATUS_*` constants) plus the
`ITB_LastError` diagnostic (`last_error`). Opts are built fluently
(`Opts()` + `with_key_bits!` / `with_inner_hash!` / `with_raw!` / …)
or passed as a `Dict` / raw query string.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing:

```julia
set_memory_limit(512 << 20)
set_gc_percent(20)
```

## Testing

```bash
./bindings/julia/run_tests.sh
```

The harness builds `libitb.so`, exports `ITB_LIBITB_PATH`, and runs
the `Test`-stdlib suite. The suite covers the library version, the
profile catalogue (`profiles` / `lookup`), Single Message and stream
round trips, pump round trips, tampered-wire rejection, closed-handle
mapping, large-payload buffer sizing, rekey, save / load persistence
(in memory and through a file), `inspect`, profile registration, the
worker cap, opts rendering, and error mapping — surface parity checks;
the deep suite lives in Go under the shipped tree.

The harness executes `test/runtests.jl` directly rather than through
`Pkg.test()`: distribution-packaged Julia builds that strip `Test` /
`Random` from Pkg's stdlib table (e.g. Arch's system `julia`) cannot
resolve a `Test` dependency inside Pkg's test sandbox. On an official
Julia distribution `julia --project=bindings/julia -e 'using Pkg;
Pkg.test()'` runs the same suite.

## Benchmarking

```bash
./bindings/julia/run_bench.sh
```

Micro-benches: `encrypt_message` and stream-session encrypt
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven by
env vars (`ITB_PROFILE`, `ITB_INNER_HASH`, `ITB_KEY_BITS`,
`ITB_NONCE_BITS`, `ITB_WITH_PARALLAX`, `ITB_WITH_WRAPPER`,
`ITB_BENCH_MIN_SEC`); the script pins the same defaults as the root
Go BENCH3.md table. Each case runs one untimed warm-up iteration
first, which also absorbs Julia's first-call JIT compile latency.

## eitb utility

A small CLI under `bindings/julia/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
./bindings/julia/eitb/eitb version
./bindings/julia/eitb/eitb profiles
./bindings/julia/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./bindings/julia/eitb/eitb inspect <blob-hex>
./bindings/julia/eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ITBError` may belong to a different
  call under concurrent FFI use. The status code is always
  attributable.
- `rekey!` must not run concurrently with cipher calls or open stream
  sessions on the same `Pipeline`.
- `using ITB` exports `load` / `save`, which collide with the
  identically named FileIO.jl entry points in a session that also
  loads FileIO; qualify as `ITB.load` / `ITB.save` (or `import ITB`)
  in that case.
- Input `Vector{UInt8}` buffers are borrowed at the FFI boundary for
  the duration of the call (`ccall` GC-roots its arguments);
  non-`Vector` byte containers and strings are copied to a fresh
  `Vector{UInt8}` first. Outputs are freshly-allocated vectors.
- FFI calls block the calling Julia thread for their duration; a
  blocked call also delays any stop-the-world GC on that thread.
  Potentially-blocking stream reads (`read!` on an empty spool after
  `end_stream!`) return as soon as the Go side produces the terminal
  bytes.
- libitb must be reachable at the first FFI call through the lookup
  order above; a resolve failure throws `ITBError` at that call, not
  at `using ITB`.
