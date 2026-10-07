#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Julia binding:
# runs the utility with every argument passed through. The binding is
# pure Julia over Libdl + ccall, so there is nothing to compile here;
# build.sh owns libitb3.so and the project's precompile cache.
#
# Two things the launcher does contribute. The worker thread pool is
# fixed when the process starts and cannot be widened afterwards, so it
# is requested here at the harness's worker ceiling, with one
# interactive thread beside it so the waiting main task always has a
# thread of its own while every worker sits inside a library call. And
# the package is loaded once beforehand with its output captured: a
# cold cache makes the runtime report its precompilation on stderr, and
# those lines would otherwise join the utility's own output. Nothing is
# printed unless that load fails, in which case everything it said is.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

JULIA_FLAGS=(--startup-file=no --project=. --threads=10,1)

if ! warm_output="$(julia "${JULIA_FLAGS[@]}" -e 'using LibItb3' 2>&1)"; then
    printf '%s\n' "$warm_output" >&2
    exit 1
fi

exec julia "${JULIA_FLAGS[@]}" loop/main.jl "$@"
