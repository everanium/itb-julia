#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Julia binding. Builds
# libitb.so via build.sh, points ITB_LIBITB_PATH at the freshly-built
# shared library, then runs the Test-stdlib suite.
#
# The suite is executed directly (test/runtests.jl resolves the Test
# stdlib through the default `@stdlib` LOAD_PATH entry) rather than
# via `Pkg.test()`: distribution-packaged Julia builds that strip
# Test / Random from Pkg's stdlib table (e.g. Arch's system julia)
# cannot resolve a Test dependency inside Pkg's test sandbox. On an
# official Julia distribution `julia --project=. -e 'using Pkg;
# Pkg.test()'` runs the same suite.
#
# Usage:
#   ./run_tests.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"

exec julia --startup-file=no --project=. test/runtests.jl
