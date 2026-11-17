#!/usr/bin/env bash
# fuzz.sh — Run fuzz tests for protocol parsers
#
# Usage:
#  ./scripts/fuzz.sh  # Run all fuzzers for 5 minutes each
#  ./scripts/fuzz.sh imap  # Run only IMAP fuzzers
#  ./scripts/fuzz.sh imap 10m  # Run IMAP fuzzers for 10 minutes
#  ./scripts/fuzz.sh --list  # List available fuzz targets
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

DEFAULT_TIME="5m"

# Fuzz targets: package path, fuzz function prefix, corpus directory
declare -A FUZZ_TARGETS
FUZZ_TARGETS=(
    ["imap"]="pkg/imap FuzzIMAP testdata/fuzz-corpus/imap"
    ["imap-search"]="pkg/imap FuzzSearch testdata/fuzz-corpus/imap"
    ["smtp"]="pkg/smtp FuzzSMTP testdata/fuzz-corpus/smtp"
    ["caldav-vcard"]="pkg/caldav FuzzVCARD testdata/fuzz-corpus/caldav"
    ["caldav-ical"]="pkg/caldav FuzzICalendar testdata/fuzz-corpus/caldav"
    ["sieve"]="pkg/sieve FuzzSieve testdata/fuzz-corpus/sieve"
    ["dkim"]="pkg/dkim FuzzDKIM testdata/fuzz-corpus/dkim"
)

list_targets() {
    echo "Available fuzz targets:"
    for key in "${!FUZZ_TARGETS[@]}"; do
        IFS=' ' read -r pkg func corpus <<< "${FUZZ_TARGETS[$key]}"
        echo "  $key  ($pkg - $func, corpus: $corpus)"
    done
    exit 0
}

run_fuzz() {
    local name="$1"
    local fuzz_time="$2"
    local pkg func corpus
    IFS=' ' read -r pkg func corpus <<< "${FUZZ_TARGETS[$name]}"

    local fuzz_func
    # Find the exact fuzz function name
    fuzz_func=$(go test -list "Fuzz${func}.*" "./${pkg}" 2>/dev/null | grep "Fuzz${func}" | head -1)
    if [ -z "$fuzz_func" ]; then
        echo "[SKIP] $name: no fuzz function matching $func in $pkg"
        return 0
    fi

    local corpus_dir="${REPO_ROOT}/${corpus}"
    local fuzz_dir="${REPO_ROOT}/testdata/fuzz-${name}"

    echo "[RUN] $name: go test -fuzz=$fuzz_func -fuzztime=$fuzz_time ./${pkg}"
    echo "  corpus=$corpus_dir  fuzzoutput=$fuzz_dir"

    go test \
        -fuzz="$fuzz_func" \
        -fuzztime="$fuzz_time" \
        -fuzzcachedir="${fuzz_dir}/cache" \
        "./${pkg}" \
       2>&1 | tee "${fuzz_dir}/output.log"

    local exit_code=${PIPESTATUS[0]}
    if [ $exit_code -ne 0 ]; then
        echo "[FAIL] $name: fuzzer found a crash — see ${fuzz_dir}/output.log"
        echo "[FAIL] Crashing input saved to: ${fuzz_dir}/artifact/"
        return 1
    fi
    echo "[PASS] $name: no crashes found in $fuzz_time"
    return 0
}

# --- main ---

if [ "${1:-}" = "--list" ]; then
    list_targets
fi

TARGET="${1:-all}"
FUZZ_TIME="${2:-$DEFAULT_TIME}"

if [ "$TARGET" = "all" ]; then
    failed=()
    for name in "${!FUZZ_TARGETS[@]}"; do
        if ! run_fuzz "$name" "$FUZZ_TIME"; then
            failed+=("$name")
        fi
        echo ""
    done

    if [ ${#failed[@]} -gt 0 ]; then
        echo "=== FAILED TARGETS ==="
        for f in "${failed[@]}"; do
            echo "  $f"
        done
        exit 1
    fi
    echo "=== ALL TARGETS PASSED ==="
else
    if [ -z "${FUZZ_TARGETS[$TARGET]+x}" ]; then
        echo "Unknown target: $TARGET"
        echo "Use --list to see available targets."
        exit 1
    fi
    run_fuzz "$TARGET" "$FUZZ_TIME"
fi
