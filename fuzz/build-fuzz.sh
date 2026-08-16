#!/usr/bin/env bash
# Build the libFuzzer harness for winfile's lfnmisc path parsers (native macOS).
# Prereq: brew install llvm   (Apple's CommandLineTools clang lacks the fuzzer rt)
#
#   ./build-fuzz.sh              # build ./fuzz_lfn  (CANON_OUT=256, the documented lower bound)
#   ./build-fuzz.sh run         # build + run the fuzzer
#   CANON_OUT=260 ./build-fuzz.sh run   # build against the "safe" documented size
#   ./build-fuzz.sh repro       # deterministic reproducer, no libFuzzer
set -euo pipefail
cd "$(dirname "$0")"

CLANG="$(brew --prefix llvm)/bin/clang"
CANON_OUT="${CANON_OUT:-256}"
MERGE_OUT="${MERGE_OUT:-2048}"
COMMON=(-g -O1 -fno-omit-frame-pointer -Wall -Wextra -Wno-unused-parameter)
LFN_D=(-DCANON_OUT="$CANON_OUT")
MRG_D=(-DMERGE_OUT="$MERGE_OUT")

case "${1:-build}" in
  repro)                 # I_LFNCanon reproducer
    "$CLANG" "${COMMON[@]}" "${LFN_D[@]}" -DREPRO -fsanitize=address,undefined fuzz_lfn.c -o fuzz_lfn_repro
    echo "built ./fuzz_lfn_repro (CANON_OUT=$CANON_OUT)"; exec ./fuzz_lfn_repro ;;
  repro-merge)           # LFNMergePath reproducer
    "$CLANG" "${COMMON[@]}" "${MRG_D[@]}" -DREPRO -fsanitize=address,undefined fuzz_merge.c -o fuzz_merge_repro
    echo "built ./fuzz_merge_repro (MERGE_OUT=$MERGE_OUT)"; exec ./fuzz_merge_repro ;;
  repro-junction)        # WFJunction stack-overflow reproducer
    TL="${TARGET_LEN:-800}"
    "$CLANG" "${COMMON[@]}" -DTARGET_LEN="$TL" -fsanitize=address,undefined fuzz_junction.c -o fuzz_junction_repro
    echo "built ./fuzz_junction_repro (TARGET_LEN=$TL; >761 overflows, <=760 safe)"; exec ./fuzz_junction_repro ;;
  run)                   # fuzz I_LFNCanon / I_LFNEditName
    "$CLANG" "${COMMON[@]}" "${LFN_D[@]}" -fsanitize=fuzzer,address,undefined fuzz_lfn.c -o fuzz_lfn
    echo "built ./fuzz_lfn (CANON_OUT=$CANON_OUT); fuzzing..."
    exec ./fuzz_lfn -print_final_stats=1 -rss_limit_mb=2048 seeds ;;
  run-merge)             # fuzz LFNMergePath
    "$CLANG" "${COMMON[@]}" "${MRG_D[@]}" -fsanitize=fuzzer,address,undefined fuzz_merge.c -o fuzz_merge
    echo "built ./fuzz_merge (MERGE_OUT=$MERGE_OUT); fuzzing..."
    exec ./fuzz_merge -print_final_stats=1 -rss_limit_mb=2048 seeds_merge ;;
  *)
    "$CLANG" "${COMMON[@]}" "${LFN_D[@]}" -fsanitize=fuzzer,address,undefined fuzz_lfn.c -o fuzz_lfn
    "$CLANG" "${COMMON[@]}" "${MRG_D[@]}" -fsanitize=fuzzer,address,undefined fuzz_merge.c -o fuzz_merge
    echo "built ./fuzz_lfn (CANON_OUT=$CANON_OUT) and ./fuzz_merge (MERGE_OUT=$MERGE_OUT)" ;;
esac
