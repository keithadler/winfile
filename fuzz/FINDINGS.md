# winfile fuzzing — findings

Target: `microsoft/winfile` (archived March 2025). Harness cross-built and fuzzed
natively on macOS (Apple Silicon) with Homebrew clang + libFuzzer + ASan/UBSan.
No Windows, VM, or Visual Studio involved.

## Finding 1 — off-by-one heap/stack overflow in `I_LFNCanon` (latent)

**Where:** [`src/lfnmisc.c:135`](../src/lfnmisc.c#L135) (the `*outs++ = c;` write),
length guard one line too late at `src/lfnmisc.c:137`.

**What:** `I_LFNCanon(CanonType, InFile, OutFile)` canonicalises a path into
`OutFile`. It takes **no output-size argument**; the source comment states the
caller "must reserve enough space for the canon name, which can be either 256 or
260". The per-path length guard is:

```c
*outs++ = c;                       // write happens first
size++;
if (size > CCHMAXPATHCOMP) {       // CCHMAXPATHCOMP == 256, checked too late
    *OutFile = CHAR_NULL;
    return ERROR_INVALID_PARAMETER;
}
```

Because the guard is `>` (not `>=`) and runs **after** the write, a path whose
canonical length reaches exactly 256 writes the terminating character into the
257th slot — one `TCHAR` (2 bytes) past a 256-`TCHAR` buffer.

Additionally, a fully-qualified `X:` prefix is copied **without** incrementing
`size` (`src/lfnmisc.c:61-62`), so a qualified path can overwrite up to **3**
`TCHAR`s past a 256-element buffer.

**Minimised reproducer:** 256 bytes, all `0x61` (`"aaaa…a"`) — a plain
relative name, no drive letter, no separators. See `fuzz/min-crash`.

**ASan report:**
```
ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 2
  #0 I_LFNCanon fuzz_lfn.c:140            (== src/lfnmisc.c:135)
0x... is located 0 bytes after 512-byte region   (256 * sizeof(uint16_t))
```

**Severity boundary (measured):**

| `OutFile` size handed in | Result   |
|--------------------------|----------|
| 256  (documented lower bound) | **overflow** (1 TCHAR; up to 3 with `X:` prefix) |
| 260  (documented upper bound) | safe     |
| 1024 (winfile's real `MAXPATHLEN`) | safe |

**Live impact on shipping winfile: none.** `I_LFNCanon` is declared in `lfn.h`
but has **no caller anywhere in the tree** — it is dead, exported code — and
winfile's own path buffers are `MAXPATHLEN == 1024`. The defect matters only for
third-party code that reuses `lfnmisc.c`/`lfn.h` and calls `I_LFNCanon` with a
buffer sized to the documented 256 (or ≤258 with a drive prefix).

**Fix options:** change the guard to `if (size >= CCHMAXPATHCOMP)` so a NUL slot
is always reserved, count the `X:` drive prefix in `size`, and/or document the
true minimum as `CCHMAXPATHCOMP + 3`. (Given the function is unused, deletion is
also reasonable.)

## Finding 3 — reachable stack buffer overflow in `WFJunction` (CodeQL) ★

**Where:** [`src/lfn.c:758`](../src/lfn.c#L758) (write), root cause at
[`src/lfn.c:678`](../src/lfn.c#L678) (undersized buffer). Flagged by CodeQL
`cpp/bad-strncpy-size`: "second argument should be size of destination."

```c
char reparseBuffer[MAXPATHLEN * 3];        // 3072 BYTES on the stack
...
// dev comment: "copy 2 paths each MAXPATHLEN long, so we take 3x MAXPATHLEN"
wcscpy_s(r->PathBuffer, MAXPATHLEN, szSubstituteName);                     // :754
wcscpy_s(r->PathBuffer + wcslen(szSubstituteName) + 1, MAXPATHLEN, szTargetName); // :758
```

**Two mistakes compound:**
1. `reparseBuffer` is sized `3 * MAXPATHLEN` **bytes**, but it holds two
   `WCHAR` paths of up to `MAXPATHLEN` *wide chars* each — that needs
   `~4 * MAXPATHLEN` bytes. The buffer is undersized.
2. The second `wcscpy_s` writes at an **offset** (`wcslen(szSubstituteName)+1`)
   yet passes the size as the full `MAXPATHLEN`, not the remaining space — so
   the secure-CRT bounds check cannot stop the overrun. The `_s` suffix gives
   false assurance here.

`szTargetName` is `GetFullPathName(pszLinkTarget, MAXPATHLEN, …)` — the user's
junction target, up to 1023 wide chars.

**Threshold:** overflow when target length `T` satisfies `2T + 6 > 1528`, i.e.
**T > ~761 wide chars**. Demonstrated: `TARGET_LEN=800` overflows,
`TARGET_LEN=260` is safe.

**ASan (modeled buffer arithmetic, 16-bit WCHAR, real 3072-byte size):**
```
ERROR: AddressSanitizer: heap-buffer-overflow  WRITE of size 1602
  #0 ... memcpy
  #2 main fuzz_junction.c:89        (== src/lfn.c:758)
```

**Reachability: LIVE.** `WFJunction` is called from the copy engine at
[`src/wfcopy.c:2813`](../src/wfcopy.c#L2813) (`ret = WFJunction(szDest, szSource)`)
when creating a directory junction. Unlike Finding 1, this is not dead code.

**Severity:** stack memory corruption with attacker-influenced length and
content, in a reachable feature. Trigger requires creating a junction whose
target path resolves to >761 wide chars (feasible with NTFS long paths).
On MSVC builds with `/GS`, the stack cookie likely turns this into a crash
(DoS) rather than clean control-flow hijack; the mingw build has no such guard.
Confirmed three ways: CodeQL, manual analysis, ASan reproducer.

**Fix:** size `reparseBuffer` as `sizeof(REPARSE_DATA_BUFFER) + 2*(MAXPATHLEN+1)*sizeof(WCHAR)`,
and pass the *remaining* space to the second copy:
`wcscpy_s(dst, capacityWChars - (wcslen(szSubstituteName)+1), szTargetName)`.

## Finding 2 — out-of-bounds read in `AddBackslash` on empty input (latent)

**Where:** [`src/wfutil.c:1271`](../src/wfutil.c#L1271).

```c
UINT AddBackslash(LPTSTR lpszPath) {
   UINT uLen = lstrlen(lpszPath);
   if (*(lpszPath+uLen-1) != CHAR_BACKSLASH) {   // uLen==0 -> reads lpszPath[-1]
```

On an empty string, `uLen == 0` and the guard dereferences `lpszPath[-1]` — a
1-`TCHAR` read before the buffer. ASan: `stack-buffer-underflow READ of size 2`.

**Reached via** `LFNMergePath` ([`src/lfn.c:457`](../src/lfn.c#L457)): it does
`lstrcpy(szT, lpMask); RemoveLast(szT); AddBackslash(szT);`. `RemoveLast` empties
`szT` when the mask has no `\` or `:` (e.g. a bare `*.txt`), so `AddBackslash`
then reads before the stack buffer. Call site: `src/wfcopy.c:1796`
(`if (IsWild(pToPath)) LFNMergePath(pToPath, FindFileName(pFrom))`).

**Minimised trigger:** empty input (0 bytes); also any mask with no separator.
See `fuzz/crash-da39a3ee…` (empty).

**Impact: low / latent.** It is a 1-element read whose value is only compared to
`CHAR_BACKSLASH`; on Windows it reads adjacent stack (no crash, no corruption).
But it is a real defect, and `AddBackslash` is called in ~30 sites — any empty
string reaching it reads out of bounds. `LFNMergePath`'s write-back
`lstrcpy(lpMask, szT)` is **size-matched** to the real caller
(`szDest[2*MAXPATHLEN]`, `src/wfcopy.c:2233`), so it does not overflow in-tree;
it is latent for a caller that under-sizes the mask buffer
(reproducible with `MERGE_OUT=260 ./build-fuzz.sh repro-merge`).

**Fix:** `if (uLen == 0 || lpszPath[uLen-1] != CHAR_BACKSLASH)`.

## Not a bug

- `I_LFNEditName` (mask combiner) — fuzzed with a tight result buffer; it honours
  its `iResBufSize` argument on every write path. No overflow found.

## Reproduce

```bash
brew install llvm
cd fuzz
# Finding 1 — I_LFNCanon overflow
./build-fuzz.sh repro                 # deterministic: overflows at CANON_OUT=256
CANON_OUT=260 ./build-fuzz.sh repro   # safe
./build-fuzz.sh run                   # libFuzzer; crashes within a few units
# Finding 2 — AddBackslash OOB read via LFNMergePath
./build-fuzz.sh repro-merge           # deterministic: reads before szT
./build-fuzz.sh run-merge             # libFuzzer; crashes on the empty input
# Finding 3 — WFJunction stack overflow (found by CodeQL)
./build-fuzz.sh repro-junction                 # TARGET_LEN=800: overflows
TARGET_LEN=260 ./build-fuzz.sh repro-junction  # safe
```

## Tooling used

- **libFuzzer + ASan/UBSan** (Homebrew clang) — found Findings 1 & 2.
- **CodeQL 2.26.3** `cpp-security-extended` suite (98 queries) over a database
  built from the traced mingw compile — surfaced Finding 3 via
  `cpp/bad-strncpy-size`. Notably the default queries found little else because
  they model the C stdlib sinks (`strcpy`/`sprintf`), not the Win32
  `lstrcpy`/`wsprintf` family winfile actually uses — a custom query adding
  those sinks would widen coverage.
- **cppcheck 2.21** — 52 raw candidates, but most `uninitvar` hits are false
  positives (API out-parameters it can't see without headers).
