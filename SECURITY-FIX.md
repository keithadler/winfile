# Security fix: stack buffer overflow in `WFJunction` (CWE-121 / CWE-787)

This fork fixes a stack buffer overflow in Windows File Manager's junction /
symbolic-link creation, plus documents two lower-severity latent defects found
along the way. Upstream [`microsoft/winfile`](https://github.com/microsoft/winfile)
was archived in 2025 and is read-only, so it cannot accept the fix.

## The vulnerability

**Function:** `WFJunction` — [`src/lfn.c`](src/lfn.c) (creates an NTFS junction).
**Introduced:** commit `f396e22`, 2022-10-29 ("Creation of Symbolic Links,
Hardlinks and Junctions"). This is *not* original 1990s File Manager code; it is
a modern feature addition.
**Reachable from:** the copy engine at
[`src/wfcopy.c:2813`](src/wfcopy.c) — triggered by creating a directory junction
(Ctrl+Shift+Alt drag-and-drop of a directory).

### Root cause — two compounding mistakes

```c
char reparseBuffer[MAXPATHLEN * 3];   // 3072 bytes on the stack
...
wcscpy_s(pathBuffer,               MAXPATHLEN, szSubstituteName);   // copy 1
wcscpy_s(pathBuffer + subLen + 1,  MAXPATHLEN, szTargetName);       // copy 2
```

1. **Byte/wide-char confusion.** The buffer holds two `WCHAR` paths of up to
   `MAXPATHLEN` *wide chars* each. `WCHAR` is 2 bytes, so that needs
   `~4 * MAXPATHLEN` bytes; the code reserved `3 * MAXPATHLEN` **bytes**. The
   original comment ("copy 2 paths each MAXPATHLEN long, so 3x MAXPATHLEN")
   counted paths but forgot they are wide.
2. **Wrong size argument.** Copy 2 writes at an offset into `PathBuffer` but
   passes the size as the full `MAXPATHLEN`, not the *remaining* space. So
   `wcscpy_s`'s bounds check cannot stop the overrun — the `_s` suffix gives
   false assurance.

`szTargetName` is `GetFullPathName(pszLinkTarget, MAXPATHLEN, …)` — the user's
junction target, up to 1023 wide chars.

**Overflow threshold:** a target path longer than **~761 wide chars** overflows
the 3072-byte stack buffer with attacker-influenced path bytes.

### Severity

Stack memory corruption with controlled length and content, in a reachable
feature. On MSVC `/GS` builds the stack cookie most likely converts this into a
crash (denial of service) rather than clean control-flow hijack; builds without
`/GS` have no such guard. Requires the victim to create a junction to an
unusually long (>761-char) target path, which is feasible with NTFS long paths.

## The fix

See [`src/lfn.c`](src/lfn.c) (commit on branch `fix/wfjunction-stack-overflow`):

- Size `reparseBuffer` for two full-length **WCHAR** paths:
  `sizeof(REPARSE_DATA_BUFFER) + 2 * (MAXPATHLEN + 1) * sizeof(WCHAR)`.
- Pass the **true remaining** capacity to the second copy:
  `wcscpy_s(pathBuffer + subLen + 1, cchPathBuffer - (subLen + 1), szTargetName)`.

The build still compiles cleanly (mingw-w64 cross-compile; see
[`build-mac.sh`](build-mac.sh)).

## How it was found, and how to reproduce

Found by static analysis (CodeQL `cpp/bad-strncpy-size`) and confirmed with an
AddressSanitizer reproducer that models the exact buffer arithmetic
(16-bit `WCHAR`, real 3072-byte size). All tooling runs natively on macOS —
the app was cross-compiled with mingw-w64 and run under Wine.

```bash
brew install llvm
cd fuzz
./build-fuzz.sh repro-junction                 # TARGET_LEN=800 -> ASan overflow
TARGET_LEN=260 ./build-fuzz.sh repro-junction  # safe (below threshold)
```

Full analysis of this and two other (latent) findings —
`I_LFNCanon` off-by-one and `AddBackslash` OOB read — is in
[`fuzz/FINDINGS.md`](fuzz/FINDINGS.md).

## Disclosure

Upstream is archived and unmaintained. The app is still distributed via the
Microsoft Store, winget, and Chocolatey. This fork documents the issue and
carries the fix; report to Microsoft MSRC if you require an official servicing
decision.
