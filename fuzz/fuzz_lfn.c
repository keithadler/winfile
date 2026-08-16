/*
 * fuzz_lfn.c — libFuzzer harness for winfile's self-contained path parsers.
 *
 * Targets two pure pointer-walking routines lifted VERBATIM from
 * src/lfnmisc.c (only substitution: isalpha -> WF_ISALPHA, an ASCII-faithful
 * shim, to avoid libc UB when a wide char > 255 reaches isalpha()):
 *
 *   I_LFNCanon(CanonType, InFile, OutFile)      -- no output-size parameter;
 *       caller "must reserve 256 or 260" per the source comment.
 *   I_LFNEditName(lpSrc, lpEd, lpRes, iBufSize) -- mask combiner, size-bounded.
 *
 * The Win32 types/macros below are shimmed with the REAL values from
 * src/wftypes.h / src/lfn.h (WCHAR is 16-bit on Windows -> uint16_t here,
 * CCHMAXPATHCOMP = 256, CHAR_* = the ASCII code points).
 *
 * Build:  ./fuzz/build-fuzz.sh          (fuzzer)
 *         ./fuzz/build-fuzz.sh repro    (deterministic reproducer, no libFuzzer)
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- Win32 type shim (real widths/values) ---- */
typedef uint16_t TCHAR;
typedef TCHAR   *LPTSTR;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef int      INT;

#define NO_ERROR                0
#define ERROR_INVALID_PARAMETER 87

#define CCHMAXPATHCOMP  256      /* src/lfn.h */
#define LFNCANON_MASK   1        /* src/lfn.h */

#define CHAR_NULL      ((TCHAR)0x00)
#define CHAR_BACKSLASH ((TCHAR)'\\')
#define CHAR_SLASH     ((TCHAR)'/')
#define CHAR_COLON     ((TCHAR)':')
#define CHAR_SPACE     ((TCHAR)' ')
#define CHAR_DOT       ((TCHAR)'.')
#define CHAR_DQUOTE    ((TCHAR)'"')
#define CHAR_PIPE      ((TCHAR)'|')
#define CHAR_GREATER   ((TCHAR)'>')
#define CHAR_LESS      ((TCHAR)'<')
#define CHAR_STAR      ((TCHAR)'*')
#define CHAR_QUESTION  ((TCHAR)'?')
#define DOT            CHAR_DOT

/* Faithful to Win32 isalpha() in the C locale (ASCII letters only). */
#define WF_ISALPHA(c) (((c) >= 'A' && (c) <= 'Z') || ((c) >= 'a' && (c) <= 'z'))

/* ============================================================= *
 *  BEGIN verbatim from src/lfnmisc.c (isalpha -> WF_ISALPHA)     *
 * ============================================================= */
DWORD
I_LFNCanon(WORD CanonType, LPTSTR InFile, LPTSTR OutFile)
{
   LPTSTR       ins = InFile;
   LPTSTR       outs = OutFile;
   unsigned    size;
   unsigned    trails;
   TCHAR        c;

   if (!InFile || !OutFile)
      return ERROR_INVALID_PARAMETER;

   if (*InFile == CHAR_NULL)
      return ERROR_INVALID_PARAMETER;


   /* First, check if we have a fully qualified name, or a relative name */
   if (*InFile != CHAR_BACKSLASH && *InFile != CHAR_SLASH) {
      if (WF_ISALPHA(*InFile)) {
         if (InFile[1] == CHAR_COLON) {
            *outs++ = *ins++;
            *outs++ = *ins++;     // Copy over the drive and colon
         }
      }
   } else {
      ins++;
      *outs++ = CHAR_BACKSLASH;
   }

   size = 0;
   do {
      c = *ins++;
      if ((c < 0x001f && c != CHAR_NULL) || (c == CHAR_DQUOTE) || (c == CHAR_COLON) || (c == CHAR_PIPE) ||
          (c == CHAR_GREATER) || (c == CHAR_LESS)) {
             *OutFile = CHAR_NULL;
             return ERROR_INVALID_PARAMETER;
      }
      if (CanonType != LFNCANON_MASK && ((c == CHAR_STAR) || (c == CHAR_QUESTION))) {
         *OutFile = CHAR_NULL;
         return ERROR_INVALID_PARAMETER;
      }
      if (c == CHAR_SLASH)
         c = CHAR_BACKSLASH;       // Convert / to \ for canon

      if (c == CHAR_BACKSLASH || c == CHAR_NULL) {   // Component separator:  Trim file name

         if (outs > OutFile) {
            if (*(outs - 1) == CHAR_DOT) {
               if  ((outs - 1) == OutFile || *(outs - 2) == CHAR_BACKSLASH) {   // Single dot
                  *(outs--) = c;
                  if (size)
                     size--;
                  continue;
               }
               if (*(outs - 2) == CHAR_DOT) {     // Possible ..
                  if ((outs - 2) == OutFile || *(outs - 3) == CHAR_BACKSLASH ||
                        *(outs - 3) == CHAR_COLON) {
                     *outs++ = c;
                     size++;
                     continue;
                  }
               }
            }
         }

         trails = 0;
         while (outs > OutFile && ((*(outs-1) == CHAR_DOT || *(outs-1) == CHAR_SPACE)
                 && (*(outs-1) != CHAR_BACKSLASH && *(outs - 1) != CHAR_COLON)) ) {
            outs--;
            trails++;
            if (size)
               size--;
         }
         if (outs == OutFile) {
            *OutFile = CHAR_NULL;
            return ERROR_INVALID_PARAMETER;
         }
         if (outs > OutFile && *(outs-1) == CHAR_BACKSLASH) {
            *OutFile = CHAR_NULL;
            return ERROR_INVALID_PARAMETER;
         }
      }
      *outs++ = c;
      size++;
      if (size > CCHMAXPATHCOMP) {
         *OutFile = CHAR_NULL;
         return ERROR_INVALID_PARAMETER;
      }
   } while (c);

   if (outs != OutFile)
      if (*(outs-1) == CHAR_BACKSLASH) {
         *OutFile = CHAR_NULL;
         return ERROR_INVALID_PARAMETER;
      }

   return 0;

}

WORD I_LFNEditName( LPTSTR lpSrc, LPTSTR lpEd, LPTSTR lpRes, INT iResBufSize )
{
   INT ResLen = 0;     // Length of result

   while (*lpEd) {

      if (ResLen < iResBufSize) {

         switch (*lpEd) {

         case CHAR_STAR:
            {
               TCHAR delimit = *(lpEd+1);

               while ((ResLen < iResBufSize) &&
                  ( *lpSrc != CHAR_NULL ) && ( *lpSrc != delimit )) {

                  *(lpRes++) = *(lpSrc++);
                  ResLen++;

               }
            }
            break;


         case CHAR_QUESTION:
            if ((*lpSrc != DOT ) && (*lpSrc != CHAR_NULL)) {

               if (ResLen < iResBufSize) {

                  *(lpRes++) = *(lpSrc++);
                  ResLen++;
               }
               else
                  return ERROR_INVALID_PARAMETER ;
            }
            break;

         case CHAR_DOT:
            while ((*lpSrc != DOT ) && (*lpSrc != CHAR_NULL))
               lpSrc++;

            *(lpRes++) = DOT ;       // from EditMask, even if src doesn't
                                     // have one, so always put one.
            ResLen++;
            if (*lpSrc)              // point one past CHAR_DOT
               lpSrc++;
               break;

         default:
            if ((*lpSrc != DOT ) && (*lpSrc != CHAR_NULL)) {

               lpSrc++;
            }

            if (ResLen < iResBufSize) {

               *(lpRes++) = *lpEd;
               ResLen++;
            }
            else
               return ERROR_INVALID_PARAMETER ;
            break;
         }
         lpEd++;

      }
      else {

         return ERROR_INVALID_PARAMETER ;
      }
   }

   if ((ResLen) < iResBufSize) {
      *lpRes = CHAR_NULL;
      return NO_ERROR ;
   }
   else
      return ERROR_INVALID_PARAMETER ;
}
/* ============================================================= *
 *  END verbatim                                                 *
 * ============================================================= */

/* Output buffer size handed to I_LFNCanon. The source comment says a caller
 * may reserve 256 ("either 256 or 260"), so 256 is a documented-legal size.
 * Override at compile time: -DCANON_OUT=260 (safe) or 1024 (winfile's real). */
#ifndef CANON_OUT
#define CANON_OUT CCHMAXPATHCOMP    /* 256 */
#endif

/* Convert raw bytes -> null-terminated TCHAR string (chars 0x00..0xFF). */
static TCHAR *to_tstr(const uint8_t *data, size_t n, size_t cap) {
   if (n > cap) n = cap;
   TCHAR *s = (TCHAR *)malloc((n + 1) * sizeof(TCHAR));
   for (size_t i = 0; i < n; i++) s[i] = (TCHAR)data[i];
   s[n] = 0;
   return s;
}

static void exercise(const uint8_t *data, size_t size) {
   /* --- Target 1: I_LFNCanon into a heap buffer sized per the documented
    * lower bound. ASAN red-zones any write past index CANON_OUT-1. --- */
   TCHAR *in = to_tstr(data, size, 8192);

   TCHAR *out = (TCHAR *)malloc(CANON_OUT * sizeof(TCHAR));
   I_LFNCanon(LFNCANON_MASK, in, out);   /* MASK: allows * and ? */
   free(out);

   out = (TCHAR *)malloc(CANON_OUT * sizeof(TCHAR));
   I_LFNCanon(0, in, out);               /* non-mask */
   free(out);
   free(in);

   /* --- Target 2: I_LFNEditName. Split input on the first 0x1F byte into
    * (src, mask); give a tight result buffer and pass its true size. --- */
   size_t split = size;
   for (size_t i = 0; i < size; i++) if (data[i] == 0x1F) { split = i; break; }
   TCHAR *src  = to_tstr(data, split, 4096);
   size_t mlen = (split < size) ? (size - split - 1) : 0;
   TCHAR *mask = to_tstr(split < size ? data + split + 1 : data, mlen, 4096);

   const INT RES = 64;
   /* Exact size so ASAN's red-zone sits at index RES (first OOB slot). */
   TCHAR *res = (TCHAR *)malloc(RES * sizeof(TCHAR));
   I_LFNEditName(src, mask, res, RES);
   free(res);
   free(src);
   free(mask);
}

#ifdef REPRO
/* Deterministic reproducer: feed a long path and let ASAN adjudicate. */
int main(void) {
   fprintf(stderr, "[repro] CANON_OUT=%d, feeding 300-char path...\n", CANON_OUT);
   uint8_t buf[512];
   /* fully-qualified: drive prefix is written UNCOUNTED, widening the write */
   buf[0] = 'C'; buf[1] = ':'; buf[2] = '\\';
   for (int i = 3; i < 300; i++) buf[i] = 'a';
   exercise(buf, 300);
   fprintf(stderr, "[repro] returned without ASAN trap "
                   "(no overflow for CANON_OUT=%d)\n", CANON_OUT);
   return 0;
}
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   exercise(data, size);
   return 0;
}
#endif
