/*
 * fuzz_merge.c — libFuzzer harness for winfile's copy-time path merge.
 *
 * Targets LFNMergePath() and the pure string helpers it drives, all lifted
 * VERBATIM from the tree:
 *     LFNMergePath   src/lfn.c:457
 *     FindFileName   src/wfcopy.c:106
 *     RemoveLast     src/wfcopy.c:168
 *     AddBackslash   src/wfutil.c:1267
 *     I_LFNEditName  src/lfnmisc.c:193
 *
 * Reachable path: WFMoveCopyDriver -> ... -> GetNextPair (src/wfcopy.c:1796)
 *     if (IsWild(pToPath)) LFNMergePath(pToPath, FindFileName(pFrom));
 * i.e. driven by the destination mask + source filename of a copy/move.
 *
 * Win32 types/values shimmed with the real widths/constants; string helpers
 * (lstrcpy/lstrlen) shimmed to their exact wide-char semantics.
 *
 * Build via ./build-fuzz.sh (see MERGE target).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

typedef uint16_t TCHAR;
typedef TCHAR   *LPTSTR;
typedef const TCHAR *LPCTSTR;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef unsigned UINT;
typedef int      INT;
typedef int      BOOL;
#define TRUE 1

#define NO_ERROR                0
#define ERROR_INVALID_PARAMETER 87

#define MAXPATHLEN     1024          /* src/wftypes.h: MAXLFNPATHLEN */
#define CHAR_NULL      ((TCHAR)0x00)
#define CHAR_BACKSLASH ((TCHAR)'\\')
#define CHAR_COLON     ((TCHAR)':')
#define CHAR_DOT       ((TCHAR)'.')
#define CHAR_STAR      ((TCHAR)'*')
#define CHAR_QUESTION  ((TCHAR)'?')
#define DOT            CHAR_DOT
#define COUNTOF(a)     (sizeof(a)/sizeof((a)[0]))

/* Win32 lstrcpy/lstrlen semantics on wide chars. */
static LPTSTR lstrcpy(LPTSTR d, LPCTSTR s){ LPTSTR r=d; while((*d++=*s++)!=0){} return r; }
static int    lstrlen(LPCTSTR s){ int n=0; while(s[n]) n++; return n; }

/* ============ verbatim: FindFileName (src/wfcopy.c) ============ */
LPTSTR FindFileName(LPTSTR pPath)
{
   LPTSTR pT;
   for (pT=pPath; *pPath; pPath++) {
      if ((pPath[0] == CHAR_BACKSLASH || pPath[0] == CHAR_COLON) && pPath[1])
         pT = pPath+1;
   }
   return(pT);
}

/* ============ verbatim: RemoveLast (src/wfcopy.c) ============ */
UINT RemoveLast(LPTSTR pFile)
{
  LPTSTR pT;
  UINT uChars = 0;
  for (pT=pFile; *pFile; pFile++) {
     if (*pFile == CHAR_BACKSLASH) {
        pT = pFile;
        uChars = 0;
     } else if (*pFile == CHAR_COLON) {
        if (pFile[1] ==CHAR_BACKSLASH) {
           pFile++;
        }
        pT = pFile + 1;
        uChars = 0;
        continue;
     }
     uChars++;
  }
  *pT = CHAR_NULL;
  return uChars;
}

/* ============ verbatim: AddBackslash (src/wfutil.c) ============ */
UINT AddBackslash(LPTSTR lpszPath)
{
   UINT uLen = lstrlen(lpszPath);
   if (*(lpszPath+uLen-1) != CHAR_BACKSLASH) {       /* uLen==0 -> reads [-1] */
      lpszPath[uLen++] = CHAR_BACKSLASH;
      lpszPath[uLen]   = CHAR_NULL;
   }
   return uLen;
}

/* ============ verbatim: I_LFNEditName (src/lfnmisc.c) ============ */
WORD I_LFNEditName( LPTSTR lpSrc, LPTSTR lpEd, LPTSTR lpRes, INT iResBufSize )
{
   INT ResLen = 0;
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
            *(lpRes++) = DOT ;
            ResLen++;
            if (*lpSrc)
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

/* ============ verbatim: LFNMergePath (src/lfn.c) ============ */
BOOL LFNMergePath(LPTSTR lpMask, LPTSTR lpFile)
{
   TCHAR szT[MAXPATHLEN*2];
   INT iResStrlen;

   lstrcpy( szT, lpMask );
   RemoveLast( szT );
   AddBackslash(szT);

   if (!( CHAR_BACKSLASH == lpFile[0] && CHAR_NULL == lpFile[1] )) {
      iResStrlen = lstrlen( szT );
      I_LFNEditName(lpFile,
         FindFileName( lpMask ),
         szT + iResStrlen,
         COUNTOF(szT) - iResStrlen);
      iResStrlen = lstrlen( szT );
      if ((iResStrlen != 0) && CHAR_DOT == szT[iResStrlen - 1])
         szT[ iResStrlen-1 ] = CHAR_NULL;
   }
   lstrcpy(lpMask, szT);
   return TRUE;
}
/* ============ end verbatim ============ */

/* lpMask buffer size. The real caller (wfcopy.c) uses szDest[2*MAXPATHLEN].
 * Override with -DMERGE_OUT=260 to model a caller that under-sizes it. */
#ifndef MERGE_OUT
#define MERGE_OUT (2*MAXPATHLEN)
#endif

static void run(const uint8_t *data, size_t size) {
   /* split on 0x1F: [mask] 0x1F [file] */
   size_t split = size;
   for (size_t i = 0; i < size; i++) if (data[i] == 0x1F) { split = i; break; }

   size_t mlen = split;
   if (mlen > (size_t)MERGE_OUT - 1) mlen = MERGE_OUT - 1;   /* caller buffer holds the mask */
   TCHAR *mask = (TCHAR *)malloc(MERGE_OUT * sizeof(TCHAR));
   for (size_t i = 0; i < mlen; i++) mask[i] = (TCHAR)data[i];
   mask[mlen] = 0;

   size_t flen = (split < size) ? (size - split - 1) : 0;
   const uint8_t *fp = (split < size) ? data + split + 1 : data;
   if (flen > 4096) flen = 4096;
   TCHAR *file = (TCHAR *)malloc((flen + 1) * sizeof(TCHAR));
   for (size_t i = 0; i < flen; i++) file[i] = (TCHAR)fp[i];
   file[flen] = 0;

   LFNMergePath(mask, file);

   free(mask);
   free(file);
}

#ifdef REPRO
int main(void) {
   /* Bare wildcard dest (no backslash/colon): RemoveLast() empties the scratch
    * buffer, then AddBackslash() reads index -1. */
   const char *m = "*.txt";
   uint8_t buf[64]; size_t n=0;
   for (const char *p=m; *p; p++) buf[n++]=(uint8_t)*p;
   buf[n++]=0x1F;
   const char *f="report";
   for (const char *p=f; *p; p++) buf[n++]=(uint8_t)*p;
   fprintf(stderr, "[repro] merge(\"*.txt\", \"report\")...\n");
   run(buf, n);
   fprintf(stderr, "[repro] returned without ASAN trap\n");
   return 0;
}
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   run(data, size);
   return 0;
}
#endif
