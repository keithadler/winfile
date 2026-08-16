/*
 * fuzz_junction.c — reproducer for the stack overflow CodeQL flagged in
 * WFJunction() (src/lfn.c:674). Models the exact buffer arithmetic of
 * src/lfn.c:726-758 with 16-bit WCHARs (as on Windows) so the byte offsets
 * and the 3072-byte buffer size match the real code.
 *
 * Root cause: reparseBuffer is `char[MAXPATHLEN*3]` (3072 bytes) — the dev
 * comment assumes "3x MAXPATHLEN" is enough for two paths, but paths are
 * WCHAR (2 bytes), so two ~MAXPATHLEN paths need ~4x MAXPATHLEN bytes. The
 * second wcscpy_s is told its size is MAXPATHLEN even though it writes at an
 * offset into PathBuffer, so its bounds check can't stop the overrun.
 *
 * Build: ./build-fuzz.sh repro-junction   (or with TARGET_LEN=NNN)
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef uint16_t WCHAR;              /* Windows WCHAR is 16-bit */
#define MAXPATHLEN 1024              /* src/wftypes.h MAXLFNPATHLEN */

/* REPARSE_DATA_BUFFER for a mount point, header laid out exactly as Windows:
 * 4 + 2 + 2 + (2+2+2+2) = 16 bytes before PathBuffer. */
#pragma pack(push,1)
typedef struct {
   uint32_t ReparseTag;
   uint16_t ReparseDataLength;
   uint16_t Reserved;
   uint16_t SubstituteNameOffset;
   uint16_t SubstituteNameLength;
   uint16_t PrintNameOffset;
   uint16_t PrintNameLength;
   WCHAR    PathBuffer[1];
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;
#pragma pack(pop)

static size_t w_len(const WCHAR *s){ size_t n=0; while(s[n]) n++; return n; }

/* Faithful model of wcscpy_s(dst, size, src): the secure CRT copies when
 * wcslen(src) < size, otherwise invokes the invalid-parameter handler. Here
 * the caller passes size=MAXPATHLEN, and since the target always satisfies
 * wcslen(src) < MAXPATHLEN, the real wcscpy_s copies too — the overflow comes
 * from `size` not reflecting the true remaining space at an offset. */
static void w_cpy_s(WCHAR *dst, size_t size, const WCHAR *src){
   size_t n = w_len(src);
   if (n < size) memcpy(dst, src, (n+1)*sizeof(WCHAR));
   else { fprintf(stderr,"[wcscpy_s] would fault (len %zu >= size %zu)\n", n, size); abort(); }
}

/* swprintf_s(dst, size, L"\\??\\%s", target) — build the substitute name. */
static void make_substitute(WCHAR *dst, size_t size, const WCHAR *target){
   const WCHAR pfx[] = { '\\','?','?','\\', 0 };
   size_t i=0;
   for (size_t k=0; pfx[k] && i<size-1; k++) dst[i++]=pfx[k];
   for (size_t k=0; target[k] && i<size-1; k++) dst[i++]=target[k];
   dst[i]=0;
}

#ifndef TARGET_LEN
#define TARGET_LEN 800      /* > ~761 threshold => overflow; try 260 for "safe" */
#endif

int main(void){
   /* Real code: char reparseBuffer[MAXPATHLEN*3]; on the STACK. We heap-alloc
    * the same size so ASan's red-zone marks the exact overflow byte. */
   char *reparseBuffer = (char*)malloc(MAXPATHLEN*3);   /* 3072 bytes */

   /* szTargetName = GetFullPathName(user target) — bounded to MAXPATHLEN. */
   WCHAR szTargetName[MAXPATHLEN];
   size_t T = TARGET_LEN; if (T > MAXPATHLEN-1) T = MAXPATHLEN-1;
   for (size_t i=0;i<T;i++) szTargetName[i]='a';
   szTargetName[T]=0;

   WCHAR szSubstituteName[MAXPATHLEN];
   make_substitute(szSubstituteName, MAXPATHLEN, szTargetName);

   PREPARSE_DATA_BUFFER r = (PREPARSE_DATA_BUFFER)reparseBuffer;
   memset(r, 0, 16 + sizeof(WCHAR));
   r->ReparseTag = 0xA0000003;  /* IO_REPARSE_TAG_MOUNT_POINT */

   fprintf(stderr,"[repro] target len=%zu, PathBuffer cap=%d wchars, buffer=%d bytes\n",
           T, (MAXPATHLEN*3-16)/2, MAXPATHLEN*3);

   /* src/lfn.c:754 */
   w_cpy_s(r->PathBuffer, MAXPATHLEN, szSubstituteName);
   /* src/lfn.c:758 — size arg ignores the offset => overflow */
   w_cpy_s(r->PathBuffer + w_len(szSubstituteName) + 1, MAXPATHLEN, szTargetName);

   fprintf(stderr,"[repro] returned without ASAN trap (no overflow at len=%zu)\n", T);
   free(reparseBuffer);
   return 0;
}
