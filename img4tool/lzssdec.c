//
//  lzssdec.c
//  img4tool
//
//  Code borrowed from: http://newosxbook.com/src.jl?tree=listings&file=joker.c
//  Coded by Jonathan Levin (a.k.a @Morpheus______), http://newosxbook.com
//

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#include "lzssdec.h"

/*
 * LZSS.C -- A data compression program for decompressing lzss compressed objects
 * 4/6/1989 Haruhiko Okumura
 * Use, distribute, and modify this program freely.
 * Please send me your improved versions.
 * PC-VAN      SCIENCE
 * NIFTY-Serve PAF01022
 * CompuServe  74050,1022
 
 * Copyright (c) 2003 Apple Computer, Inc.
 * DRI: Josh de Cesare
 */

#define N         4096  /* size of ring buffer - must be power of 2 */
#define F         18    /* upper limit for match_length */
#define THRESHOLD 2     /* encode string into position and length if match_length is greater than this */
#define NIL       N     /* index for root of binary search trees */

/* define type for build for win64 support */
typedef unsigned char u_int8_t;
typedef unsigned int u_int32_t;
void *lz_memmem(const void *b1, const void *b2, size_t len1, size_t len2)
{
    char *sp = (char *) b1; // Initialize search pointer
    char *pp = (char *) b2; // Initialize pattern pointer
    char *eos   = sp + len1 - len2; // Initialize end of search address space pointer
    
    /* Sanity check */
    if(!(b1 && b2 && len1 && len2))
        return NULL;
    
    while (sp <= eos) {
        if (*sp == *pp)
            if (memcmp(sp, pp, len2) == 0)
                return sp;
        
        sp++;
    }
    
    return NULL;
}

int decompressed_lzss(u_int8_t *dst, u_int8_t *src, u_int32_t srclen){
    /* ring buffer of size N, with extra F-1 bytes to aid string comparison */
    u_int8_t text_buf[N + F - 1];
    u_int8_t *dststart = dst;
    u_int8_t *srcend = src + srclen;
    int  i, j, k, r, c;
    unsigned int flags;
    
    dst = dststart;
    srcend = src + srclen;
    for (i = 0; i < N - F; i++)
        text_buf[i] = ' ';
    r = N - F;
    flags = 0;
    for ( ; ; ) {
        if (((flags >>= 1) & 0x100) == 0) {
            if (src < srcend) c = *src++; else break;
            flags = c | 0xFF00;  /* uses higher byte cleverly */
        }   /* to count eight */
        if (flags & 1) {
            if (src < srcend) c = *src++; else break;
            *dst++ = c;
            text_buf[r++] = c;
            r &= (N - 1);
        } else {
            if (src < srcend) i = *src++; else break;
            if (src < srcend) j = *src++; else break;
            i |= ((j & 0xF0) << 4);
            j  =  (j & 0x0F) + THRESHOLD;
            for (k = 0; k <= j; k++) {
                c = text_buf[(i + k) & (N - 1)];
                *dst++ = c;
                text_buf[r++] = c;
                r &= (N - 1);
            }
        }
    }
    
    return (int)(dst - dststart);
}

struct compHeader {
    char        sig[8] ; // "complzss"
    uint32_t    unknown; // Likely CRC32. But who cares, anyway?
    uint32_t    uncompressedSize;
    uint32_t    compressedSize;
    uint32_t    unknown1; // 1
};

char *tryLZSS(char *compressed, size_t *filesize){
    struct compHeader *compHeader = (struct compHeader*)compressed;
    if (!compHeader) return NULL;
    int sig[2] = { 0xfeedfacf, 0x0100000c };
    int sig2[2] = { 0xfeedface, 0x0000000c };
    
    char *decomp = malloc (ntohl(compHeader->uncompressedSize));
    char *feed = lz_memmem(compressed+64, 1024, sig, sizeof(sig));
    
    if (!feed){
        feed = lz_memmem(compressed+64, 1024, sig2, sizeof(sig2));
        if (!feed)
            return NULL;
    }
    
    feed--;
    int rc = decompressed_lzss((void*)decomp, (void*)feed, ntohl(compHeader->compressedSize));
    if (rc != ntohl(compHeader->uncompressedSize)) {
        return NULL;
    }
    
    *filesize = rc;
    return (decomp);
    
} // compLZSS
