//
//  lzssdec.h
//  img4tool
//
//  Code borrowed from: http://newosxbook.com/src.jl?tree=listings&file=joker.c
//  Coded by Jonathan Levin (a.k.a @Morpheus______), http://newosxbook.com

#ifndef lzssdec_h
#define lzssdec_h

#include <stdlib.h>

char *tryLZSS(const char *compressed, size_t compressedSize, size_t *outSize, const char **outHypervisor, size_t *outHypervisorSize);

uint32_t lzss_compress(const uint8_t *src, uint32_t src_len,uint8_t *dst, uint32_t dst_len);


#endif /* lzssdec_h */
