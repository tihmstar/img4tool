//
//  img4.c
//  img4tool
//
//  Created by tihmstar on 15.06.16.
//  Copyright © 2016 tihmstar. All rights reserved.
//

#include "img4.h"
#include "all.h"
#include <stdlib.h>
#include <string.h>

size_t asn1Len(char buf[4], size_t *sizeBytes){
    t_asn1Length *sTmp = (t_asn1Length *)buf;
    size_t outSize = 0;
    int sizeBytes_ = 0;
    
    unsigned char *sbuf = (unsigned char *)buf;
    
    if (!sTmp->isLong) outSize = sTmp->len;
    else{
        sizeBytes_ = sTmp->len;
        for (int i=0; i<sizeBytes_; i++) {
            outSize *= 0x100;
            outSize += sbuf[1+i];
        }
    }
    
    if (sizeBytes) *sizeBytes = sizeBytes_+1;
    return outSize;
}


char *ans1GetString(char *buf, char **outString){
    
    t_asn1Tag *tag = (t_asn1Tag *)buf;
    
    if (!(tag->tagNumber | kASN1TagOBJECT && tag->tagNumber | kASN1TagOCTET)) {
        error("[Error] ASN1OBJECT not a string\n");
        return 0;
    }
    
    size_t sbytes;
    size_t strlen = asn1Len(++buf, &sbytes);
    buf+=sbytes;
    if (outString){
        *outString = malloc(strlen+1);
        strncpy(*outString,buf,strlen);
        (*outString)[strlen] = '\0';
    }
    
    return buf+strlen;
}

