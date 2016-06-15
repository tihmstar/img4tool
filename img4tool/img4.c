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

#define putStr(s,l) printf("%.*s",(int)l,s)

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

t_asn1Tag *asn1ParseTag(char *buf, char **data, size_t *dataLen){
    char *data_ = NULL;
    int tagbytes = 0;
    size_t dataLen_ = 0;
    
    t_asn1Tag *tag = (t_asn1Tag*)buf;
    if (tag->tagClass == kASN1TagClassPrivate && buf[1] & 0x80) {
        int tagbytes = 0;
        asn1Len(++buf, (size_t*)&tagbytes);
        buf += tagbytes+1;
    }
    
    dataLen_ = asn1Len(++buf, (size_t*)&tagbytes);
    data_ = buf + tagbytes;
    
    
    if (data) *data = data_;
    if (dataLen) *dataLen = dataLen_;
    return tag;
}

int asn1ElementsInObject(char *buf, size_t bufLen){
    int ret = 0;
    
    char *data;
    size_t dataLen;
    t_asn1Tag *tag = asn1ParseTag(buf, &data, &dataLen);
    
    if (!tag->isConstructed) return 0;
    
    bufLen -= data - buf;
    buf = data;
    while (dataLen) {
        size_t subDataLen;
        asn1ParseTag(buf, &data, &subDataLen);
        dataLen -= data - buf +subDataLen;
        buf = data + subDataLen;
        ret ++;
    }
    return ret;
}

char *ans1GetString(char *buf, char **outString, size_t *strlen){
    
    t_asn1Tag *tag = (t_asn1Tag *)buf;
    
    if (!(tag->tagNumber | kASN1TagIA5String)) {
        error("[Error] ans1GetString: not a string\n");
        return 0;
    }
    
    size_t sbytes;
    *strlen = asn1Len(++buf, &sbytes);
    buf+=sbytes;
    if (outString) *outString = buf;
    
    return buf+*strlen;
}

t_asn1Tag *asn1ElementAtIndex(char *buf, int index){
    char *data;
    size_t dataLen;
    t_asn1Tag *ret = asn1ParseTag(buf, &data, &dataLen);
    
    
    if (!ret->isConstructed) return 0; //not a constructed object
    int firstTag = 1;
    while (dataLen) {
        size_t subDataLen;
        asn1ParseTag((char*)ret, &data, &subDataLen);
        dataLen -= data - buf +subDataLen;
        ret = (t_asn1Tag *) data;
        if (!firstTag)ret += subDataLen;
        else firstTag = 0;
        
        
        if (!index--) break;
    }
    
    return ret;
}

void printStringWithKey(char*key, t_asn1Tag *string){
    char *str = 0;
    size_t strlen;
    ans1GetString((char*)string,&str,&strlen);
    printf("%s",key);
    putStr(str, strlen);
    putchar('\n');
}

void printHexString(t_asn1Tag *str){
    if (str->tagNumber != kASN1TagOCTET){
        error("[Error] not an OCTET string\n");
        return;
    }
    
    size_t sb;
    size_t len = asn1Len((char*)str+1, &sb);
    
    unsigned char *string = (unsigned char*)str + sb +1;
    
    while (len--) printf("%02x",*string++);
}

void printKBAGOctet(char *octet){
#define reterror(a ...){printf(a);goto error;}
    if (((t_asn1Tag*)octet)->tagNumber != kASN1TagOCTET) reterror("[Error] printKBAGOctet: not an OCTET\n");
    
    size_t lb;
    size_t octetlen = asn1Len(++octet, &lb);
    octet +=lb;
    //main seq
    int subseqs = asn1ElementsInObject(octet, octetlen);
    for (int i=0; i<subseqs; i++) {
        char *s = (char*)asn1ElementAtIndex(octet, i);
        int elems = asn1ElementsInObject(s, asn1Len(s+1, 0)+1);
        
        if (elems--){
            //integer (currently unknown?)
            t_asn1Tag *num = asn1ElementAtIndex(s, 0);
            char *dbg = num;
            if (num->tagNumber != kASN1TagINTEGER) warning("[Warning] skipping unexpected tag\n");
            else{
                char n = *(char*)(num+2);
                printf("num: %d\n",n);
            }
        }
        if (elems--)printHexString(asn1ElementAtIndex(s, 1)),putchar('\n');
        if (elems--)printHexString(asn1ElementAtIndex(s, 2)),putchar('\n');
        
        putchar('\n');
    }
    
error:
    return;
#undef reterror
}

void printIM4P(char *buf, size_t len){
#define reterror(a ...){printf(a);goto error;}
    
    t_asn1Tag *tag = (t_asn1Tag*)buf;
    if (!(tag->tagNumber | kASN1TagSEQUENCE)) reterror("[Error] printIM4P: not a SEQUENCE\n");
    
    int elems = asn1ElementsInObject(buf, len);
    if (!elems--) reterror("[Error] printIM4P: no elements in SEQUENCE\n");
    size_t l;
    char *magic;
    ans1GetString((char*)asn1ElementAtIndex(buf,0),&magic,&l);
    if (strncmp("IM4P", magic, l)) reterror("[Error] printIM4P: unexpected \"%.*s\", expected \"IM4P\"\n",(int)l,magic);
    

    if (elems--) printStringWithKey("type: ",asn1ElementAtIndex(buf, 1));
    if (elems--) printStringWithKey("desc: ",asn1ElementAtIndex(buf, 2));
    if (elems--) {
        //data
        t_asn1Tag *data =asn1ElementAtIndex(buf, 3);
        if (data->tagNumber != kASN1TagOCTET) warning("[Warning] printIM4P: skipped an unexpected tag where OCTETSTING was expected\n");
        else printf("size: 0x%08zx\n",asn1Len((char*)data+1, NULL));
    }
    if (elems--) {
        //kbag values
        printf("\nKBAG\n");
        printKBAGOctet((char*)asn1ElementAtIndex(buf, 4));
    }
    
error:
    return;
#undef reterror
}







