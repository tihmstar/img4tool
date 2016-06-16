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

t_asn1ElemLen asn1Len(char buf[4]){
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
    
    t_asn1ElemLen ret;
    ret.dataLen = outSize;
    ret.sizeBytes = sizeBytes_+1;
    return ret;
}

t_asn1Tag *asn1ParseTag(char *buf, char **data, size_t *dataLen){
    char *data_ = NULL;
    
    t_asn1Tag *tag = (t_asn1Tag*)buf;
    if (tag->tagClass == kASN1TagClassPrivate && buf[1] & 0x80) {
        size_t tagbytes = asn1Len(++buf).sizeBytes;
        buf += tagbytes+1;
    }
    
    t_asn1ElemLen len = asn1Len(++buf);
    data_ = buf + len.sizeBytes;
    
    if (data) *data = data_;
    if (dataLen) *dataLen = len.dataLen;
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
    
    t_asn1ElemLen len = asn1Len(++buf);
    *strlen = len.dataLen;
    buf+=len.sizeBytes;
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


int getSequenceName(char *buf, size_t buflen,char**name, size_t *nameLen){
#define reterror(a ...){printf(a); err = -1; goto error;}
    int err = 0;
    if (((t_asn1Tag*)buf)->tagNumber != kASN1TagSEQUENCE) reterror("[Error] getSequenceName: not a SEQUENCE");
    int elems = asn1ElementsInObject(buf, buflen);
    if (!elems) reterror("[Error] getSequenceName: no elements in SEQUENCE\n");
    ans1GetString((char*)asn1ElementAtIndex(buf,0),name,nameLen);
    
error:
    return err;
#undef reterror
}

size_t asn1GetPrivateTagnum(t_asn1Tag *tag){
    t_asn1ElemLen taglen = asn1Len((char*)tag);
    taglen.sizeBytes-=1;
    size_t tagname =0;
    do {
        tagname *=0x100;
        tagname>>=1;
        tagname += ((t_asn1PrivateTag*)tag)->num;
    } while (((t_asn1PrivateTag*)tag++)->more);
    return tagname;
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
    
    t_asn1ElemLen len = asn1Len((char*)str+1);
    
    unsigned char *string = (unsigned char*)str + len.sizeBytes +1;
    
    while (len.dataLen--) printf("%02x",*string++);
}

void printI5AString(t_asn1Tag *str){
    if (str->tagNumber != kASN1TagIA5String){
        error("[Error] not an I5A string\n");
        return;
    }
    
    t_asn1ElemLen len = asn1Len((char*)++str);
    putStr(((char*)str)+len.sizeBytes, len.dataLen);
}

void printKBAGOctet(char *octet){
#define reterror(a ...){printf(a);goto error;}
    if (((t_asn1Tag*)octet)->tagNumber != kASN1TagOCTET) reterror("[Error] printKBAGOctet: not an OCTET\n");
    
    t_asn1ElemLen octetlen = asn1Len(++octet);
    octet +=octetlen.sizeBytes;
    //main seq
    int subseqs = asn1ElementsInObject(octet, octetlen.dataLen);
    for (int i=0; i<subseqs; i++) {
        char *s = (char*)asn1ElementAtIndex(octet, i);
        int elems = asn1ElementsInObject(s, asn1Len(s+1).dataLen+1);
        
        if (elems--){
            //integer (currently unknown?)
            t_asn1Tag *num = asn1ElementAtIndex(s, 0);
            if (num->tagNumber != kASN1TagINTEGER) warning("[Warning] skipping unexpected tag\n");
            else{
                char n = *(char*)(num+2);
                printf("num: %d\n",n);
            }
        }
        if (elems--)printHexString(asn1ElementAtIndex(s, 1)),putchar('\n');
        if (elems--)printHexString(asn1ElementAtIndex(s, 2)),putchar('\n');
    }
    
error:
    return;
#undef reterror
}

void printNumber(t_asn1Tag *tag){
    if (tag->tagNumber != kASN1TagINTEGER) {
        error("[Error] printNumber: tag not an INTEGER\n");
        return;
    }
    t_asn1ElemLen len = asn1Len((char*)++tag);
    uint num = 0;
    while (len.sizeBytes--) {
        num *=0x100;
        num += *(unsigned char*)++tag;
    }
    printf("%u",num);
}

void printIM4P(char *buf, size_t len){
#define reterror(a ...){printf(a);goto error;}
    
    char *magic;
    size_t l;
    getSequenceName(buf, len, &magic, &l);
    if (strncmp("IM4P", magic, l)) reterror("[Error] printIM4P: unexpected \"%.*s\", expected \"IM4P\"\n",(int)l,magic);
    
    int elems = asn1ElementsInObject(buf, len);
    if (elems--) printStringWithKey("type: ",asn1ElementAtIndex(buf, 1));
    if (elems--) printStringWithKey("desc: ",asn1ElementAtIndex(buf, 2));
    if (elems--) {
        //data
        t_asn1Tag *data =asn1ElementAtIndex(buf, 3);
        if (data->tagNumber != kASN1TagOCTET) warning("[Warning] printIM4P: skipped an unexpected tag where OCTETSTING was expected\n");
        else printf("size: 0x%08zx\n",asn1Len((char*)data+1).dataLen);
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

int extractFileFromIM4P(char *buf, size_t len, char *dstFilename){
    int elems = asn1ElementsInObject(buf, len);
    if (elems < 4){
        error("[Error] extractFileFromIM4P: not enough elements in SEQUENCE %d\n",elems);
        return -2;
    }
    
    t_asn1Tag *dataTag = asn1ElementAtIndex(buf, 3)+1;
    t_asn1ElemLen dlen = asn1Len((char*)dataTag);
    char *data = (char*)dataTag+dlen.sizeBytes;
    
    FILE *f = fopen(dstFilename, "wb");
    if (!f) {
        error("[Error] extractFileFromIM4P: can't open file %s\n",dstFilename);
        return -1;
    }
    fwrite(data, dlen.dataLen, 1, f);
    fclose(f);
    
    return 0;
}

void printElemsInIMG4(char *buf, size_t buflen){
#define reterror(a...) {printf(a); goto error;}
    char *magic;
    size_t l;
    getSequenceName(buf, buflen, &magic, &l);
    if (strncmp("IMG4", magic, l)) reterror("[Error] printElemsInIMG4: unexpected \"%.*s\", expected \"IMG4\"\n",(int)l,magic);
    printf("IMG4:\n");
    int elems = asn1ElementsInObject(buf, buflen);
    
    for (int i=1; i<elems; i++) {
        char *tag = (char*)asn1ElementAtIndex(buf, i);
        
        if (((t_asn1Tag*)tag)->tagClass == kASN1TagClassContextSpecific) {
            tag += asn1Len((char*)tag+1).sizeBytes +1;
        }
        
        char *magic = 0;
        size_t l;
        getSequenceName((char*)tag, asn1Len((char*)tag+1).dataLen, &magic, &l);
        
        putStr(magic, l);printf(": ---------\n");
        
        if (strncmp("IM4R", magic, l) == 0) printIM4R(tag, asn1Len(tag+1).dataLen);
        if (strncmp("IM4M", magic, l) == 0) printIM4M(tag, asn1Len(tag+1).dataLen);
        if (strncmp("IM4P", magic, l) == 0) printIM4P(tag, asn1Len(tag+1).dataLen);
        putchar('\n');
    }
    
error:
    return;
#undef reterror
}


void printIM4R(char *buf, size_t len){
#define reterror(a ...){printf(a);goto error;}
    
    char *magic;
    size_t l;
    getSequenceName(buf, len, &magic, &l);
    if (strncmp("IM4R", magic, l)) reterror("[Error] printIM4R: unexpected \"%.*s\", expected \"IM4R\"\n",(int)l,magic);
    
    int elems = asn1ElementsInObject(buf, len);
    if (elems<2) reterror("[Error] printIM4R: expecting at least 2 elements\n");
    
    t_asn1Tag *set = asn1ElementAtIndex(buf, 1);
    if (set->tagNumber != kASN1TagSET) reterror("[Error] printIM4R: expecting SET type\n");
    
    set += asn1Len((char*)set+1).sizeBytes+1;
    
    if (set->tagClass != kASN1TagClassPrivate) reterror("[Error] printIM4R: expecting PRIVATE type\n");
    
    printf("PrivTag: 0x%08zx\n",asn1GetPrivateTagnum(++set));
    
    set++;
    elems = asn1ElementsInObject((char*)set, asn1Len((char*)set-1).dataLen);
    if (elems<2) reterror("[Error] printIM4R: expecting at least 2 elements\n");
    
    printf("\t");
    printI5AString(asn1ElementAtIndex((char*)set, 0));
    printf(": ");
    printHexString(asn1ElementAtIndex((char*)set, 1));
    putchar('\n');
    
error:
    return;
#undef reterror
}


void printIM4M(char *buf, size_t len){
#define reterror(a ...){printf(a);goto error;}
    
    char *magic;
    size_t l;
    getSequenceName(buf, len, &magic, &l);
    if (strncmp("IM4M", magic, l)) reterror("[Error] printIM4M: unexpected \"%.*s\", expected \"IM4M\"\n",(int)l,magic);
    
    int elems = asn1ElementsInObject(buf, len);
    if (elems<2) reterror("[Error] printIM4R: expecting at least 2 elements\n");
    
    if (--elems>0) {
        printf("someinteger: ");
        printNumber(asn1ElementAtIndex(buf, 1));
        putchar('\n');
    }
    if (--elems>0) {
        t_asn1Tag *manbset = asn1ElementAtIndex(buf, 2);
#warning todo stuff here
    }
    
    
error:
    return;
#undef reterror
}



