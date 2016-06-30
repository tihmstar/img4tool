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

int asn1ElementsInObject(char *buf){
    int ret = 0;
    
    if (!((t_asn1Tag *)buf)->isConstructed) return 0;
    t_asn1ElemLen len = asn1Len(++buf);
    
    buf +=len.sizeBytes+1;
    while (len.dataLen) {
        t_asn1ElemLen sublen = asn1Len(buf);
        size_t toadd =sublen.dataLen + sublen.sizeBytes + 1;
        len.dataLen -=toadd;
        buf +=toadd;
        ret ++;
    }
    return ret;
}

char *ans1GetString(char *buf, char **outString, size_t *strlen){
    
    t_asn1Tag *tag = (t_asn1Tag *)buf;
    
    if (!(tag->tagNumber | kASN1TagIA5String)) {
        error("not a string\n");
        return 0;
    }
    
    t_asn1ElemLen len = asn1Len(++buf);
    *strlen = len.dataLen;
    buf+=len.sizeBytes;
    if (outString) *outString = buf;
    
    return buf+*strlen;
}

t_asn1Tag *asn1ElementAtIndex(char *buf, int index){
    int num = 0;
    char *ret = 0;;
    
    if (!((t_asn1Tag *)buf)->isConstructed) return 0;
    t_asn1ElemLen len = asn1Len(++buf);
    
    buf +=len.sizeBytes+1;
    do {
        ret = buf-1;
        t_asn1ElemLen sublen = asn1Len(buf);
        size_t toadd =sublen.dataLen + sublen.sizeBytes + 1;
        len.dataLen -=toadd;
        buf +=toadd;
        if (num == index) break;
        num ++;
    } while (len.dataLen);
    
    return (t_asn1Tag*)ret;
}


int getSequenceName(char *buf,char**name, size_t *nameLen){
#define reterror(a ...){error(a); err = -1; goto error;}
    int err = 0;
    if (((t_asn1Tag*)buf)->tagNumber != kASN1TagSEQUENCE) reterror("not a SEQUENCE");
    int elems = asn1ElementsInObject(buf);
    if (!elems) reterror("no elements in SEQUENCE\n");
    size_t len;
    ans1GetString((char*)asn1ElementAtIndex(buf,0),name,&len);
    if (nameLen) *nameLen = len;
error:
    return err;
#undef reterror
}

size_t asn1GetPrivateTagnum(t_asn1Tag *tag, size_t *sizebytes){
    if (*(unsigned char*)tag != 0xff) {
        error("not a private TAG 0x%02x\n",*(unsigned int*)tag);
        return 0;
    }
    size_t sb = 1;
    t_asn1ElemLen taglen = asn1Len((char*)++tag);
    taglen.sizeBytes-=1;
    size_t tagname =0;
    do {
        tagname *=0x100;
        tagname>>=1;
        tagname += ((t_asn1PrivateTag*)tag)->num;
        sb++;
    } while (((t_asn1PrivateTag*)tag++)->more);
    if (sizebytes) *sizebytes = sb;
    return tagname;
}

uint64_t ans1GetNumberFromTag(t_asn1Tag *tag){
    if (tag->tagNumber != kASN1TagINTEGER) return (error("not an INTEGER\n"),0);
    uint64_t ret = 0;
    t_asn1ElemLen len = asn1Len((char*)++tag);
    unsigned char *data = (unsigned char*)tag+len.sizeBytes;
    while (len.dataLen--) {
        ret *= 0x100;
        ret+= *data++;
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
        error("not an OCTET string\n");
        return;
    }
    
    t_asn1ElemLen len = asn1Len((char*)str+1);
    
    unsigned char *string = (unsigned char*)str + len.sizeBytes +1;
    
    while (len.dataLen--) printf("%02x",*string++);
}

void printI5AString(t_asn1Tag *str){
    if (str->tagNumber != kASN1TagIA5String){
        error("not an I5A string\n");
        return;
    }
    
    t_asn1ElemLen len = asn1Len((char*)++str);
    putStr(((char*)str)+len.sizeBytes, len.dataLen);
}

void printKBAGOctet(char *octet){
#define reterror(a ...){error(a);goto error;}
    if (((t_asn1Tag*)octet)->tagNumber != kASN1TagOCTET) reterror("not an OCTET\n");
    
    t_asn1ElemLen octetlen = asn1Len(++octet);
    octet +=octetlen.sizeBytes;
    //main seq
    int subseqs = asn1ElementsInObject(octet);
    for (int i=0; i<subseqs; i++) {
        char *s = (char*)asn1ElementAtIndex(octet, i);
        int elems = asn1ElementsInObject(s);
        
        if (elems--){
            //integer (currently unknown?)
            t_asn1Tag *num = asn1ElementAtIndex(s, 0);
            if (num->tagNumber != kASN1TagINTEGER) warning("skipping unexpected tag\n");
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
        error("tag not an INTEGER\n");
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

void printIM4P(char *buf){
#define reterror(a ...){error(a);goto error;}
    
    char *magic;
    size_t l;
    getSequenceName(buf, &magic, &l);
    if (strncmp("IM4P", magic, l)) reterror("unexpected \"%.*s\", expected \"IM4P\"\n",(int)l,magic);
    
    int elems = asn1ElementsInObject(buf);
    if (--elems>0) printStringWithKey("type: ",asn1ElementAtIndex(buf, 1));
    if (--elems>0) printStringWithKey("desc: ",asn1ElementAtIndex(buf, 2));
    if (--elems>0) {
        //data
        t_asn1Tag *data =asn1ElementAtIndex(buf, 3);
        if (data->tagNumber != kASN1TagOCTET) warning("skipped an unexpected tag where OCTETSTING was expected\n");
        else printf("size: 0x%08zx\n",asn1Len((char*)data+1).dataLen);
    }
    if (--elems>0) {
        //kbag values
        printf("\nKBAG\n");
        printKBAGOctet((char*)asn1ElementAtIndex(buf, 4));
    }else{
        printf("\nIM4P does not contain KBAG values\n");
    }
    
error:
    return;
#undef reterror
}

int extractFileFromIM4P(char *buf, char *dstFilename){
    int elems = asn1ElementsInObject(buf);
    if (elems < 4){
        error("not enough elements in SEQUENCE %d\n",elems);
        return -2;
    }
    
    t_asn1Tag *dataTag = asn1ElementAtIndex(buf, 3)+1;
    t_asn1ElemLen dlen = asn1Len((char*)dataTag);
    char *data = (char*)dataTag+dlen.sizeBytes;
    
    FILE *f = fopen(dstFilename, "wb");
    if (!f) {
        error("can't open file %s\n",dstFilename);
        return -1;
    }
    fwrite(data, dlen.dataLen, 1, f);
    fclose(f);
    
    return 0;
}

int sequenceHasName(char *buf, char *name){
    char *magic;
    size_t l;
    getSequenceName(buf, &magic, &l);
    return strncmp(name, magic, l) == 0;
}

int extractElementFromIMG4(char *buf, char* element, char *dstFilename){
#define reterror(a ...) return (error(a),-1)
    if (!sequenceHasName(buf, "IMG4")) reterror("not img4 sequcence\n");
    
    int elems = asn1ElementsInObject(buf);
    for (int i=0; i<elems; i++) {
        
        t_asn1Tag *elemen = asn1ElementAtIndex(buf, i);
        
        if (elemen->tagNumber != kASN1TagSEQUENCE && elemen->tagClass == kASN1TagClassContextSpecific) {
            //assuming we found a "subcontainer"
            elemen += asn1Len((char*)elemen+1).sizeBytes+1;
        }
        
        if (elemen->tagNumber == kASN1TagSEQUENCE && sequenceHasName((char*)elemen, element)) {
            FILE *f = fopen(dstFilename, "wb");
            if (!f) {
                error("can't open file %s\n",dstFilename);
                return -1;
            }
            
            t_asn1ElemLen len = asn1Len((char*)elemen+1);
            size_t flen = len.dataLen + len.sizeBytes +1;
            fwrite(elemen, flen, 1, f);
            fclose(f);
            
            return 0;
        }
        
        
    }
    reterror("element %s not found in IMG4\n",element);
#undef reterror
}

char *getValueForTagInSet(char *set, size_t tag){
#define reterror(a) return (error(a),NULL)
    
    if (((t_asn1Tag*)set)->tagNumber != kASN1TagSET) reterror("not a SET\n");
    t_asn1ElemLen setlen = asn1Len(++set);
    
    for (char *setelems = set+setlen.sizeBytes; setelems<set+setlen.dataLen;) {
        
        if (*(unsigned char*)setelems == 0xff) {
            //priv tag
            size_t sb;
            size_t ptag = asn1GetPrivateTagnum((t_asn1Tag*)setelems,&sb);
            setelems += sb;
            t_asn1ElemLen len = asn1Len(setelems);
            setelems += len.sizeBytes;
            if (tag == ptag) return setelems;
            setelems +=len.dataLen;
        }else{
            //normal tag
            t_asn1ElemLen len = asn1Len(setelems);
            setelems += len.sizeBytes + 1;
            if (((t_asn1Tag*)setelems)->tagNumber == tag) return setelems;
            setelems += len.dataLen;
        }
    }
    return 0;
#undef reterror
}

void printElemsInIMG4(char *buf){
#define reterror(a...) {error(a); goto error;}
    char *magic;
    size_t l;
    getSequenceName(buf, &magic, &l);
    if (strncmp("IMG4", magic, l)) reterror("unexpected \"%.*s\", expected \"IMG4\"\n",(int)l,magic);
    printf("IMG4:\n");
    int elems = asn1ElementsInObject(buf);
    
    for (int i=1; i<elems; i++) {
        char *tag = (char*)asn1ElementAtIndex(buf, i);
        
        if (((t_asn1Tag*)tag)->tagClass == kASN1TagClassContextSpecific) {
            tag += asn1Len((char*)tag+1).sizeBytes +1;
        }
        
        char *magic = 0;
        size_t l;
        getSequenceName((char*)tag, &magic, &l);
        
        putStr(magic, l);printf(": ---------\n");
        
        if (strncmp("IM4R", magic, l) == 0) printIM4R(tag);
        if (strncmp("IM4M", magic, l) == 0) printIM4M(tag);
        if (strncmp("IM4P", magic, l) == 0) printIM4P(tag);
        putchar('\n');
    }
    
error:
    return;
#undef reterror
}


void printIM4R(char *buf){
#define reterror(a ...){error(a);goto error;}
    
    char *magic;
    size_t l;
    getSequenceName(buf, &magic, &l);
    if (strncmp("IM4R", magic, l)) reterror("unexpected \"%.*s\", expected \"IM4R\"\n",(int)l,magic);
    
    int elems = asn1ElementsInObject(buf);
    if (elems<2) reterror("expecting at least 2 elements\n");
    
    t_asn1Tag *set = asn1ElementAtIndex(buf, 1);
    if (set->tagNumber != kASN1TagSET) reterror("expecting SET type\n");
    
    set += asn1Len((char*)set+1).sizeBytes+1;
    
    if (set->tagClass != kASN1TagClassPrivate) reterror("expecting PRIVATE type\n");
    
    printf("PrivTag: 0x%08zx\n",asn1GetPrivateTagnum(set++,0));
    
    set += asn1Len((char*)set).sizeBytes+1;
    elems = asn1ElementsInObject((char*)set);
    if (elems<2) reterror("expecting at least 2 elements\n");
    
    printf("\t");
    printI5AString(asn1ElementAtIndex((char*)set, 0));
    printf(": ");
    printHexString(asn1ElementAtIndex((char*)set, 1));
    putchar('\n');
    
error:
    return;
#undef reterror
}

char *getIM4PFromIMG4(char *buf){
    char *magic;
    size_t l;
    getSequenceName(buf, &magic, &l);
    if (strncmp("IMG4", magic, l)) return error("unexpected \"%.*s\", expected \"IMG4\"\n",(int)l,magic),NULL;
    if (asn1ElementsInObject(buf)<2) return error("not enough elements in SEQUENCE"),NULL;
    char *ret = (char*)asn1ElementAtIndex(buf, 1);
    getSequenceName(ret, &magic, &l);
    return (strncmp("IM4P", magic, 4) == 0) ? ret : (error("unexpected \"%.*s\", expected \"IM4P\"\n",(int)l,magic),NULL);
}

char *getIM4MFromIMG4(char *buf){
    char *magic;
    size_t l;
    getSequenceName(buf, &magic, &l);
    if (strncmp("IMG4", magic, l)) return error("unexpected \"%.*s\", expected \"IMG4\"\n",(int)l,magic),NULL;
    if (asn1ElementsInObject(buf)<3) return error("not enough elements in SEQUENCE"),NULL;
    char *ret = (char*)asn1ElementAtIndex(buf, 2);
    if (((t_asn1Tag*)ret)->tagClass != kASN1TagClassContextSpecific) return error("unexpected Tag 0x%02x, expected SET\n",*(unsigned char*)ret),NULL;
    ret += asn1Len(ret+1).sizeBytes + 1;
    getSequenceName(ret, &magic, &l);
    return (strncmp("IM4M", magic, 4) == 0) ? ret : NULL;
}

uint64_t getECIDFromIM4M(char *buf){
#define reterror(a ...) return (error(a),0)
    //get set
    int elems = asn1ElementsInObject(buf);
    if (elems<3) reterror("not enough elements in IM4M SEQUENCE\n");
    
    char *theset = (char*)asn1ElementAtIndex(buf, 2);
    
    char *manbSeq = (char*)getValueForTagInSet(theset, 0x4d414e42); //0x4d414e42 MANB private Tag
    if (!manbSeq) reterror("MANB privTag not found\n");
    if (((t_asn1Tag*)manbSeq)->tagNumber != kASN1TagSEQUENCE) reterror("value for privTag not a SEQUENCE\n");
    char *magic;
    size_t magiclen;
    getSequenceName(manbSeq, &magic, &magiclen);
    if (strncmp("MANB", magic, magiclen) != 0) reterror("unexpected SEQUENCENAME, expecting MANB\n");
    
    elems = asn1ElementsInObject(manbSeq);
    if (elems<2) reterror("not enough elements in MANB SEQUENCE\n");
    char *manbset = (char*)asn1ElementAtIndex(manbSeq, 1);
    if (((t_asn1Tag*)manbset)->tagNumber != kASN1TagSET) reterror("not a SET\n");
    
    char *manpSeq = (char*)getValueForTagInSet(manbset, 0x4d414e50); //0x4d414e50 MANP private Tag
    if (!manpSeq) reterror("MANP privTag not found\n");
    if (((t_asn1Tag*)manpSeq)->tagNumber != kASN1TagSEQUENCE) reterror("value for privTag not a SEQUENCE\n");
    getSequenceName(manpSeq, &magic, &magiclen);
    if (strncmp("MANP", magic, magiclen) != 0) reterror("unexpected SEQUENCENAME, expecting MANP\n");
    
    elems = asn1ElementsInObject(manpSeq);
    if (elems<2) reterror("not enough elements in MANP SEQUENCE\n");
    char *manpSet = (char*)asn1ElementAtIndex(manpSeq, 1);
    if (((t_asn1Tag*)manpSet)->tagNumber != kASN1TagSET) reterror("not a SET\n");
    
    char *ecidSeq = (char*)getValueForTagInSet(manpSet, 0x45434944);
    if (!ecidSeq) reterror("ECID privTag not found\n");
    if (((t_asn1Tag*)ecidSeq)->tagNumber != kASN1TagSEQUENCE) reterror("value for privTag not a SEQUENCE\n");
    
    elems = asn1ElementsInObject(ecidSeq);
    if (elems<2) reterror("not enough elements in ECID SEQUENCE\n");
    
    t_asn1Tag *ecidNum = asn1ElementAtIndex(ecidSeq, 1);
    
    return ans1GetNumberFromTag(ecidNum);
#undef reterror
}

void printIM4M(char *buf){
#define reterror(a ...){error(a);goto error;}
    
    char *magic;
    size_t l;
    getSequenceName(buf, &magic, &l);
    if (strncmp("IM4M", magic, l)) reterror("unexpected \"%.*s\", expected \"IM4M\"\n",(int)l,magic);
    
    int elems = asn1ElementsInObject(buf);
    if (elems<2) reterror("expecting at least 2 elements\n");
    
    if (--elems>0) {
        printf("someinteger: ");
        printNumber(asn1ElementAtIndex(buf, 1));
        putchar('\n');
    }
    if (--elems>0) {
        t_asn1Tag *manbset = asn1ElementAtIndex(buf, 2);
        if (manbset->tagNumber != kASN1TagSET) reterror("expecting SET\n");
        
        t_asn1Tag *privtag = manbset + asn1Len((char*)manbset+1).sizeBytes+1;
        size_t sb;
        printf("PrivTag: 0x%08zx\n",asn1GetPrivateTagnum(privtag++,&sb));
        char *manbseq = (char*)privtag+sb;
        manbseq+= asn1Len(manbseq).sizeBytes+1;
        printMANB(manbseq);
    }
    if (--elems>0){
        printf("signed hash: ");
        printHexString(asn1ElementAtIndex(buf, 3));
        putchar('\n');
    }
    if (--elems>0){
#warning TODO print apple certificate?
    }
    
    
error:
    return;
#undef reterror
}

void printMANB(char *buf){
#define reterror(a ...){error(a);goto error;}
    
    char *magic;
    size_t l;
    getSequenceName(buf, &magic, &l);
    if (strncmp("MANB", magic, l)) reterror("unexpected \"%.*s\", expected \"MANB\"\n",(int)l,magic);
    
#warning TODO stuff
    
error:
    return;
#undef reterror
}



