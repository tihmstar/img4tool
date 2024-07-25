//
//  img4tool.cpp
//  img4tool
//
//  Created by tihmstar on 04.10.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "../include/img4tool/img4tool.hpp"
#include "../include/img4tool/ASN1DERElement.hpp"

#include <libgeneral/macros.h>
#include <libgeneral/ByteOrder.hpp>

#include <stdio.h>
#include <string.h>
#include <array>
#include <algorithm>
extern "C"{
#include "lzssdec.h"
};

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#elif defined(HAVE_WINSOCK_H)
#include <winsock.h>
#endif

#if defined(HAVE_LIBCOMPRESSION)
#   include <compression.h>
#   define lzfse_decode_buffer(dst, dst_size, src, src_size, scratch) \
        compression_decode_buffer(dst, dst_size, src, src_size, scratch, COMPRESSION_LZFSE)
#   define lzfse_encode_buffer(dst, dst_size, src, src_size, scratch) \
        compression_encode_buffer(dst, dst_size, src, src_size, scratch, COMPRESSION_LZFSE)
#elif defined(HAVE_LIBLZFSE)
#   include <lzfse.h>
#endif

#ifdef HAVE_OPENSSL
#   include <openssl/aes.h>
#   include <openssl/sha.h>

#warning TODO adjust this for HAVE_COMMCRYPTO
#   include <openssl/x509.h> //not replaced by CommCrypto
#   include <openssl/evp.h> //not replaced by CommCrypto
#else
#   ifdef HAVE_COMMCRYPTO
#       include <CommonCrypto/CommonCrypto.h>
#       include <CommonCrypto/CommonDigest.h>
#       define SHA1(d, n, md) CC_SHA1(d, n, md)
#       define SHA384(d, n, md) CC_SHA384(d, n, md)
#       define SHA_DIGEST_LENGTH CC_SHA1_DIGEST_LENGTH
#       define SHA384_DIGEST_LENGTH CC_SHA384_DIGEST_LENGTH
#   endif //HAVE_COMMCRYPTO
#endif // HAVE_OPENSSL

using namespace tihmstar;
using namespace tihmstar::img4tool;

#define putPrivtag(s) do {static_assert(sizeof(s) >= 4, "bad privtag size"); printf("[%.4s]",(char*)&s);}while(0)
#define INDENTVALUE 3

namespace tihmstar {
    namespace img4tool {
        void printKBAG(const void *buf, size_t size, int indent = 0);
        void printMANB(const void *buf, size_t size, bool printAll, int indent = 0);
        void printMANP(const void *buf, size_t size, int indent = 0);
        void printPAYP(const void *buf, size_t size, int indent = 0);
        void printIM4R(const void *buf, size_t size, int indent = 0);
        void printWithName(const char *name, const void *buf, size_t size, int indent = 0);

        void printRecSequence(const void *buf, size_t size, int indent = 0, bool dontIndentNext = false);

        ASN1DERElement parsePrivTag(const void *buf, size_t size, size_t *outPrivTag);
        ASN1DERElement uncompressIfNeeded(const ASN1DERElement &compressedOctet, const ASN1DERElement &origIM4P, const char **outUsedCompression = NULL, const char **outHypervisor = NULL, size_t *outHypervisorSize = NULL);
    };
};

#pragma mark private

void tihmstar::img4tool::printKBAG(const void *buf, size_t size, int indent){
    ASN1DERElement octet(buf,size);

    assure(!octet.tag().isConstructed);
    assure(octet.tag().tagNumber == ASN1DERElement::TagOCTET);
    assure(octet.tag().tagClass == ASN1DERElement::TagClass::Universal);

    ASN1DERElement sequence(octet.payload(),octet.payloadSize());

    assure(sequence.tag().isConstructed);
    assure(sequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(sequence.tag().tagClass == ASN1DERElement::TagClass::Universal);

    printf("KBAG\n");
    for (auto &kbtag : sequence) {
        assure(kbtag.tag().isConstructed);
        assure(kbtag.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
        assure(kbtag.tag().tagClass == ASN1DERElement::TagClass::Universal);
        int i=-1;
        for (auto &elem : kbtag) {
            switch (++i) {
                case 0:
                    printf("num: %llu\n",elem.getIntegerValue());
                    break;
                case 1:
                case 2:
                {
                    std::string kbagstr = elem.getStringValue();
                    for (int i=0; i<kbagstr.size(); i++) {
                        printf("%02x",((uint8_t*)kbagstr.c_str())[i]);
                    }
                    printf("\n");
                    break;
                }
                default:
                    reterror("[%s] unexpected element at SEQUENCE index %d",__FUNCTION__,i);
                    break;
            }
        }
    }
}

void tihmstar::img4tool::printMANB(const void *buf, size_t size, bool printAll, int indent){
    size_t privTag = 0;
    ASN1DERElement sequence = parsePrivTag(buf, size, &privTag);
    assure(privTag == *(uint32_t*)"MANB");
    assure(sequence.tag().isConstructed);
    assure(sequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(sequence.tag().tagClass == ASN1DERElement::TagClass::Universal);

    putPrivtag(privTag);

    {
        int i=-1;
        for (auto &tag : sequence) {
            switch (++i) {
                case 0:
                    assure(tag.getStringValue() == "MANB");
                    printf(": MANB: ------------------------------\n");
                    break;
                case 1:
                {
                    assure(tag.tag().isConstructed);
                    assure(tag.tag().tagNumber == ASN1DERElement::TagSET);
                    assure(tag.tag().tagClass == ASN1DERElement::TagClass::Universal);
                    for (int z=0; z<INDENTVALUE*indent; z++) printf(" ");
                    
                    for (auto &stag : tag){
                        size_t privTag = 0;
                        ASN1DERElement subsequence = parsePrivTag(stag.buf(), stag.size(), &privTag);

                        if (privTag == *(uint32_t*)"MANP") {
                            printMANP(stag.buf(), stag.size(), indent+1);
                        }else if (printAll){
                            for (int z=0; z<INDENTVALUE*indent; z++) printf(" ");
                            putPrivtag(privTag);
                            printf(": ");
                            printRecSequence(subsequence.buf(), subsequence.size(), indent+1, true);
                            printf("\n");
                        }
                    }
                    break;
                }
                default:
                    reterror("[%s] unexpected element at SEQUENCE index %d",__FUNCTION__,i);
                    break;
            }
        }
    }
}

void tihmstar::img4tool::printMANP(const void *buf, size_t size, int indent){
    size_t privTag = 0;
    ASN1DERElement sequence = parsePrivTag(buf, size, &privTag);
    assure(privTag == *(uint32_t*)"MANP");
    assure(sequence.tag().isConstructed);
    assure(sequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(sequence.tag().tagClass == ASN1DERElement::TagClass::Universal);

    putPrivtag(privTag);

    {
        int i=-1;
        for (auto &tag : sequence) {
            switch (++i) {
                case 0:
                    assure(tag.getStringValue() == "MANP");
                    printf(": MANP: ------------------------------\n");
                    break;
                case 1:
                {
                    assure(tag.tag().isConstructed);
                    assure(tag.tag().tagNumber == ASN1DERElement::TagSET);
                    assure(tag.tag().tagClass == ASN1DERElement::TagClass::Universal);

                    for (auto &elem : tag) {
                        for (int z=0; z<INDENTVALUE*indent; z++) printf(" ");
                        size_t privElem = 0;
                        ASN1DERElement subsequence = parsePrivTag(elem.buf(), elem.size(), &privElem);
                        putPrivtag(privElem);

                        assure(subsequence.tag().isConstructed);
                        assure(subsequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
                        assure(subsequence.tag().tagClass == ASN1DERElement::TagClass::Universal);
                        
                        {
                            int pos = -1;
                            for (auto &subelem : subsequence) {
                                ++pos;
                                printf(": ");
                                if (pos == 1) {
                                    if (privElem == htonl('love')) {
                                        printf("%s",subelem.getStringValue().c_str());
                                        continue;
                                    }
                                }
                                subelem.print();
                            }
                        }
                        printf("\n");
                    }
                    break;
                }
                default:
                    reterror("[%s] unexpected element at SEQUENCE index %d",__FUNCTION__,i);
                    break;
            }
        }
    }
}

void tihmstar::img4tool::printWithName(const char *name, const void *buf, size_t size, int indent){
    ASN1DERElement sequence(buf,size);

    assure(sequence.tag().isConstructed);
    assure(sequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(sequence.tag().tagClass == ASN1DERElement::TagClass::Universal);

    ASN1DERElement filetype = sequence[0];

    assure(!filetype.tag().isConstructed);
    assure(filetype.tag().tagNumber == ASN1DERElement::TagIA5String);
    assure(filetype.tag().tagClass == ASN1DERElement::TagClass::Universal);
    {
        int i=-1;
        for (auto &tag : sequence) {
            switch (++i) {
                case 0:
                    assure(tag.getStringValue() == name);
                    printf("%s:",name);
                    break;
                case 1:
                    printRecSequence(tag.buf(), tag.size());
                    break;
                default:
                    reterror("[%s] unexpected element at SEQUENCE index %d",__FUNCTION__,i);
                    break;
            }
        }
    }
    printf("\n\n");
}

void tihmstar::img4tool::printPAYP(const void *buf, size_t size, int indent){
    return printWithName("PAYP", buf, size);
}

void tihmstar::img4tool::printIM4R(const void *buf, size_t size, int indent){
    return printWithName("IM4R", buf, size);
}

void tihmstar::img4tool::printRecSequence(const void *buf, size_t size, int indent, bool dontIndentNext){
    ASN1DERElement sequence(buf, size);

    assure(sequence.tag().isConstructed);

    for (auto &elem : sequence){
        if (*(uint8_t*)elem.buf() == (uint8_t)ASN1DERElement::TagPrivate){
            size_t privTag = 0;
            ASN1DERElement sequence = parsePrivTag(elem.buf(), elem.size(), &privTag);
            printf("\n");
            if (indent && !dontIndentNext) {
                for (int i=0; i<indent*INDENTVALUE; i++) printf(" ");
            }
            putPrivtag(privTag);
            printf(": ");
            printRecSequence(sequence.buf(), sequence.size(), indent+1, true);
        }else if (elem.tag().isConstructed) {
            printRecSequence(elem.buf(), elem.size(), indent+1);
        }else{
            ASN1DERElement subelem;
            bool haveSubelem = true;
            try {subelem = {elem.payload(),elem.payloadSize()};(void)*subelem.begin();} catch (...) {haveSubelem=false;}
            if (elem.tag().tagNumber == ASN1DERElement::TagOCTET && haveSubelem && subelem.tag().isConstructed) {
                printRecSequence(subelem.buf(), subelem.size(), indent+1);
                printf("\n");
            }else{
                if (indent && !dontIndentNext) {
                    printf("\n");
                    for (int i=0; i<indent*INDENTVALUE; i++) printf(" ");
                }
                dontIndentNext = false;
                elem.print();
                if (elem.tag().tagNumber == ASN1DERElement::TagIA5String) {
                    printf(": ");
                    dontIndentNext = true;
                }
            }
        }
    }
}


ASN1DERElement tihmstar::img4tool::parsePrivTag(const void *buf, size_t size, size_t *outPrivTag){
    size_t privTag = 0;
    ASN1DERElement::ASN1PrivateTag *ptag = NULL;
    ASN1DERElement::ASN1Len *tlen = NULL;
    size_t taginfoSize = 7;
    assure(size >= taginfoSize);
    assure(*(uint8_t*)buf == ASN1DERElement::TagPrivate);


    ptag = ((ASN1DERElement::ASN1PrivateTag *)buf) + 1;
    tlen = ((ASN1DERElement::ASN1Len *)buf) + 6;
    
    for (int i=0; i<taginfoSize-1; i++) {
        privTag <<=7;
        privTag |= ptag[i].num;
        if (!ptag[i].more) break;
    }

    if (outPrivTag) *outPrivTag = htonl(privTag);

    if (tlen->isLong){
        taginfoSize += tlen->len;
    }

    size_t playloadLen = 0;
    {
        if (!tlen->isLong){
            playloadLen = tlen->len;
        }else{
            assure(tlen->len <= sizeof(size_t)); //can't hold more than size_t
            assure(size > taginfoSize); //len bytes shouldn't be outside of buffer

            for (uint8_t sizebits = 0; sizebits < tlen->len; sizebits++) {
                playloadLen <<= 8;
                playloadLen |= ((uint8_t*)tlen)[1+sizebits];
            }
        }
    }
    
    assure(size >= playloadLen+taginfoSize);
    return {(uint8_t*)buf+taginfoSize,playloadLen};
}


#pragma mark public

const char *tihmstar::img4tool::version(){
    return VERSION_STRING;
}

void tihmstar::img4tool::printIMG4(const void *buf, size_t size, bool printAll, bool im4pOnly){
    ASN1DERElement sequence(buf,size);

    assure(sequence.tag().isConstructed);
    assure(sequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(sequence.tag().tagClass == ASN1DERElement::TagClass::Universal);

    ASN1DERElement filetype = sequence[0];

    assure(!filetype.tag().isConstructed);
    assure(filetype.tag().tagNumber == ASN1DERElement::TagIA5String);
    assure(filetype.tag().tagClass == ASN1DERElement::TagClass::Universal);
    {
        int i=-1;
        for (auto &tag : sequence) {
            switch (++i) {
                case 0:
                    assure(tag.getStringValue() == "IMG4");
                    printf("IMG4:\n");
                    printf("size: 0x%08llx\n",(uint64_t)sequence.size());
                    break;
                case 1:
                    printIM4P(tag.buf(), tag.size());
                    break;
                case 2:
                    if (!im4pOnly){
                        assure(tag.tag().isConstructed);
                        assure(tag.tag().tagNumber == 0);
                        assure(tag.tag().tagClass == ASN1DERElement::TagClass::ContextSpecific);

                        printIM4M(tag.payload(), tag.payloadSize(), printAll);
                    }
                    break;
                case 3:
                    if (!im4pOnly){
                        assure(tag.tag().isConstructed);
                        assure(tag.tag().tagNumber == 1);
                        assure(tag.tag().tagClass == ASN1DERElement::TagClass::ContextSpecific);

                        printIM4R(tag.payload(), tag.payloadSize());
                    }
                    break;
                default:
                    reterror("[%s] unexpected element at SEQUENCE index %d",__FUNCTION__,i);
                    break;
            }
        }
    }
}

void tihmstar::img4tool::printIM4P(const void *buf, size_t size){
    ASN1DERElement sequence(buf,size);
    bool hasKBAG = false;

    assure(sequence.tag().isConstructed);
    assure(sequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(sequence.tag().tagClass == ASN1DERElement::TagClass::Universal);

    {
        int i=-1;
        for (auto &tag : sequence) {
            switch (++i) {
                case 0:
                    assure(tag.getStringValue() == "IM4P");
                    printf("IM4P: ---------\n");
                    break;
                case 1:
                    assure(!tag.tag().isConstructed);
                    assure(tag.tag().tagNumber == ASN1DERElement::TagIA5String);
                    assure(tag.tag().tagClass == ASN1DERElement::TagClass::Universal);
                    printf("type: %s\n",tag.getStringValue().c_str());
                    break;
                case 2:
                    assure(!tag.tag().isConstructed);
                    assure(tag.tag().tagNumber == ASN1DERElement::TagIA5String);
                    assure(tag.tag().tagClass == ASN1DERElement::TagClass::Universal);
                    try {
                        printSEPIDesc((const char *)tag.payload(),tag.payloadSize());
                        break;
                    } catch (...) {
                        //
                    }
                    printf("desc: %s\n",tag.getStringValue().c_str());
                    break;
                case 3:
                    assure(!tag.tag().isConstructed);
                    assure(tag.tag().tagNumber == ASN1DERElement::TagOCTET);
                    assure(tag.tag().tagClass == ASN1DERElement::TagClass::Universal);
                    printf("size: 0x%08lx\n\n",tag.payloadSize());
                    break;
                case 4:
                {
                    ASN1DERElement octet = tag;
                    if (!octet.tag().isConstructed
                            && octet.tag().tagNumber == ASN1DERElement::TagOCTET
                        && octet.tag().tagClass == ASN1DERElement::TagClass::Universal){
                        printKBAG(tag.buf(),tag.size());
                        printf("\n");
                        hasKBAG = true;
                        break;
                    }else{
                        debug("Warning: got more than 3 elements, but element is not octet!\n");
                        ++i; //skip to step 5
                    }
                }
                case 5:
                case 6:
                    if (tag.tag().isConstructed && tag.tag().tagNumber == 0 && tag.tag().tagClass == ASN1DERElement::TagClass::ContextSpecific){
                        ASN1DERElement payp = tag[0];
                        printPAYP(payp.buf(), payp.size());
                    }else{
                        assure(tag.tag().isConstructed);
                        assure(tag.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
                        assure(tag.tag().tagClass == ASN1DERElement::TagClass::Universal);
                        {
                            ASN1DERElement versionTag = tag[0];
                            ASN1DERElement sizeTag    = tag[1];

                            assure(versionTag.tag().isConstructed == ASN1DERElement::Primitive);
                            assure(versionTag.tag().tagNumber == ASN1DERElement::TagINTEGER);
                            assure(versionTag.tag().tagClass == ASN1DERElement::Universal);
                            if (versionTag.getIntegerValue() != 1){
                                reterror("unexpected compression number %llu",versionTag.getIntegerValue());
                            }
                            printf("Compression: bvx2\n");
                            assure(sizeTag.tag().isConstructed == ASN1DERElement::Primitive);
                            assure(sizeTag.tag().tagNumber == ASN1DERElement::TagINTEGER);
                            assure(sizeTag.tag().tagClass == ASN1DERElement::Universal);
                            printf("Uncompressed size: 0x%08llx\n",sizeTag.getIntegerValue());
                        }
                    }
                    break;
                default:
                    reterror("[%s] unexpected element at SEQUENCE index %d",__FUNCTION__,i);
                    break;
            }
        }
        if (!hasKBAG) {
            printf("IM4P does not contain KBAG values\n\n");
        }
    }
}


void tihmstar::img4tool::printIM4M(const void *buf, size_t size, bool printAll){
    ASN1DERElement sequence(buf,size);

    assure(sequence.tag().isConstructed);
    assure(sequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(sequence.tag().tagClass == ASN1DERElement::TagClass::Universal);

    {
        int i=-1;
        for (auto &tag : sequence) {
            switch (++i) {
                case 0:
                    assure(tag.getStringValue() == "IM4M");
                    printf("IM4M: ---------\n");
                    break;
                case 1:
                    printf("Version: %llu\n",tag.getIntegerValue());
                    break;
                case 2:
                    assure(tag.tag().isConstructed);
                    assure(tag.tag().tagNumber == ASN1DERElement::TagSET);
                    assure(tag.tag().tagClass == ASN1DERElement::TagClass::Universal);
                    printMANB(tag.payload(), tag.payloadSize(), printAll, 1);
                    break;
                case 3: //signature
                case 4: //certificate
                    break;
                default:
                    reterror("[%s] unexpected element at SEQUENCE index %d",__FUNCTION__,i);
                    break;
            }
        }
    }
}

void tihmstar::img4tool::printSEPIDesc(const char *buf, size_t size){
    uint8_t *payload = NULL;
    cleanup([&]{
        safeFree(payload);
    });
    
    assure(payload = (uint8_t*)malloc(size / 2));
    
    for (size_t i=0; i<size; i+=2) {
        unsigned int v = 0;
        retassure(sscanf(&buf[i], "%02x",&v) == 1, "Failed to parse desc byte");
        payload[i/2] = (uint8_t)v;
    }
    
    ASN1DERElement sepidesc(payload,size/2);
    {
        size_t privElem = 0;
        ASN1DERElement subsequence = parsePrivTag(sepidesc.buf(), sepidesc.size(), &privElem);
        putPrivtag(privElem);
        printf(": ");
        printRecSequence(sepidesc.buf(), sepidesc.size());
    }
}


std::string tihmstar::img4tool::getNameForSequence(const void *buf, size_t size){
    ASN1DERElement sequence(buf,size);
    assure(sequence.tag().isConstructed);
    assure(sequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(sequence.tag().tagClass == ASN1DERElement::TagClass::Universal);

    return sequence[0].getStringValue();
}

ASN1DERElement tihmstar::img4tool::getIM4PFromIMG4(const ASN1DERElement &img4){
    assure(isIMG4(img4));

    ASN1DERElement im4p = img4[1];
    assure(isIM4P(im4p));

    return im4p;
}

ASN1DERElement tihmstar::img4tool::getIM4MFromIMG4(const ASN1DERElement &img4){
    assure(isIMG4(img4));

    ASN1DERElement container = img4[2];

    assure(container.tag().isConstructed);
    assure(container.tag().tagNumber == 0);
    assure(container.tag().tagClass == ASN1DERElement::TagClass::ContextSpecific);

    ASN1DERElement im4m = container[0];

    assure(im4m.tag().isConstructed);
    assure(im4m.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(im4m.tag().tagClass == ASN1DERElement::TagClass::Universal);

    retassure(im4m[0].getStringValue() == "IM4M", "Container is not a IM4M");

    return im4m;
}

ASN1DERElement tihmstar::img4tool::getIM4RFromIMG4(const ASN1DERElement &img4){
    assure(isIMG4(img4));

    ASN1DERElement container = img4[3];

    assure(container.tag().isConstructed);
    assure(container.tag().tagNumber == 1);
    assure(container.tag().tagClass == ASN1DERElement::TagClass::ContextSpecific);

    ASN1DERElement im4r = container[0];

    assure(isIM4R(im4r));

    return im4r;
}

ASN1DERElement tihmstar::img4tool::getIM4RFromGenerator(uint64_t generator){
    ASN1DERElement im4r({ASN1DERElement::TagSEQUENCE, ASN1DERElement::Constructed, ASN1DERElement::Universal},NULL,0);
    ASN1DERElement im4r_str({ASN1DERElement::TagIA5String, ASN1DERElement::Primitive, ASN1DERElement::Universal},"IM4R",4);
    im4r += im4r_str;
    
    ASN1DERElement bnch_seq({ASN1DERElement::TagSEQUENCE, ASN1DERElement::Constructed, ASN1DERElement::Universal},NULL,0);
    ASN1DERElement bnch_str({ASN1DERElement::TagIA5String, ASN1DERElement::Primitive, ASN1DERElement::Universal},"BNCN",4);
    ASN1DERElement bnch_payload({ASN1DERElement::TagOCTET, ASN1DERElement::Primitive, ASN1DERElement::Universal},&generator,8);
    bnch_seq += bnch_str;
    bnch_seq += bnch_payload;
    ASN1DERElement bnch = genPrivTagForNumberWithPayload('BNCN',bnch_seq);
    ASN1DERElement set({ASN1DERElement::TagSET, ASN1DERElement::Constructed, ASN1DERElement::Universal},NULL,0);
    set += bnch;
    im4r += set;
#ifdef DEBUG
    assure(isIM4R(im4r));
#endif
    return im4r;
}

ASN1DERElement tihmstar::img4tool::getBNCNFromIM4R(const ASN1DERElement &im4r){
    assure(isIM4R(im4r));
    
    ASN1DERElement set = im4r[1];
    
    for (auto elem : set){
        if (*(uint8_t*)elem.buf() == (uint8_t)ASN1DERElement::TagPrivate){
            size_t privTag = 0;
            ASN1DERElement bncn = parsePrivTag(elem.buf(), elem.size(), &privTag);
            if (privTag == *(uint32_t*)"BNCN"){
                ASN1DERElement octet = bncn[1];
                //convert big endian to little endian
                std::string octetString{(char*)octet.payload(),octet.payloadSize()};

                ASN1DERElement retval({ASN1DERElement::TagOCTET, ASN1DERElement::Primitive, ASN1DERElement::Universal},octetString.c_str(),octetString.size());
                return retval;
            }
        }
    }
    reterror("Failed to get bnch from IM4R");
}

ASN1DERElement tihmstar::img4tool::getEmptyIMG4Container(){
    ASN1DERElement img4({ASN1DERElement::TagSEQUENCE, ASN1DERElement::Constructed, ASN1DERElement::Universal},NULL,0);
    ASN1DERElement img4_str({ASN1DERElement::TagIA5String, ASN1DERElement::Primitive, ASN1DERElement::Universal},"IMG4",4);
    img4 += img4_str;

    return img4;
}

ASN1DERElement tihmstar::img4tool::appendIM4PToIMG4(const ASN1DERElement &img4, const ASN1DERElement &im4p){
    assure(isIMG4(img4));
    assure(isIM4P(im4p));

    ASN1DERElement newImg4(img4);

    newImg4 += im4p;

    return newImg4;
}

ASN1DERElement tihmstar::img4tool::appendIM4MToIMG4(const ASN1DERElement &img4, const ASN1DERElement &im4m){
    assure(isIMG4(img4));

    assure(im4m.tag().isConstructed);
    assure(im4m.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(im4m.tag().tagClass == ASN1DERElement::TagClass::Universal);

    retassure(im4m[0].getStringValue() == "IM4M", "Container is not a IM4M");

    ASN1DERElement newImg4(img4);

    ASN1DERElement container({ASN1DERElement::TagEnd_of_Content, ASN1DERElement::Constructed, ASN1DERElement::ContextSpecific},NULL,0);

    container += im4m;

    newImg4 += container;

    return newImg4;
}

ASN1DERElement tihmstar::img4tool::appendIM4RToIMG4(const ASN1DERElement &img4, const ASN1DERElement &im4r){
    assure(isIMG4(img4));

    assure(im4r.tag().isConstructed);
    assure(im4r.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(im4r.tag().tagClass == ASN1DERElement::TagClass::Universal);

    retassure(im4r[0].getStringValue() == "IM4R", "Container is not a IM4M");

    ASN1DERElement newImg4(img4);

    ASN1DERElement container({1, ASN1DERElement::Constructed, ASN1DERElement::ContextSpecific},NULL,0);

    container += im4r;

    newImg4 += container;

    return newImg4;
}

bool tihmstar::img4tool::im4pContainsKBAG(const ASN1DERElement &im4p){
    retassure(isIM4P(im4p), "Arg is not IM4P");
    assure(im4p.tag().isConstructed);
    assure(im4p.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(im4p.tag().tagClass == ASN1DERElement::TagClass::Universal);

    try {
        ASN1DERElement octet = im4p[4];
        if (!octet.tag().isConstructed
            && octet.tag().tagNumber == ASN1DERElement::TagOCTET
            && octet.tag().tagClass == ASN1DERElement::TagClass::Universal){
            return true;
        }
    } catch (...) {
        //
    }
    return false;
}

std::string tihmstar::img4tool::getKBAG(const ASN1DERElement &im4p, int kbagNum){
    retassure(isIM4P(im4p), "Arg is not IM4P");
    assure(im4p.tag().isConstructed);
    assure(im4p.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(im4p.tag().tagClass == ASN1DERElement::TagClass::Universal);

    ASN1DERElement octet = im4p[4];

    assure(!octet.tag().isConstructed);
    assure(octet.tag().tagNumber == ASN1DERElement::TagOCTET);
    assure(octet.tag().tagClass == ASN1DERElement::TagClass::Universal);

    ASN1DERElement sequence(octet.payload(),octet.payloadSize());

    assure(sequence.tag().isConstructed);
    assure(sequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(sequence.tag().tagClass == ASN1DERElement::TagClass::Universal);

    std::string retval;
    for (auto &kbtag : sequence) {
        assure(kbtag.tag().isConstructed);
        assure(kbtag.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
        assure(kbtag.tag().tagClass == ASN1DERElement::TagClass::Universal);
        int i=-1;
        int curKBAG = -1;
        for (auto &elem : kbtag) {
            switch (++i) {
                case 0:
                    curKBAG = (int)elem.getIntegerValue();
                    break;
                case 1:
                    if (curKBAG == kbagNum) {
                        retval = elem.getStringValue();
                    }
                    break;
                case 2:
                {
                    if (curKBAG == kbagNum) {
                        return retval + elem.getStringValue();
                    }
                    break;
                }
                default:
                    reterror("[%s] unexpected element at SEQUENCE index %d",__FUNCTION__,i);
                    break;
            }
        }
    }
    reterror("Failed to get KBAG with num=%d",kbagNum);
}


ASN1DERElement tihmstar::img4tool::uncompressIfNeeded(const ASN1DERElement &compressedOctet, const ASN1DERElement &origIM4P, const char **outUsedCompression, const char **outHypervisor, size_t *outHypervisorSize){
    const char *payload = (const char *)compressedOctet.payload();
    size_t payloadSize = compressedOctet.payloadSize();
    size_t unpackedLen = 0;
    char *unpacked = NULL;
    cleanup([&]{
        safeFree(unpacked);
    });
    ASN1DERElement retVal=compressedOctet;

    if (strncmp(payload, "complzss", 8) == 0) {
        printf("Compression detected, uncompressing (%s): ", "complzss");
        if((unpacked = tryLZSS(payload, payloadSize, &unpackedLen, outHypervisor, outHypervisorSize))){
            retVal = ASN1DERElement({ASN1DERElement::TagNumber::TagOCTET,ASN1DERElement::Primitive, ASN1DERElement::Universal}, unpacked, unpackedLen);
            printf("ok\n");
            if (outHypervisor && outHypervisorSize && *outHypervisorSize) {
                printf("Detected and extracted hypervisor!\n");
            }
            if (outUsedCompression) *outUsedCompression = "complzss";
        }else{
            printf("failed!\n");
        }
    } else if (strncmp(payload, "bvx2", 4) == 0) {
        printf("Compression detected, uncompressing (%s): ", "bvx2");
#if defined(HAVE_LIBCOMPRESSION) || defined(HAVE_LIBLZFSE)
        size_t uncompSizeReal = 0;
        //checking
        ASN1DERElement compressingSequence = origIM4P[4];
        if (!compressingSequence.tag().isConstructed
                && compressingSequence.tag().tagNumber == ASN1DERElement::TagOCTET
                && compressingSequence.tag().tagClass == ASN1DERElement::TagClass::Universal){
            compressingSequence = origIM4P[5];
        }

        ASN1DERElement versionTag = compressingSequence[0];
        ASN1DERElement sizeTag    = compressingSequence[1];

        assure(versionTag.tag().isConstructed == ASN1DERElement::Primitive);
        assure(versionTag.tag().tagNumber == ASN1DERElement::TagINTEGER);
        assure(versionTag.tag().tagClass == ASN1DERElement::Universal);
        if (versionTag.getIntegerValue() != 1){
            reterror("unexpected compression number %llu",versionTag.getIntegerValue());
        }
        assure(sizeTag.tag().isConstructed == ASN1DERElement::Primitive);
        assure(sizeTag.tag().tagNumber == ASN1DERElement::TagINTEGER);
        assure(sizeTag.tag().tagClass == ASN1DERElement::Universal);

        unpackedLen = sizeTag.getIntegerValue();
        unpacked = (char*)malloc(unpackedLen);

        
        if ((uncompSizeReal = lzfse_decode_buffer((uint8_t*)unpacked, unpackedLen, (const uint8_t*)compressedOctet.payload(), compressedOctet.payloadSize(), NULL)) == unpackedLen) {
            retVal = ASN1DERElement({ASN1DERElement::TagNumber::TagOCTET,ASN1DERElement::Primitive, ASN1DERElement::Universal}, unpacked, unpackedLen);
            printf("ok\n");
            if (outUsedCompression) *outUsedCompression = "bvx2";
        }else{
            printf("failed!\n");
        }
#else
        reterror("img4tool was build without bvx2 support");
#endif
    }

    return retVal;
}

ASN1DERElement tihmstar::img4tool::getPayloadFromIM4P(const ASN1DERElement &im4p, const char *decryptIv, const char *decryptKey, const char **outUsedCompression, ASN1DERElement *outHypervisor){
    assure(isIM4P(im4p));
    const char *hypervisorBuf = NULL;
    size_t hypervisorBufSize = 0;
    ASN1DERElement payload = im4p[3];
    if (decryptIv || decryptKey) {
#ifdef HAVE_CRYPTO
        payload = decryptPayload(payload, decryptIv, decryptKey);
        info("payload decrypted");
#else
        reterror("decryption keys were provided, but img4tool was compiled without crypto backend!");
#endif //HAVE_CRYPTO
    }

    auto ret = uncompressIfNeeded(payload, im4p, outUsedCompression, &hypervisorBuf, &hypervisorBufSize);
    if (outHypervisor && hypervisorBuf) {
        debug("Re-packaging Hypervisor");
        *outHypervisor = ASN1DERElement{{
            .tagNumber = ASN1DERElement::TagNumber::TagOCTET,
            .isConstructed = ASN1DERElement::Primitive::Primitive,
            .tagClass = ASN1DERElement::TagClass::Universal
        },hypervisorBuf, hypervisorBufSize};
    }
    
    return ret;
}

ASN1DERElement tihmstar::img4tool::getValFromIM4M(const ASN1DERElement &im4m, uint32_t val){
    assure(isIM4M(im4m));

    val = htonl(val); //allows us to pass "ECID" instead of "DICE"

    ASN1DERElement set = im4m[2];
    ASN1DERElement manbpriv = set[0];
    size_t privTagVal = 0;
    ASN1DERElement manb = parsePrivTag(manbpriv.buf(), manbpriv.size(), &privTagVal);
    assure(privTagVal == *(uint32_t*)"MANB");
    assure(manb[0].getStringValue() == "MANB");

    ASN1DERElement manbset = manb[1];

    ASN1DERElement manppriv = manbset[0];
    ASN1DERElement manp = parsePrivTag(manppriv.buf(), manppriv.size(), &privTagVal);
    assure(privTagVal == *(uint32_t*)"MANP");
    assure(manp[0].getStringValue() == "MANP");

    ASN1DERElement manpset = manp[1];

    for (auto &e : manpset) {
        size_t ptagVal = 0;
        ASN1DERElement ptag = parsePrivTag(e.buf(), e.size(), &ptagVal);
        if (ptagVal == val) {
            assure(*(uint32_t*)ptag[0].getStringValue().c_str() == val);
            return ptag[1];
        }
    }
    
    for (auto &e : manbset) {
        size_t ptagVal = 0;
        ASN1DERElement ptag = parsePrivTag(e.buf(), e.size(), &ptagVal);
        if (ptagVal == val) {
            assure(*(uint32_t*)ptag[0].getStringValue().c_str() == val);
            return ptag[1];
        }
    }

    reterror("failed to find val!");
    return {0,0};
}

ASN1DERElement tihmstar::img4tool::getValFromElement(const ASN1DERElement &e, uint32_t val){
    val = htonl(val); //allows us to pass "ECID" instead of "DICE"

    for (auto &elem : e) {
        size_t ptagVal = 0;
        ASN1DERElement ptag = parsePrivTag(elem.buf(), elem.size(), &ptagVal);
        if (ptagVal == val) {
            assure(*(uint32_t*)ptag[0].getStringValue().c_str() == val);
            return ptag[1];
        }
    }
    
    reterror("failed to find val!");
}


ASN1DERElement tihmstar::img4tool::genPrivTagForNumberWithPayload(size_t privnum, const ASN1DERElement &payload){
    char *elembuf = NULL;
    size_t elemSize = 0;
    cleanup([&]{
        safeFree(elembuf);
    });
    char buf[20] = {};
    buf[0] = 0xff;

    int modval = 0;
    while (privnum >> modval) modval+=7;
    int i=1;
    for (;i<sizeof(buf) && modval>0; i++) {
        modval-=7;
        ((ASN1DERElement::ASN1PrivateTag*)buf)[i].num = (privnum>>modval) & 0x7f;
        if (modval) {
            ((ASN1DERElement::ASN1PrivateTag*)buf)[i].more = 1;
        }
    }
    std::string payloadSize = ASN1DERElement::makeASN1Size(payload.size());

    elembuf = (char*)malloc(elemSize = (payload.size() +payloadSize.size() + i));
    memcpy(&elembuf[0], buf, i);
    memcpy(&elembuf[i], payloadSize.c_str(), payloadSize.size());
    memcpy(&elembuf[i+payloadSize.size()], payload.buf(), payload.size());

    ASN1DERElement local(elembuf,elemSize);

    //by casting to const we make sure to create a copy which owns the buffer so we can free our local buffer
    return static_cast<const ASN1DERElement>(local);
}

#pragma mark begin_needs_crypto
#ifdef HAVE_CRYPTO
ASN1DERElement tihmstar::img4tool::decryptPayload(const ASN1DERElement &payload, const char *decryptIv, const char *decryptKey){
    uint8_t iv[16] = {};
    uint8_t key[32] = {};
    retassure(decryptIv, "decryptPayload requires IV but none was provided!");
    retassure(decryptKey, "decryptPayload requires KEY but none was provided!");

    assure(!payload.tag().isConstructed);
    assure(payload.tag().tagNumber == ASN1DERElement::TagOCTET);
    assure(payload.tag().tagClass == ASN1DERElement::TagClass::Universal);

    ASN1DERElement decPayload(payload);

    assure(strlen(decryptIv) == sizeof(iv)*2);
    assure(strlen(decryptKey) == sizeof(key)*2);
    for (int i=0; i<sizeof(iv); i++) {
        unsigned int t;
        assure(sscanf(decryptIv+i*2,"%02x",&t) == 1);
        iv[i] = t;
    }
    for (int i=0; i<sizeof(key); i++) {
        unsigned int t;
        assure(sscanf(decryptKey+i*2,"%02x",&t) == 1);
        key[i] = t;
    }


#ifdef HAVE_OPENSSL
    AES_KEY decKey = {};
    retassure(!AES_set_decrypt_key(key, sizeof(key)*8, &decKey), "Failed to set decryption key");
    AES_cbc_encrypt((const unsigned char*)decPayload.payload(), (unsigned char*)decPayload.payload(), decPayload.payloadSize(), &decKey, iv, AES_DECRYPT);
#else
#   ifdef HAVE_COMMCRYPTO
    retassure(CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0, key, sizeof(key), iv, decPayload.payload(), decPayload.payloadSize(), (void*)decPayload.payload(), decPayload.payloadSize(), NULL) == kCCSuccess,
              "Decryption failed!");
#   endif //HAVE_COMMCRYPTO
#endif //HAVE_OPENSSL

    return decPayload;
}

std::string tihmstar::img4tool::getIM4PSHA1(const ASN1DERElement &im4p){
    std::array<char, SHA_DIGEST_LENGTH> tmp{'\0'};
    std::string hash{tmp.begin(),tmp.end()};
    SHA1((unsigned char*)im4p.buf(), (unsigned int)im4p.size(), (unsigned char *)hash.c_str());
    return hash;
}

std::string tihmstar::img4tool::getIM4PSHA384(const ASN1DERElement &im4p){
    std::array<char, SHA384_DIGEST_LENGTH> tmp{'\0'};
    std::string hash{tmp.begin(),tmp.end()};
    SHA384((unsigned char*)im4p.buf(), (unsigned int)im4p.size(), (unsigned char *)hash.c_str());
    return hash;
}

std::string tihmstar::img4tool::dgstNameForHash(const ASN1DERElement &im4m, std::string hash){
    assure(isIM4M(im4m));
    ASN1DERElement set = im4m[2];
    ASN1DERElement manbpriv = set[0];
    size_t privTagVal = 0;
    ASN1DERElement manb = parsePrivTag(manbpriv.buf(), manbpriv.size(), &privTagVal);
    assure(privTagVal == *(uint32_t*)"MANB");
    assure(manb[0].getStringValue() == "MANB");

    ASN1DERElement manbset = manb[1];

    for (auto &e : manbset) {
        size_t pTagVal = 0;
        ASN1DERElement me = parsePrivTag(e.buf(), e.size(), &pTagVal);
        if (pTagVal == *(uint32_t*)"MANP")
            continue;

        ASN1DERElement set = me[1];
        std::string dgstName = me[0].getStringValue();

        for (auto &se : set) {
            size_t pTagVal = 0;
            ASN1DERElement sel = parsePrivTag(se.buf(), se.size(), &pTagVal);
            switch (pTagVal) {
                case 'TSGD': //DGST
                {
                    std::string selDigest = sel[1].getStringValue();
                    if (selDigest == hash){
                        return dgstName;
                    }
                }
                    break;
                default:
                    break;
            }
        }
    }
    reterror("Hash not in IM4M");
}


bool tihmstar::img4tool::im4mContainsHash(const ASN1DERElement &im4m, std::string hash) noexcept{
    try {
        dgstNameForHash(im4m,hash);
        return true;
    } catch (...) {
        return false;
    }
}

bool tihmstar::img4tool::isGeneratorValidForIM4M(const ASN1DERElement &im4m, std::string generator) noexcept{
    try {
        ASN1DERElement bnch = getValFromIM4M(im4m,'BNCH');
        uint64_t gen = 0;

        sscanf(generator.c_str(), "0x%16llx", &gen);

        if (bnch.payloadSize() == SHA_DIGEST_LENGTH) {
            std::array<char, SHA_DIGEST_LENGTH> tmp{'\0'};
            std::string hash{tmp.begin(),tmp.end()};
            SHA1((unsigned char*)&gen, sizeof(gen), (unsigned char *)hash.c_str());
            return memcmp(hash.c_str(), bnch.payload(), bnch.payloadSize()) == 0;
        }else{
            std::array<char, SHA384_DIGEST_LENGTH> tmp{'\0'};
            std::string hash{tmp.begin(),tmp.end()};
            SHA384((unsigned char*)&gen, sizeof(gen), (unsigned char *)hash.c_str());
            return memcmp(hash.c_str(), bnch.payload(), bnch.payloadSize()) == 0;
        }
    } catch (...) {
        return false;
    }
}
#endif //HAVE_CRYPTO
#pragma mark end_needs_crypto


ASN1DERElement tihmstar::img4tool::getEmptyIM4PContainer(const char *type, const char *desc){
    ASN1DERElement im4p({ASN1DERElement::TagSEQUENCE, ASN1DERElement::Constructed, ASN1DERElement::Universal},NULL,0);
    ASN1DERElement im4p_str({ASN1DERElement::TagIA5String, ASN1DERElement::Primitive, ASN1DERElement::Universal},"IM4P",4);
    ASN1DERElement im4p_type({ASN1DERElement::TagIA5String, ASN1DERElement::Primitive, ASN1DERElement::Universal},type,strlen(type));
    ASN1DERElement im4p_desc({ASN1DERElement::TagIA5String, ASN1DERElement::Primitive, ASN1DERElement::Universal},desc,strlen(desc));

    retassure(im4p_type.payloadSize() == 4, "Type needs to be exactly 4 bytes long");

    im4p += im4p_str;
    im4p += im4p_type;
    im4p += im4p_desc;

    return im4p;
}

ASN1DERElement tihmstar::img4tool::getIM4RWithElements(std::map<std::string,tihmstar::Mem> elements){
    ASN1DERElement im4r({ASN1DERElement::TagSEQUENCE, ASN1DERElement::Constructed, ASN1DERElement::Universal},NULL,0);
    ASN1DERElement im4r_str({ASN1DERElement::TagIA5String, ASN1DERElement::Primitive, ASN1DERElement::Universal},"IM4R",4);
    im4r += im4r_str;
    
    ASN1DERElement set({ASN1DERElement::TagSET, ASN1DERElement::Constructed, ASN1DERElement::Universal},NULL,0);
    
    for (auto e : elements) {
        ASN1DERElement bnch_seq({ASN1DERElement::TagSEQUENCE, ASN1DERElement::Constructed, ASN1DERElement::Universal},NULL,0);
        ASN1DERElement bnch_str({ASN1DERElement::TagIA5String, ASN1DERElement::Primitive, ASN1DERElement::Universal},e.first.c_str(),4);
        ASN1DERElement bnch_payload({ASN1DERElement::TagOCTET, ASN1DERElement::Primitive, ASN1DERElement::Universal},e.second.data(),e.second.size());
        bnch_seq += bnch_str;
        bnch_seq += bnch_payload;
        ASN1DERElement bnch = genPrivTagForNumberWithPayload(htonl(*(uint32_t*)e.first.c_str()),bnch_seq);
        set += bnch;
    }
    
    im4r += set;
#ifdef DEBUG
    assure(isIM4R(im4r));
#endif
    return im4r;
}

ASN1DERElement tihmstar::img4tool::appendPayloadToIM4P(const ASN1DERElement &im4p, const void *buf, size_t size, const char *compression, const void *buf2Raw, size_t buf2RawSize){
    assure(im4p.tag().isConstructed);
    assure(im4p.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(im4p.tag().tagClass == ASN1DERElement::TagClass::Universal);

    retassure(im4p[0].getStringValue() == "IM4P", "Container is not a IM4P");
    retassure(im4p[1].getStringValue().size() == 4, "IM4P type has size != 4");
    retassure(im4p[2].getStringValue().size(), "IM4P description is empty");
    ASN1DERElement newim4p(im4p);
    
    ASN1DERElement im4p_payload({ASN1DERElement::TagOCTET, ASN1DERElement::Primitive, ASN1DERElement::Universal},buf,size);
    
    if (compression) {
        if (strcmp(compression, "complzss") == 0) {
            uint8_t *packed = NULL;
            cleanup([&]{
                safeFree(packed);
            });
            size_t packedSize = size + buf2RawSize;
            
            printf("Compression requested, compressing (%s): ", "complzss");
            packed = (uint8_t *)malloc(packedSize);
            
            packedSize = lzss_compress((const uint8_t *)buf, (uint32_t)size, packed, (uint32_t)packedSize);
            assure(packedSize < size);
            
            printf("ok\n");
            
            if (buf2Raw && buf2RawSize) {
                printf("Requested appending uncompressed buffer at the end!\n");
                //we optionally can append a buffer after compression
                packed = (uint8_t *)realloc(packed, packedSize + buf2RawSize);
                memcpy(&packed[packedSize], buf2Raw, buf2RawSize);
                packedSize += buf2RawSize;
            }
            
            im4p_payload = ASN1DERElement({ASN1DERElement::TagNumber::TagOCTET,ASN1DERElement::Primitive, ASN1DERElement::Universal}, packed, packedSize);
            
            newim4p += im4p_payload;
        } else if (strcmp(compression, "bvx2") == 0) {
            printf("Compression requested, compressing (%s): ", "bvx2");
#if defined(HAVE_LIBCOMPRESSION) || defined(HAVE_LIBLZFSE)
            uint8_t *packed = NULL;
            cleanup([&]{
                safeFree(packed);
            });
            size_t packedSize = size;
            packed = (uint8_t *)malloc(packedSize);

            packedSize = lzfse_encode_buffer(packed, packedSize, (const uint8_t *)buf, size, NULL);
            
            printf("ok\n");
            
            im4p_payload = ASN1DERElement({ASN1DERElement::TagNumber::TagOCTET,ASN1DERElement::Primitive, ASN1DERElement::Universal}, packed, packedSize);
            newim4p += im4p_payload;
            
            ASN1DERElement bvx2Info({ASN1DERElement::TagNumber::TagSEQUENCE,ASN1DERElement::Constructed, ASN1DERElement::Universal}, NULL, 0);
            {
                int one = 1;
                bvx2Info += ASN1DERElement({ASN1DERElement::TagNumber::TagINTEGER, ASN1DERElement::Universal}, &one, 1);
            }

            bvx2Info += ASN1DERElement::makeASN1Integer(size);
            newim4p += bvx2Info;
#else
            reterror("img4tool was build without bvx2 support");
#endif
        }else {
            reterror("unknown compression=%s",compression);
        }
    }else{
        newim4p += im4p_payload;
    }
    

    return newim4p;
}

bool tihmstar::img4tool::isIMG4(const ASN1DERElement &img4) noexcept{
    try{
        assure(img4.tag().isConstructed);
        assure(img4.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
        assure(img4.tag().tagClass == ASN1DERElement::TagClass::Universal);

        retassure(img4[0].getStringValue() == "IMG4", "Not an IMG4 file");
        return true;
    }catch (tihmstar::exception &e){
        //
    }
    return false;
}

bool tihmstar::img4tool::isIM4P(const ASN1DERElement &im4p) noexcept{
    try {
        assure(im4p.tag().isConstructed);
        assure(im4p.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
        assure(im4p.tag().tagClass == ASN1DERElement::TagClass::Universal);

        retassure(im4p[0].getStringValue() == "IM4P", "Container is not a IM4P");
        retassure(im4p[1].getStringValue().size() == 4, "IM4P type has size != 4");
        retassure(im4p[2].getStringValue().size(), "IM4P description is empty");

        ASN1DERElement payload = im4p[3];
        assure(!payload.tag().isConstructed);
        assure(payload.tag().tagNumber == ASN1DERElement::TagOCTET);
        assure(payload.tag().tagClass == ASN1DERElement::TagClass::Universal);

        return true;
    } catch (tihmstar::exception &e) {
        //
    }
    return false;
}

bool tihmstar::img4tool::isIM4M(const ASN1DERElement &im4m) noexcept{
    try {
        assure(im4m.tag().isConstructed);
        assure(im4m.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
        assure(im4m.tag().tagClass == ASN1DERElement::TagClass::Universal);

        retassure(im4m[0].getStringValue() == "IM4M", "Container is not a IM4M");
        retassure(im4m[1].getIntegerValue() == 0, "IM4M has weird version number");

        auto set = im4m[2];
        assure(set.tag().isConstructed);
        assure(set.tag().tagNumber == ASN1DERElement::TagSET);
        assure(set.tag().tagClass == ASN1DERElement::TagClass::Universal);

        auto octet = im4m[3];
        assure(!octet.tag().isConstructed);
        assure(octet.tag().tagNumber == ASN1DERElement::TagOCTET);
        assure(octet.tag().tagClass == ASN1DERElement::TagClass::Universal);

        auto seq = im4m[4];
        assure(seq.tag().isConstructed);
        assure(seq.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
        assure(seq.tag().tagClass == ASN1DERElement::TagClass::Universal);

        return true;
    } catch (tihmstar::exception &e) {
        //
    }
    return false;
}

bool tihmstar::img4tool::isIM4R(const ASN1DERElement &im4r) noexcept{
    try {
        assure(im4r.tag().isConstructed);
        assure(im4r.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
        assure(im4r.tag().tagClass == ASN1DERElement::TagClass::Universal);

        retassure(im4r[0].getStringValue() == "IM4R", "Container is not a IM4R");

        auto set = im4r[1];
        assure(set.tag().isConstructed);
        assure(set.tag().tagNumber == ASN1DERElement::TagSET);
        assure(set.tag().tagClass == ASN1DERElement::TagClass::Universal);
        return true;
    } catch (tihmstar::exception &e) {
        //
    }
    return false;
}

bool tihmstar::img4tool::isIM4C(const ASN1DERElement &im4c) noexcept{
    try {
        assure(im4c.tag().isConstructed);
        assure(im4c.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
        assure(im4c.tag().tagClass == ASN1DERElement::TagClass::Universal);

        retassure(im4c[0].getStringValue() == "IM4C", "Container is not a IM4C");

        auto set = im4c[2];
        assure(set.tag().isConstructed);
        assure(set.tag().tagNumber == ASN1DERElement::TagSET);
        assure(set.tag().tagClass == ASN1DERElement::TagClass::Universal);
        
        auto sig = im4c[3];
        assure(sig.tag().isConstructed == 0);
        assure(sig.tag().tagNumber == ASN1DERElement::TagOCTET);
        assure(sig.tag().tagClass == ASN1DERElement::TagClass::Universal);

        return true;
    } catch (tihmstar::exception &e) {
        //
    }
    return false;
}

ASN1DERElement tihmstar::img4tool::renameIM4P(const ASN1DERElement &im4p, const char *type){
    assure(isIM4P(im4p));
    retassure(strlen(type) == 4, "type has size != 4");
    ASN1DERElement newIm4p(im4p);

    uint8_t *ptr = (uint8_t*)newIm4p.payload();
    size_t size = newIm4p.payloadSize();
    {
        ASN1DERElement e0(ptr,size);
        retassure(e0.size()<=size, "im4p too small for e0");
        ptr += e0.size();
        size -= e0.size();
    }

    {
        ASN1DERElement e1(ptr,size);
        retassure(e1.taginfoSize()+4<=size, "im4p too small for e1");
        ptr += e1.taginfoSize();
    }

    memcpy(ptr,type,4);

    return newIm4p;
}

std::string tihmstar::img4tool::getDescFromIM4P(const ASN1DERElement &im4p){
    assure(isIM4P(im4p));
    auto descTag = im4p[2];
    assure(!descTag.tag().isConstructed);
    assure(descTag.tag().tagNumber == ASN1DERElement::TagIA5String);
    assure(descTag.tag().tagClass == ASN1DERElement::TagClass::Universal);
    return descTag.getStringValue();
}

bool tihmstar::img4tool::isIM4MSignatureValid(const ASN1DERElement &im4m){
#ifndef XCODE
    try {
#endif
        assure(isIM4M(im4m));
        ASN1DERElement data   = im4m[2];
        ASN1DERElement sig   = im4m[3];
        ASN1DERElement certelem = im4m[4][0];
        
//        if (sig.payloadSize() == 256 /*tested (A8)*/ || sig.payloadSize() == 512 /*untested*/)
        {
#ifndef HAVE_OPENSSL
            reterror("Compiled without openssl");
#else
            EVP_MD_CTX *mdctx = NULL;
            X509 *cert = NULL;
            EVP_PKEY *certpubkey = NULL;
            const unsigned char* certificate = NULL;
            bool useSHA384 = false;
            cleanup([&]{
                if(mdctx) EVP_MD_CTX_destroy(mdctx);
            });
            try {
                //bootAuthority is 0
                //tssAuthority is 1
                certelem = im4m[4][1];
            } catch (tihmstar::exception &e) {
                //however bootAuthority does not exist on iPhone7
                useSHA384 = true;
            }

            certificate = (const unsigned char*)certelem.buf();

            assure(mdctx = EVP_MD_CTX_create());
            assure(cert = d2i_X509(NULL, &certificate, certelem.size()));
            assure(certpubkey = X509_get_pubkey(cert));

            assure(EVP_DigestVerifyInit(mdctx, NULL, (useSHA384) ? EVP_sha384() : EVP_sha1(), NULL, certpubkey) == 1);

            assure(EVP_DigestVerifyUpdate(mdctx, data.buf(), data.size()) == 1);

            assure(EVP_DigestVerifyFinal(mdctx, (unsigned char*)sig.payload(), sig.payloadSize()) == 1);
#endif //HAVE_OPENSSL
        }
#ifndef XCODE
    } catch (tihmstar::exception &e) {
        printf("[IMG4TOOL] failed to verify IM4M signature with error:\n");
        e.dump();
        return false;
    }
#endif
    return true;
}

#pragma mark begin_needs_plist
#ifdef HAVE_PLIST
bool tihmstar::img4tool::doesIM4MBoardMatchBuildIdentity(const ASN1DERElement &im4m, plist_t buildIdentity) noexcept{
    plist_t ApBoardID = NULL;
    plist_t ApChipID = NULL;
    plist_t ApSecurityDomain = NULL;
    try{
        assure(isIM4M(im4m));

        assure(ApBoardID = plist_dict_get_item(buildIdentity, "ApBoardID"));
        assure(ApChipID = plist_dict_get_item(buildIdentity, "ApChipID"));
        assure(ApSecurityDomain = plist_dict_get_item(buildIdentity, "ApSecurityDomain"));

        assure(plist_get_node_type(ApBoardID) == PLIST_STRING);
        assure(plist_get_node_type(ApChipID) == PLIST_STRING);
        assure(plist_get_node_type(ApSecurityDomain) == PLIST_STRING);


        ASN1DERElement set = im4m[2];
        ASN1DERElement manbpriv = set[0];
        size_t privTagVal = 0;
        ASN1DERElement manb = parsePrivTag(manbpriv.buf(), manbpriv.size(), &privTagVal);
        assure(privTagVal == *(uint32_t*)"MANB");
        assure(manb[0].getStringValue() == "MANB");

        ASN1DERElement manbset = manb[1];

        ASN1DERElement manppriv = manbset[0];
        privTagVal = 0;
        ASN1DERElement manp = parsePrivTag(manppriv.buf(), manppriv.size(), &privTagVal);
        assure(privTagVal == *(uint32_t*)"MANP");
        assure(manp[0].getStringValue() == "MANP");

        ASN1DERElement manpset = manp[1];


        for (auto &e : manpset) {
            char *pstrval= NULL;
            uint64_t val = 0;
            size_t ptagVal = 0;
            plist_t currVal = NULL;
            cleanup([&]{
                safeFree(pstrval);
            });
            ASN1DERElement ptag = parsePrivTag(e.buf(), e.size(), &ptagVal);

            switch (ptagVal) {
                case 'DROB': //BORD
                    assure(ptag[0].getStringValue() == "BORD");
                    currVal = ApBoardID;ApBoardID = NULL;
                    break;
                case 'PIHC': //CHIP
                    assure(ptag[0].getStringValue() == "CHIP");
                    currVal = ApChipID;ApChipID = NULL;
                    break;
                case 'MODS': //SDOM
                    assure(ptag[0].getStringValue() == "SDOM");
                    currVal = ApSecurityDomain;ApSecurityDomain = NULL;
                    break;
                default:
                    continue;
            }

            plist_get_string_val(currVal, &pstrval);
            if (strncmp("0x", pstrval, 2) == 0){
                sscanf(pstrval, "0x%llx",&val);
            }else{
                sscanf(pstrval, "%lld",&val);
            }
            assure(ptag[1].getIntegerValue() == val);
        }
        //make sure we verified all 3 values we wanted to check
        assure(!ApBoardID && !ApChipID && !ApSecurityDomain);
    }catch (...){
        return false;
    }
    return true;
}

bool tihmstar::img4tool::im4mMatchesBuildIdentity(const ASN1DERElement &im4m, plist_t buildIdentity, std::vector<const char*> ignoreWhitelist) noexcept{
    plist_t manifest = NULL;
    try {
        bool checksPassed = true;
        std::string findDGST;
        if (ignoreWhitelist.size() == 1 && ignoreWhitelist[0][0] == '!') {
            checksPassed = false;
            findDGST = ignoreWhitelist[0]+1;
        }

        printf("[IMG4TOOL] checking buildidentity matches board ... ");
        if (!doesIM4MBoardMatchBuildIdentity(im4m, buildIdentity)) {
            printf("NO\n");
            return false;
        }
        printf("YES\n");

        printf("[IMG4TOOL] checking buildidentity has all required hashes:\n");
        ASN1DERElement set = im4m[2];
        ASN1DERElement manbpriv = set[0];
        size_t privTagVal = 0;
        ASN1DERElement manb = parsePrivTag(manbpriv.buf(), manbpriv.size(), &privTagVal);
        assure(privTagVal == *(uint32_t*)"MANB");
        assure(manb[0].getStringValue() == "MANB");

        ASN1DERElement manbset = manb[1];

        assure(manifest = plist_dict_get_item(buildIdentity, "Manifest"));
        assure(plist_get_node_type(manifest) == PLIST_DICT);

        plist_dict_iter melems = NULL;
        cleanup([&]{
            safeFree(melems);
        });
        plist_dict_new_iter(manifest, &melems);
        assure(melems);
        plist_t eVal = NULL;
        char *eKey = NULL;

        while (((void)plist_dict_next_item(manifest, melems, &eKey, &eVal),eVal)) {
            plist_t pInfo = NULL;
            plist_t pDigest = NULL;
            plist_t pTrusted = NULL;
            uint8_t isTrusted = 0;
            char *digest = NULL;
            uint64_t digestLen = 0;
            bool hasDigit = false;
            cleanup([&]{
                safeFree(digest);
            });

            int didprint = printf("[IMG4TOOL] checking hash for \"%s\"",eKey);
            while (didprint++< 55) {
                printf(" ");
            }

            assure(pInfo = plist_dict_get_item(eVal, "Info"));

            if ((pTrusted = plist_dict_get_item(eVal, "Trusted"))){
                assure(plist_get_node_type(pTrusted) == PLIST_BOOLEAN);
                plist_get_bool_val(pTrusted, &isTrusted);
                if (!isTrusted){
                    printf("OK (untrusted)\n");
                    continue;
                }
            }

            if (!(pDigest = plist_dict_get_item(eVal, "Digest"))) {
                printf("IGN (no digest in BuildManifest)\n");
                continue;
            }

            assure(plist_get_node_type(pDigest) == PLIST_DATA);
            plist_get_data_val(pDigest, &digest, &digestLen);


            for (auto &e : manbset) {
                size_t pTagVal = 0;
                ASN1DERElement me = parsePrivTag(e.buf(), e.size(), &pTagVal);
                if (pTagVal == *(uint32_t*)"MANP")
                    continue;

                ASN1DERElement set = me[1];

                for (auto &se : set) {
                    size_t pTagVal = 0;
                    ASN1DERElement sel = parsePrivTag(se.buf(), se.size(), &pTagVal);
                    switch (pTagVal) {
                        case 'TSGD': //DGST
                        {
                            std::string selDigest = sel[1].getStringValue();
                            if (selDigest.size() == digestLen && memcmp(selDigest.c_str(), digest, digestLen) == 0){
                                hasDigit = true;
                                if (findDGST == me[0].getStringValue()) {
                                    checksPassed = true;
                                }
                                printf("OK (found \"%s\" with matching hash)\n",me[0].getStringValue().c_str());
                                goto continue_plist;
                            }
                        }
                            break;
                        default:
                            break;
                    }
                }
            }
        continue_plist:
            if (!hasDigit) {
                if (!(ignoreWhitelist.size() == 1 && ignoreWhitelist[0][0] == '!')) {
                    for (auto &ignore : ignoreWhitelist) {
                        if (!strcmp(eKey, ignore)) {
                            hasDigit = true;
                            printf("BAD! (but ignoring due to whitelist)\n");
                            break;
                        }
                    }
                }
            }

            if (!hasDigit) {
                if (findDGST.size()) {
                    printf("IGN (hash not found in im4m, but ignoring since we only care about '%s')\n",findDGST.c_str());
                }else if (!pTrusted){
                    printf("IGN (hash not found in im4m, but ignoring since not explicitly enforced through \"Trusted\"=\"YES\" tag)\n");
                }else{
                    printf("BAD! (hash not found in im4m)\n");
                    checksPassed = false;
                }
            }
        }
        retassure(checksPassed, "verification failed!");
    } catch (tihmstar::exception &e) {
        printf("\nfailed verification with error:\n");
        e.dump();
        return false;
    }
    return true;
}

const plist_t tihmstar::img4tool::getBuildIdentityForIm4m(const ASN1DERElement &im4m, plist_t buildmanifest, std::vector<const char*> ignoreWhitelist){
    plist_t buildidentities = NULL;

    assure(buildmanifest);
    assure(buildidentities = plist_dict_get_item(buildmanifest, "BuildIdentities"));
    assure(plist_get_node_type(buildidentities) == PLIST_ARRAY);

    for (int i=0; i<plist_array_get_size(buildidentities); i++) {
        plist_t buildIdentity = NULL;

        printf("[IMG4TOOL] checking buildidentity %d:\n",i);
        assure(buildIdentity = plist_array_get_item(buildidentities, i));
        if (im4mMatchesBuildIdentity(im4m, buildIdentity, ignoreWhitelist)) {
            return buildIdentity;
        }
    }
    reterror("Failed to find matching buildidentity");
}

void tihmstar::img4tool::printGeneralBuildIdentityInformation(plist_t buildidentity){
    plist_t info = NULL;
    plist_dict_iter iter = NULL;
    cleanup([&]{
        safeFree(iter);
    });
    assure(info = plist_dict_get_item(buildidentity, "Info"));

    assure(((void)plist_dict_new_iter(info, &iter),iter));

    plist_t node = NULL;
    char *key = NULL;
    while ((void)plist_dict_next_item(info, iter, &key, &node),node) {
        char *str = NULL;
        cleanup([&]{
            safeFree(str);
        });
        plist_type t = PLIST_NONE;
        switch (t = plist_get_node_type(node)) {
            case PLIST_STRING:
                plist_get_string_val(node, &str);
                printf("%s : %s\n",key,str);
                break;
            case PLIST_BOOLEAN:
                plist_get_bool_val(node, (uint8_t*)&t);
                printf("%s : %s\n",key,((uint8_t)t) ? "YES" : "NO" );
            default:
                break;
        }
    }
}

bool tihmstar::img4tool::isValidIM4M(const ASN1DERElement &im4m, plist_t buildmanifest, std::string forDGSTName){
#ifndef XCODE
    try {
#endif
        
        if (!isIM4MSignatureValid(im4m)) {
            reterror("Signature verification of IM4M failed!\n");
        }
        printf("\n[IMG4TOOL] IM4M signature is verified by TssAuthority\n");

        if (buildmanifest) {
            plist_t buildIdentity = NULL;
            if (forDGSTName.size()) {
                forDGSTName.insert(0, "!");
                buildIdentity = getBuildIdentityForIm4m(im4m, buildmanifest, {forDGSTName.c_str()});
            }else{
                buildIdentity = getBuildIdentityForIm4m(im4m, buildmanifest);
            }

            printf("[IMG4TOOL] IM4M is valid for the given BuildManifest for the following restore:\n");
            printGeneralBuildIdentityInformation(buildIdentity);
        }
#ifndef XCODE
    } catch (tihmstar::exception &e) {
        printf("\n[IMG4TOOL] IM4M validation failed with error:\n");
        e.dump();
        return false;
    }
#endif

    return true;
}

plist_t tihmstar::img4tool::getSHSH2FromIM4M(const ASN1DERElement &im4m){
    plist_t newshsh = NULL;
    plist_t generator = NULL;
    plist_t data = NULL;
    cleanup([&]{
        safeFreeCustom(newshsh,plist_free);
        safeFreeCustom(data,plist_free);
        safeFreeCustom(generator,plist_free);
    });
    ASN1DERElement real_im4m = im4m;
    
    if (isIMG4(real_im4m)) {
        char *generatorStr = NULL;
        cleanup([&]{
            safeFree(generatorStr);
        });
        ASN1DERElement im4r = getIM4RFromIMG4(real_im4m);
        ASN1DERElement bncn = getBNCNFromIM4R(im4r);
        
        size_t generatorStrSize = bncn.payloadSize()*2+2+1;
        generatorStr = (char*)malloc(generatorStrSize);
        strcpy(generatorStr, "0x");
        std::string octetString = bncn.getStringValue();
        std::reverse(octetString.begin(), octetString.end());
        for (char c : octetString) {
            assure(generatorStrSize-strlen(generatorStr)>=3);
            snprintf(&generatorStr[strlen(generatorStr)], 3, "%02x",(unsigned char)c);
        }
        assure(generator = plist_new_string(generatorStr));
        
        real_im4m = getIM4MFromIMG4(real_im4m);
    }
    
    retassure(isIM4M(real_im4m), "Not IM4M file");

    retassure(newshsh = plist_new_dict(),"failed to create new plist dict");
    retassure(data = plist_new_data((const char*)im4m.buf(), im4m.size()),"failed to create plist data from im4m buf");

    plist_dict_set_item(newshsh, "ApImg4Ticket", data); data = NULL;
    if (generator) {
        plist_dict_set_item(newshsh, "generator", generator); generator = NULL;
    }

    {
        plist_t rt = newshsh; newshsh = NULL;
        return rt;
    }
}

#endif //HAVE_PLIST
#pragma mark end_needs_plist
