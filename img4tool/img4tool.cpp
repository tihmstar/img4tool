//
//  img4tool.cpp
//  img4tool
//
//  Created by tihmstar on 04.10.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "img4tool.hpp"
#include <stdio.h>
#include <string.h>
#include <array>
#include <arpa/inet.h>
#include "ASN1DERElement.hpp"
#include <libgeneral/macros.h>
extern "C"{
#include "lzssdec.h"
};

#if defined(HAVE_LIBCOMPRESSION)
#   include <compression.h>
#   define lzfse_decode_buffer(dst, dst_size, src, src_size, scratch) \
        compression_decode_buffer(dst, dst_size, src, src_size, scratch, COMPRESSION_LZFSE)
#elif defined(HAVE_LIBLZFSE)
#   include <lzfse.h>
#else
#error Either libcompression or liblzfse is needed!
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

#define putStr(s,l) printf("%.*s",(int)l,s)

namespace tihmstar {
    namespace img4tool {
        void printKBAG(const void *buf, size_t size);
        void printMANB(const void *buf, size_t size, bool printAll);
        void printMANP(const void *buf, size_t size);

        void printRecSequence(const void *buf, size_t size);

        ASN1DERElement parsePrivTag(const void *buf, size_t size, size_t *outPrivTag);
        ASN1DERElement uncompressIfNeeded(const ASN1DERElement &compressedOctet, const ASN1DERElement &origIM4P, const char **outUsedCompression = NULL, const char **outHypervisor = NULL, size_t *outHypervisorSize = NULL);
    };
};

#pragma mark private

void tihmstar::img4tool::printKBAG(const void *buf, size_t size){
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

void tihmstar::img4tool::printMANB(const void *buf, size_t size, bool printAll){
    size_t privTag = 0;
    ASN1DERElement sequence = parsePrivTag(buf, size, &privTag);
    assure(privTag == *(uint32_t*)"MANB");
    assure(sequence.tag().isConstructed);
    assure(sequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(sequence.tag().tagClass == ASN1DERElement::TagClass::Universal);

    putStr((char*)&privTag,4);

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

                    printMANP(tag.payload(), tag.payloadSize());
                    printf("\n");

                    if (printAll) {
                        int j = -1;
                        for (auto &selem : tag) {
                            if (++j == 0)
                                continue;

                            size_t privElem = 0;
                            ASN1DERElement subsequence = parsePrivTag(selem.buf(), size-(size_t)((uint8_t*)selem.buf()-(uint8_t*)buf), &privElem);
                            putStr((char*)&privElem,4);
                            printf(": ");
                            printRecSequence(subsequence.buf(), subsequence.size());
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

void tihmstar::img4tool::printMANP(const void *buf, size_t size){
    size_t privTag = 0;
    ASN1DERElement sequence = parsePrivTag(buf, size, &privTag);
    assure(privTag == *(uint32_t*)"MANP");
    assure(sequence.tag().isConstructed);
    assure(sequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(sequence.tag().tagClass == ASN1DERElement::TagClass::Universal);

    putStr((char*)&privTag,4);

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
                        size_t privElem = 0;
                        ASN1DERElement subsequence = parsePrivTag(elem.buf(), size-(size_t)((uint8_t*)elem.buf()-(uint8_t*)buf), &privElem);
                        putStr((char*)&privElem,4);

                        assure(subsequence.tag().isConstructed);
                        assure(subsequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
                        assure(subsequence.tag().tagClass == ASN1DERElement::TagClass::Universal);

                        for (auto &subelem : subsequence) {
                            printf(": ");
                            subelem.print();
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

void tihmstar::img4tool::printRecSequence(const void *buf, size_t size){
    ASN1DERElement sequence(buf, size);

    assure(sequence.tag().isConstructed);

    for (auto &elem : sequence){
        if (*(uint8_t*)elem.buf() == (uint8_t)ASN1DERElement::TagPrivate){
            size_t privTag = 0;
            ASN1DERElement sequence = parsePrivTag(elem.buf(), elem.size(), &privTag);
            printf("\n");
            putStr((char*)&privTag, 4);
            printf(": ");
            printRecSequence(sequence.buf(), sequence.size());
        }else if (elem.tag().isConstructed) {
            printRecSequence(elem.buf(), elem.size());
            printf("\n\n");
        }else{
            elem.print();
            if (elem.tag().tagNumber == ASN1DERElement::TagIA5String) {
                printf(": ");
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

    assure(size >= taginfoSize);
    return {(uint8_t*)buf+taginfoSize,size-taginfoSize};
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

                        ASN1DERElement bncn = getBNCNFromIM4R({tag.payload(), tag.payloadSize()});
                        std::string octetString = bncn.getStringValue();
                        std::reverse(octetString.begin(), octetString.end());
                        printf("BNCN: 0x");
                        for (int i=0; i<octetString.size(); i++) {
                            printf("%02x",((uint8_t*)octetString.c_str())[i]);
                        }
                        printf("\n\n");
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
                    printf("desc: %s\n",tag.getStringValue().c_str());
                    break;
                case 3:
                    assure(!tag.tag().isConstructed);
                    assure(tag.tag().tagNumber == ASN1DERElement::TagOCTET);
                    assure(tag.tag().tagClass == ASN1DERElement::TagClass::Universal);
                    printf("size: 0x%08lx\n\n",tag.payloadSize());
                    break;
                case 4:
                    printKBAG(tag.buf(),tag.size());
                    printf("\n");
                    break;
                case 5:
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
                    break;
                default:
                    reterror("[%s] unexpected element at SEQUENCE index %d",__FUNCTION__,i);
                    break;
            }
        }
        if (i<4) {
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
                    printMANB(tag.payload(), tag.payloadSize(), printAll);
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

ASN1DERElement tihmstar::img4tool::getBNCNFromIM4R(const ASN1DERElement &im4r){
    assure(isIM4R(im4r));
    
    ASN1DERElement set = im4r[1];
    ASN1DERElement bncnTag = set[0];
    size_t ptagVal = 0;
    ASN1DERElement ptag = parsePrivTag(bncnTag.buf(), bncnTag.size(), &ptagVal);
    ASN1DERElement octet = ptag[1];
    
    //convert big endian to little endian
    std::string octetString{(char*)octet.payload(),octet.payloadSize()};
    
    ASN1DERElement retval({ASN1DERElement::TagOCTET, ASN1DERElement::Primitive, ASN1DERElement::Universal},octetString.c_str(),octetString.size());
    return retval;
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

ASN1DERElement tihmstar::img4tool::uncompressIfNeeded(const ASN1DERElement &compressedOctet, const ASN1DERElement &origIM4P, const char **outUsedCompression, const char **outHypervisor, size_t *outHypervisorSize){
    const char *payload = (const char *)compressedOctet.payload();
    size_t payloadSize = compressedOctet.size();
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
        size_t uncompSizeReal = 0;
        printf("Compression detected, uncompressing (%s): ", "bvx2");
        //checking
        ASN1DERElement compressingSequence = origIM4P[5];
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
    }

    return retVal;
}

ASN1DERElement tihmstar::img4tool::getPayloadFromIM4P(const ASN1DERElement &im4p, const char *decryptIv, const char *decryptKey, const char **outUsedCompression, const char **outHypervisor, size_t *outHypervisorSize){
    assure(isIM4P(im4p));
    ASN1DERElement payload = im4p[3];
    if (decryptIv || decryptKey) {
#ifdef HAVE_CRYPTO
        payload = decryptPayload(payload, decryptIv, decryptKey);
#else
        reterror("decryption keys were provided, but img4tool was compiled without crypto backend!");
#endif //HAVE_CRYPTO
    }

    return uncompressIfNeeded(payload, im4p, outUsedCompression, outHypervisor, outHypervisorSize);
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

    reterror("failed to find nonce!");
    return {0,0};
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
            size_t packedSize = size + 0x800;
            
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
        } else if (strcmp(compression, "bvx2") == 0) {
            reterror("not implemented");
        }else {
            reterror("unknown compression=%s",compression);
        }
    }
    
    newim4p += im4p_payload;

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

        ASN1DERElement bncnTag = set[0];
        
        size_t ptagVal = 0;
        ASN1DERElement ptag = parsePrivTag(bncnTag.buf(), bncnTag.size(), &ptagVal);
        assure(ptagVal == htonl('BNCN'));
        assure(*(uint32_t*)ptag[0].getStringValue().c_str() == htonl('BNCN'));
        ASN1DERElement octet = ptag[1];
        assure(octet.tag().isConstructed == ASN1DERElement::Primitive);
        assure(octet.tag().tagNumber == ASN1DERElement::TagOCTET);
        assure(octet.tag().tagClass == ASN1DERElement::TagClass::Universal);

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

    memcpy((void*)newIm4p[1].payload(),type,4);

    return newIm4p;
}

#pragma mark begin_needs_openssl
#ifdef HAVE_OPENSSL
bool tihmstar::img4tool::isIM4MSignatureValid(const ASN1DERElement &im4m){

    EVP_MD_CTX *mdctx = NULL;
    X509 *cert = NULL;
    EVP_PKEY *certpubkey = NULL;
    const unsigned char* certificate = NULL;
    bool useSHA384 = false;
    cleanup([&]{
        if(mdctx) EVP_MD_CTX_destroy(mdctx);
    });

    try {
        assure(isIM4M(im4m));
        ASN1DERElement data   = im4m[2];
        ASN1DERElement sig   = im4m[3];
        ASN1DERElement certelem = im4m[4][0];
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
    } catch (tihmstar::exception &e) {
        printf("[IMG4TOOL] failed to verify IM4M signature with error:\n");
        e.dump();
        return false;
    }
    return true;
}
#endif //HAVE_OPENSSL
#pragma mark end_needs_openssl


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
            if ((pTrusted = plist_dict_get_item(pInfo, "Trusted"))){
                assure(plist_get_node_type(pTrusted) == PLIST_BOOLEAN);
                plist_get_bool_val(pTrusted, &isTrusted);
                if (!pTrusted){
                    printf("OK (untrusted)\n");
                    continue;
                }
            }
            
            {
                if (!strncmp(eKey, "Savage,",strlen("Savage,"))) {
                    printf("IGN (custom ignore: Savage)\n");
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
    try {
        plist_t buildIdentity = NULL;
        if (forDGSTName.size()) {
            forDGSTName.insert(0, "!");
            buildIdentity = getBuildIdentityForIm4m(im4m, buildmanifest, {forDGSTName.c_str()});
        }else{
            buildIdentity = getBuildIdentityForIm4m(im4m, buildmanifest);
        }

#ifdef HAVE_OPENSSL
        if (!isIM4MSignatureValid(im4m)) {
            reterror("Signature verification of IM4M failed!\n");
        }
        printf("\n[IMG4TOOL] IM4M signature is verified by TssAuthority\n");
#else
        printf("[WARNING] COMPILED WITHOUT OPENSSL: can not im4m signature!\n");
#endif //HAVE_OPENSSL

        printf("[IMG4TOOL] IM4M is valid for the given BuildManifest for the following restore:\n");
        printGeneralBuildIdentityInformation(buildIdentity);
    } catch (tihmstar::exception &e) {
        printf("\n[IMG4TOOL] IM4M validation failed with error:\n");
        e.dump();
        return false;
    }

    return true;
}
#endif //HAVE_PLIST
#pragma mark end_needs_plist
