//
//  img4tool.cpp
//  img4tool
//
//  Created by tihmstar on 04.10.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include <stdio.h>
#include <arpa/inet.h>
#include "img4tool.hpp"
#include "img4tool/libgeneral/macros.h"
#include "ASN1DERElement.hpp"

#ifdef __APPLE__
#   include <CommonCrypto/CommonCrypto.h>
#else
#   include <openssl/aes.h>
#endif // __APPLE__

using namespace tihmstar::img4tool;

#define putStr(s,l) printf("%.*s",(int)l,s)

namespace tihmstar {
    namespace img4tool {
        void printKBAG(const void *buf, size_t size);
        void printMANB(const void *buf, size_t size, bool printAll);
        void printMANP(const void *buf, size_t size);

        void printRecSequence(const void *buf, size_t size);
        
        ASN1DERElement parsePrivTag(const void *buf, size_t size, size_t *outPrivTag);
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
#warning TODO we don't handle IM4R yet
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
                        assure(tag.tag().tagNumber == ASN1DERElement::TagEnd_of_Content);
                        assure(tag.tag().tagClass == ASN1DERElement::TagClass::ContextSpecific);

                        printIM4M(tag.payload(), tag.payloadSize(), printAll);
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

ASN1DERElement tihmstar::img4tool::getIM4PFromIMG4(const void *buf, size_t size){
    ASN1DERElement img4(buf,size);
    assure(isValidIMG4(img4));
    
    ASN1DERElement im4p = img4[1];
    assure(isValidIM4P(im4p));

    return im4p;
}

ASN1DERElement tihmstar::img4tool::getIM4MFromIMG4(const void *buf, size_t size){
    ASN1DERElement img4(buf,size);
    
    assure(isValidIMG4(img4));
    
    ASN1DERElement container = img4[2];
    
    assure(container.tag().isConstructed);
    assure(container.tag().tagNumber == ASN1DERElement::TagEnd_of_Content);
    assure(container.tag().tagClass == ASN1DERElement::TagClass::ContextSpecific);

    ASN1DERElement im4m = container[0];

    assure(im4m.tag().isConstructed);
    assure(im4m.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(im4m.tag().tagClass == ASN1DERElement::TagClass::Universal);
    
    retassure(im4m[0].getStringValue() == "IM4M", "Container is not a IM4M");

    return im4m;
}

ASN1DERElement tihmstar::img4tool::getEmptyIMG4Container(){
    ASN1DERElement img4({ASN1DERElement::TagSEQUENCE, ASN1DERElement::Contructed, ASN1DERElement::Universal},NULL,0);
    ASN1DERElement img4_str({ASN1DERElement::TagIA5String, ASN1DERElement::Primitive, ASN1DERElement::Universal},"IMG4",4);
    img4 += img4_str;
    
    return img4;
}

ASN1DERElement tihmstar::img4tool::appendIM4PToIMG4(const ASN1DERElement img4, const ASN1DERElement im4p){
    assure(isValidIMG4(img4));
    assure(isValidIM4P(im4p));

    ASN1DERElement newImg4(img4);
    
    newImg4 += im4p;
    
    return newImg4;
}

ASN1DERElement tihmstar::img4tool::appendIM4MToIMG4(const ASN1DERElement img4, const ASN1DERElement im4m){
    assure(isValidIMG4(img4));
    
    assure(im4m.tag().isConstructed);
    assure(im4m.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
    assure(im4m.tag().tagClass == ASN1DERElement::TagClass::Universal);
    
    retassure(im4m[0].getStringValue() == "IM4M", "Container is not a IM4P");
    
    ASN1DERElement newImg4(img4);
    
    ASN1DERElement container({ASN1DERElement::TagEnd_of_Content, ASN1DERElement::Contructed, ASN1DERElement::ContextSpecific},NULL,0);
    
    container += im4m;
    
    newImg4 += container;
    
    return newImg4;
}

ASN1DERElement tihmstar::img4tool::getPayloadFromIM4P(const ASN1DERElement im4p, const char *decryptIv, const char *decryptKey){
    assure(isValidIM4P(im4p));
    ASN1DERElement payload = im4p[3];
    return (decryptIv || decryptKey) ? decryptPayload(payload, decryptIv, decryptKey) : payload;
}

ASN1DERElement tihmstar::img4tool::decryptPayload(const ASN1DERElement payload, const char *decryptIv, const char *decryptKey){
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

    
#ifdef __APPLE__
    retassure(CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0, key, sizeof(key), iv, decPayload.payload(), decPayload.payloadSize(), (void*)decPayload.payload(), decPayload.payloadSize(), NULL) == kCCSuccess,
           "Decryption failed!");
#else
    AES_KEY decKey = {};
    retassure(!AES_set_decrypt_key(key, sizeof(key)*8, &decKey), "Failed to set decryption key");
    AES_cbc_encrypt((const unsigned char*)decPayload.payload(), (unsigned char*)decPayload.payload(), decPayload.payloadSize(), &decKey, iv, AES_DECRYPT);
#endif
    
    return decPayload;
}

ASN1DERElement tihmstar::img4tool::getEmptyIM4PContainer(const char *type, const char *desc){
    ASN1DERElement im4p({ASN1DERElement::TagSEQUENCE, ASN1DERElement::Contructed, ASN1DERElement::Universal},NULL,0);
    ASN1DERElement im4p_str({ASN1DERElement::TagIA5String, ASN1DERElement::Primitive, ASN1DERElement::Universal},"IM4P",4);
    ASN1DERElement im4p_type({ASN1DERElement::TagIA5String, ASN1DERElement::Primitive, ASN1DERElement::Universal},type,strlen(type));
    ASN1DERElement im4p_desc({ASN1DERElement::TagIA5String, ASN1DERElement::Primitive, ASN1DERElement::Universal},desc,strlen(desc));

    retassure(im4p_type.payloadSize() == 4, "Type needs to be exactly 4 bytes long");
    
    im4p += im4p_str;
    im4p += im4p_type;
    im4p += im4p_desc;

    return im4p;
}

ASN1DERElement tihmstar::img4tool::appendPayloadToIM4P(const ASN1DERElement im4p, const void *buf, size_t size){
    assure(isValidIM4P(im4p));
    ASN1DERElement newim4p(im4p);

    ASN1DERElement im4p_payload({ASN1DERElement::TagOCTET, ASN1DERElement::Primitive, ASN1DERElement::Universal},buf,size);

    newim4p += im4p_payload;
    
    return newim4p;
}

bool tihmstar::img4tool::isValidIMG4(const ASN1DERElement img4){
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

bool tihmstar::img4tool::isValidIM4P(const ASN1DERElement im4p){
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

ASN1DERElement tihmstar::img4tool::renameIM4P(const ASN1DERElement im4p, const char *type){
    assure(isValidIM4P(im4p));
    retassure(strlen(type) == 4, "type has size != 4");
    ASN1DERElement newIm4p(im4p);

    memcpy((void*)newIm4p[1].payload(),type,4);
    
    return newIm4p;
}
