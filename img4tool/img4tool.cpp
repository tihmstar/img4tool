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
    for (auto kbtag : sequence) {
        assure(kbtag.tag().isConstructed);
        assure(kbtag.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
        assure(kbtag.tag().tagClass == ASN1DERElement::TagClass::Universal);
        int i=-1;
        for (auto elem : kbtag) {
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
        for (auto tag : sequence) {
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
                        for (auto selem : tag) {
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
        for (auto tag : sequence) {
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

                    for (auto elem : tag) {
                        size_t privElem = 0;
                        ASN1DERElement subsequence = parsePrivTag(elem.buf(), size-(size_t)((uint8_t*)elem.buf()-(uint8_t*)buf), &privElem);
                        putStr((char*)&privElem,4);
                        
                        assure(subsequence.tag().isConstructed);
                        assure(subsequence.tag().tagNumber == ASN1DERElement::TagSEQUENCE);
                        assure(subsequence.tag().tagClass == ASN1DERElement::TagClass::Universal);
                        
                        for (auto subelem : subsequence) {
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

    for (auto elem : sequence){
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
        for (auto tag : sequence) {
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
        for (auto tag : sequence) {
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
        for (auto tag : sequence) {
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
