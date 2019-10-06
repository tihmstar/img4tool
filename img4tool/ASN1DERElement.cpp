//
//  ASN1DER.cpp
//  img4tool
//
//  Created by tihmstar on 04.10.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include "ASN1DERElement.hpp"
#include "img4tool/libgeneral/macros.h"

using namespace tihmstar::img4tool;

#pragma mark ASN1DERElementIterator

ASN1DERElement::ASN1DERElementIterator::ASN1DERElementIterator(const ASN1DERElement::ASN1TAG *buf, size_t containerSize, uint64_t pos) :
    _buf(buf),
    _containerSize(containerSize),
    _pos(pos)
{
    //
}

ASN1DERElement::ASN1DERElementIterator &ASN1DERElement::ASN1DERElementIterator::operator++(){
    ASN1DERElement e(_buf+_pos,_containerSize-_pos);
    _pos = (uint64_t)e.buf() + e.size() - (uint64_t)_buf;
    assure(_pos<=_containerSize);
    return *this;
}

bool ASN1DERElement::ASN1DERElementIterator::operator!=(const ASN1DERElementIterator &e){
    return (_buf != e._buf || _pos != e._pos || _containerSize != e._containerSize);
}

const ASN1DERElement ASN1DERElement::ASN1DERElementIterator::operator*() const{
    return {_buf+_pos,_containerSize-_pos};
}

#pragma mark ASN1DERElement

ASN1DERElement::ASN1DERElement(const void *buf, size_t bufSize) :
    _buf((const ASN1TAG*)buf),
    _bufSize(bufSize),
    _ownsBuffer(false)
{

    assure(_bufSize > 2); //needs at least TAG and Size
    if (((uint8_t*)_buf)[0] != 0xff) {
        assure(_buf->tagNumber <= TagBMPString);
    }
    assure(_bufSize >= size());
}

ASN1DERElement::~ASN1DERElement(){
    if (_ownsBuffer) {
        void *freeme = (void*)_buf;_buf = NULL;
        safeFree(freeme);
    }
}

size_t ASN1DERElement::taginfoSize(){
    size_t tagInfoSize = 0;
    if (((uint8_t*)_buf)[0] == 0xff){
        ASN1PrivateTag *ptag = ((ASN1PrivateTag *)_buf)+1;
        do {
            assure(_bufSize >= 2 + (++tagInfoSize));
        }while (ptag++->more);
    }
    
    ASN1Len *tlen = (ASN1Len *)&_buf[1+tagInfoSize];
    return ((!tlen->isLong) ? 2 : 2+tlen->len) + tagInfoSize;
}

size_t ASN1DERElement::payloadSize(){
    size_t tagInfoSize = 0;
    if (((uint8_t*)_buf)[0] == 0xff){
        ASN1PrivateTag *ptag = ((ASN1PrivateTag *)_buf)+1;
        do {
            assure(_bufSize >= 2 + (++tagInfoSize));
        }while (ptag++->more);
    }

    size_t rt = 0;
    ASN1Len *tlen = (ASN1Len *)&_buf[1+tagInfoSize];
    if (!tlen->isLong)
        return tlen->len;
    
    assure(tlen->len <= sizeof(size_t)); //can't hold more than size_t
    assure(_bufSize > 2 + tagInfoSize + tlen->len); //len bytes shouldn't be outside of buffer
    
    for (uint8_t sizebits = 0; sizebits < tlen->len; sizebits++) {
        rt <<= 8;
        rt |= ((uint8_t*)_buf)[2+tagInfoSize+sizebits];
    }
    
    return rt;
}

size_t ASN1DERElement::size(){
    return taginfoSize() + payloadSize();
}


const void *ASN1DERElement::buf(){
    return _buf;
}

const void *ASN1DERElement::payload(){
    return ((uint8_t*)_buf)+taginfoSize();
}


ASN1DERElement::ASN1TAG ASN1DERElement::tag(){
    return *(ASN1TAG*)&_buf[0];
}

std::string ASN1DERElement::getStringValue(){
    assure(((uint8_t*)_buf)[0] != 0xff);
    assure(_buf->tagNumber == TagNumber::TagIA5String || _buf->tagNumber == TagNumber::TagOCTET);

    return {(char*)payload(),payloadSize()};
}

uint64_t ASN1DERElement::getIntegerValue(){
    uint64_t rt = 0;
    assure(_buf->tagNumber == TagNumber::TagINTEGER || _buf->tagNumber == TagNumber::TagBOOLEAN);
    assure(payloadSize() <= sizeof(uint64_t));
    for (uint8_t sizebits = 0; sizebits < payloadSize(); sizebits++) {
        rt <<= 8;
        rt |= ((uint8_t*)payload())[sizebits];
    }
    return rt;
}

void ASN1DERElement::print(){
    switch (tag().tagNumber) {
        case TagIA5String:
            printf("%s",getStringValue().c_str());
            break;
        case TagOCTET:
        {
            std::string s = getStringValue();
            for (int i=0; i<s.size(); i++) {
                printf("%02x",((uint8_t*)s.c_str())[i]);
            }
            break;
        }
        case TagINTEGER:
            printf("%llu",getIntegerValue());
            break;
        case TagBOOLEAN:
            printf("%s",getIntegerValue() == 0 ? "false" : "true");
            break;
        default:
            reterror("unimplemented ASN1DERElement::print() for type=%d",tag().tagNumber);
            break;
    }
}


ASN1DERElement ASN1DERElement::operator[](uint32_t i){
    assure(_buf->isConstructed);
    ASN1DERElement rt(_buf,_bufSize);
    
    do{
        size_t size = _bufSize - (size_t)((uint8_t*)rt.payload() - (uint8_t*)_buf);
        rt = ASN1DERElement(rt.payload(), size);
    } while (i-->0);
    
    return rt;
}

ASN1DERElement::ASN1DERElementIterator ASN1DERElement::begin(){
    return {(const ASN1TAG *)payload(),payloadSize(),0};
}

ASN1DERElement::ASN1DERElementIterator ASN1DERElement::end(){
    return {(const ASN1TAG *)payload(),payloadSize(),payloadSize()};
}
