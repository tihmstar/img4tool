//
//  ASN1DER.cpp
//  img4tool
//
//  Created by tihmstar on 04.10.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include <algorithm>
#include "../include/img4tool/ASN1DERElement.hpp"
#include <libgeneral/macros.h>
#include <string.h>

using namespace tihmstar::img4tool;

#pragma mark helper
#define putStr(s,l) printf("%.*s",(int)l,s)


std::string ASN1DERElement::makeASN1Size(size_t size){
    assure(size < 0x100000000);
    if (size >= 0x1000000) {
        // 1+4 bytes length
        return {{(char)0x84,(char)((size >> 24) & 0xFF),(char)((size >> 16) & 0xFF),(char)((size >> 8) & 0xFF),(char)(size & 0xFF)}};
    } else if (size >= 0x10000) {
        // 1+3 bytes length
        return {{(char)0x83,(char)((size >> 16) & 0xFF),(char)((size >> 8) & 0xFF),(char)(size & 0xFF)}};
    } else if (size >= 0x100) {
        // 1+2 bytes length
        return {{(char)0x82,(char)((size >> 8) & 0xFF),(char)(size & 0xFF)}};
    } else if (size >= 0x80) {
        // 1+1 byte length
        return {{(char)0x81,(char)(size & 0xFF)}};
    } else {
        // 1 byte length
        return {(char)(size & 0xFF)};
    }
}

ASN1DERElement ASN1DERElement::makeASN1Integer(uint64_t num){
    uint64_t bigEndian = num;
    int bytes = 0;
        
    while (num) {
        bigEndian <<=8;
        bigEndian |= num & 0xff;
        num >>=8;
        bytes++;
    }
    
    return ASN1DERElement({ASN1DERElement::TagNumber::TagINTEGER, ASN1DERElement::Universal}, &bigEndian, bytes);
}

#pragma mark ASN1DERElementIterator

ASN1DERElement::ASN1DERElementIterator::ASN1DERElementIterator(const ASN1DERElement::ASN1TAG *buf, size_t containerSize, size_t pos) :
    _buf(buf),
    _containerSize(containerSize),
    _pos(pos)
{
    //
}

ASN1DERElement::ASN1DERElementIterator &ASN1DERElement::ASN1DERElementIterator::operator++(){
    ASN1DERElement e(_buf+_pos,_containerSize-_pos);
    _pos += e.size();
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

ASN1DERElement::ASN1DERElement() :
    _buf(NULL),
    _bufSize(0),
    _ownsBuffer(true)
{
    constexpr const ASN1TAG tag{img4tool::ASN1DERElement::TagNULL,img4tool::ASN1DERElement::Primitive,img4tool::ASN1DERElement::Universal};
    std::string size = makeASN1Size(0);
    assure(_buf = (const ASN1TAG *)malloc(_bufSize = 1+size.size()));

    memcpy((void*)&_buf[0], &tag, 1);
    memcpy((void*)&_buf[1], size.c_str(), size.size());
}

ASN1DERElement::ASN1DERElement(const void *buf, size_t bufSize, bool ownsBuffer) :
    _buf(NULL),
    _bufSize(0),
    _ownsBuffer(true)
{
    if (ownsBuffer) {
        _buf = (const ASN1TAG*)buf;
        _bufSize = bufSize;
    }else{
        //if we don't get the ownershipt of the buffer transfered to us, we have to make a copy!
        _buf = (ASN1TAG*)malloc(_bufSize = bufSize);
        memcpy((void*)_buf, buf, _bufSize);
    }

    assure(_bufSize >= 2); //needs at least TAG and Size
    if (((uint8_t*)_buf)[0] != 0xff) {
        assure(_buf->tagNumber <= TagBMPString);
    }
    assure(_bufSize >= size());
}

ASN1DERElement::ASN1DERElement(const ASN1TAG tag, const void *payload, size_t payloadLen) :
    _buf(NULL),
    _bufSize(0),
    _ownsBuffer(true)
{
    std::string size = makeASN1Size(payloadLen);
    assure(_buf = (const ASN1TAG *)malloc(_bufSize = 1+payloadLen+size.size()));

    memcpy((void*)&_buf[0], &tag, 1);
    memcpy((void*)&_buf[1], size.c_str(), size.size());
    if (payloadLen) {
        memcpy((void*)&_buf[1+size.size()], payload, payloadLen);
    }
}

ASN1DERElement::ASN1DERElement(ASN1DERElement &&old){
    void *buf = NULL;
    cleanup([&]{
        safeFree(buf);
    });
    if (_ownsBuffer){
        buf = (void*)_buf; _buf = NULL;
    }
    if (old._ownsBuffer) {
        _buf = old._buf;
        _bufSize = old._bufSize;
        _ownsBuffer = old._ownsBuffer; old._ownsBuffer = false;
    }else{
        /*
         if the old object doesn't own the buffer, we have to perform a copy!
         Otherwise there is no guarantee that the buffer will stay valid
         */
        _bufSize = old._bufSize;
        _ownsBuffer = true;
        _buf = (ASN1TAG*)malloc(_bufSize);
        memcpy((void*)&_buf[0], old._buf, _bufSize);
    }
}

ASN1DERElement::ASN1DERElement(const ASN1DERElement &old) :
    _buf(NULL),
    _bufSize(old._bufSize),
    _ownsBuffer(true)
{
    _buf = (ASN1TAG*)malloc(_bufSize);
    memcpy((void*)&_buf[0], old._buf, _bufSize);
}


ASN1DERElement::~ASN1DERElement(){
    if (_ownsBuffer) {
        safeFreeConst(_buf);
    }
}

size_t ASN1DERElement::taginfoSize() const{
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

size_t ASN1DERElement::payloadSize() const{
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

size_t ASN1DERElement::size() const{
    return taginfoSize() + payloadSize();
}

bool ASN1DERElement::ownsBuffer() const{
   return _ownsBuffer;
}


const void *ASN1DERElement::buf() const{
    return _buf;
}

const void *ASN1DERElement::payload() const{
    return ((uint8_t*)_buf)+taginfoSize();
}


ASN1DERElement::ASN1TAG ASN1DERElement::tag() const{
    return *(ASN1TAG*)&_buf[0];
}

std::string ASN1DERElement::getStringValue() const{
    assure(((uint8_t*)_buf)[0] != 0xff);
    assure(_buf->tagNumber == TagNumber::TagIA5String || _buf->tagNumber == TagNumber::TagOCTET || _buf->tagNumber == TagNumber::TagUTF8String);

    return {(char*)payload(),payloadSize()};
}

uint64_t ASN1DERElement::getIntegerValue() const{
    uint64_t rt = 0;
    assure(_buf->tagNumber == TagNumber::TagINTEGER || _buf->tagNumber == TagNumber::TagBOOLEAN);
    uint8_t *data = (uint8_t*)payload();
    size_t dataSize = payloadSize();
    
    while (dataSize > 0 && *data == 0) {
        data++;
        dataSize--;
    }
    
    assure(dataSize <= sizeof(uint64_t));
    for (uint8_t sizebits = 0; sizebits < dataSize; sizebits++) {
        rt <<= 8;
        rt |= data[sizebits];
    }
    return rt;
}

void ASN1DERElement::print() const{
    switch (tag().tagNumber) {
        case TagIA5String:
            printf("%s",getStringValue().c_str());
            break;
        case TagOCTET:
        {
            std::string s = getStringValue();
            bool isASCII = true;
            for (int i=0; i<s.size(); i++) {
                if (!isprint(s.c_str()[i])){
                    isASCII = false;
                    break;
                }
            }
            if (isASCII) {
                printf("%s",s.c_str());
            }else{
                for (int i=0; i<s.size(); i++) {
                    printf("%02x",((uint8_t*)s.c_str())[i]);
                }
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

std::string ASN1DERElement::printString() const{
    switch (tag().tagNumber) {
        case TagIA5String:
            return getStringValue();
        case TagOCTET:
        {
            std::string s = getStringValue();
            bool isASCII = true;
            for (int i=0; i<s.size(); i++) {
                if (!isprint(s.c_str()[i])){
                    isASCII = false;
                    break;
                }
            }
            if (isASCII) {
                return s;
            }else{
                std::string ret;
                ret.resize(s.size()*2+1);
                for (int i=0; i<s.size(); i++) {
                    snprintf((char*)&ret.data()[i*2], 3, "%02x",((uint8_t*)s.c_str())[i]);
                }
                return ret;
            }
        }
        case TagINTEGER:
        {
            char buf[100]={};
            snprintf(buf, sizeof(buf), "%llu",getIntegerValue());
            return buf;
        }
        case TagBOOLEAN:
        {
            char buf[20]={};
            snprintf(buf, sizeof(buf), "%s",getIntegerValue() == 0 ? "false" : "true");
            return buf;
        }
        default:
            reterror("unimplemented ASN1DERElement::print() for type=%d",tag().tagNumber);
            break;
    }
    reterror("Shouldn't get here");
}



ASN1DERElement ASN1DERElement::operator[](uint32_t i) const{
    assure(_buf->isConstructed);
    ASN1DERElement rt(payload(),payloadSize());
    
    size_t bufSize = payloadSize();
    const uint8_t *bufptr = (const uint8_t *)payload();
    while (i--){
        bufptr += rt.size();
        bufSize -= rt.size();
        rt = ASN1DERElement(bufptr, bufSize);
    }

    return rt;
}

ASN1DERElement &ASN1DERElement::operator+=(const ASN1DERElement &add){
    if (!_ownsBuffer){
        //make a copy
        *this = (const ASN1DERElement&)(*this);
    }
    assure(_buf->isConstructed && _ownsBuffer);

    std::string newSize = makeASN1Size(add.size()+payloadSize());

    if (newSize.size() < taginfoSize()) {
        //newSize fits in the buffer without resizing at front
        _buf = (const ASN1TAG *)realloc((void*)_buf, _bufSize = size() + add.size());

        memcpy((void*)&_buf[size()], add.buf(), add.size());
        memcpy((void*)&_buf[1], newSize.c_str(), newSize.size());
    }else{
        size_t size = add.size() + payloadSize() + 1 + newSize.size();
        const ASN1TAG *buf = (const ASN1TAG *)malloc(size);

        cleanup([&]{
            void *b = (void*)buf; buf = NULL;
            safeFree(b);
        })

        memcpy((void*)&buf[0], &_buf[0], 1);
        memcpy((void*)&buf[1], newSize.c_str(), newSize.size());
        memcpy((void*)&buf[1+newSize.size()], payload(), payloadSize());
        memcpy((void*)&buf[1+newSize.size()+payloadSize()], add.buf(), add.size());

        std::swap(_buf, buf);
        _bufSize = size;
    }

    return *this;
}

ASN1DERElement &ASN1DERElement::operator=(ASN1DERElement &&old){
    void *buf = NULL;
    cleanup([&]{
        safeFree(buf);
    });
    if (_ownsBuffer){
        buf = (void*)_buf; _buf = NULL;
    }
    if (old._ownsBuffer) {
        _buf = old._buf;
        _bufSize = old._bufSize;
        _ownsBuffer = old._ownsBuffer; old._ownsBuffer = false;
    }else{
        /*
         if the old object doesn't own the buffer, we have to perform a copy!
         Otherwise there is no guarantee that the buffer will stay valid
         */
        _bufSize = old._bufSize;
        _ownsBuffer = true;
        _buf = (ASN1TAG*)malloc(_bufSize);
        memcpy((void*)&_buf[0], old._buf, _bufSize);
    }

    return *this;
}

ASN1DERElement &ASN1DERElement::operator=(const ASN1DERElement &old){
    _bufSize = old._bufSize;
    _ownsBuffer = true;
    _buf = (ASN1TAG*)malloc(_bufSize);
    memcpy((void*)&_buf[0], old._buf, _bufSize);

    return *this;
}

ASN1DERElement::ASN1DERElementIterator ASN1DERElement::begin() const{
    return {(const ASN1TAG *)payload(),payloadSize(),0};
}

ASN1DERElement::ASN1DERElementIterator ASN1DERElement::end() const{
    return {(const ASN1TAG *)payload(),payloadSize(),payloadSize()};
}
