//
//  ASN1DER.hpp
//  img4tool
//
//  Created by tihmstar on 04.10.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef ASN1DER_hpp
#define ASN1DER_hpp

#include <unistd.h>
#include <stdint.h>
#include <iostream>

namespace tihmstar {
    namespace img4tool {
        
        class ASN1DERElement {
        public:
            
            enum TagClass{
                Universal      = 0,
                Application    = 1,
                ContextSpecific= 2,
                Private        = 3
            };

            enum Primitive{
                Primitive  = 0,
                Constructed = 1
            };

            enum TagNumber{
                TagEnd_of_Content  = 0,
                TagBOOLEAN         = 1,
                TagINTEGER         = 2,
                TagBIT             = 3,
                TagOCTET           = 4,
                TagNULL            = 5,
                TagOBJECT          = 6,
                TagObject          = 7,
                TagEXTERNAL        = 8,
                TagREAL            = 9,
                TagENUMERATED      = 10, //0x0A
                TagEMBEDDED        = 11, //0x0B
                TagUTF8String      = 12, //0x0C
                TagRELATIVE_OID    = 13, //0x0D
                TagReserved        = (14 | 15), //(0x0E | 0x0F)
                TagSEQUENCE        = 16, //0x10
                TagSET             = 17, //0x11
                TagNumericString   = 18, //0x12
                TagPrintableString = 19, //0x13
                TagT61String       = 20, //0x14
                TagVideotexString  = 21, //0x15
                TagIA5String       = 22, //0x16
                TagUTCTime         = 23, //0x17
                TagGeneralizedTime = 24, //0x18
                TagGraphicString   = 25, //0x19
                TagVisibleString   = 26, //0x1A
                TagGeneralString   = 27, //0x1B
                TagUniversalString = 28, //0x1C
                TagCHARACTER       = 29, //0x1D
                TagBMPString       = 30, //0x1E
                TagPrivate         = 0xff
            };

            
            struct ASN1TAG{
                uint8_t tagNumber : 5;
                uint8_t isConstructed : 1;
                uint8_t tagClass : 2;
            };
            
            struct ASN1Len{
                uint8_t len : 7;
                uint8_t isLong : 1;
            };
            
            struct ASN1PrivateTag{
                uint8_t num : 7;
                uint8_t more : 1;
            };
            
            class ASN1DERElementIterator{
                const ASN1TAG *_buf;
                uint64_t _pos;
                size_t _containerSize;
            public:
                ASN1DERElementIterator(const ASN1TAG *buf, size_t containerSize, uint64_t pos);
                ASN1DERElementIterator &operator++();
                bool operator!=(const ASN1DERElementIterator &e);
                const ASN1DERElement operator*() const;
            };
            
        private:
            const ASN1TAG *_buf;
            size_t _bufSize;
            /*
                If we get a buffer and a size, we never claim ownership, however
                if we construct an object ourselve we alloc a buffer and thus claim ownership
             */
            bool _ownsBuffer;
        public:
            ASN1DERElement(const void *buf, size_t bufSize, bool ownsBuffer = false);
            ASN1DERElement(const ASN1TAG tag, const void *payload, size_t payloadLen);
            ~ASN1DERElement();
            
            ASN1DERElement(ASN1DERElement &&old);
            ASN1DERElement(const ASN1DERElement &old);


            bool ownsBuffer() const;
            const void *buf() const;
            const void *payload() const;
            size_t taginfoSize() const;
            size_t payloadSize() const;
            size_t size() const;

            ASN1TAG tag() const;
            
            std::string getStringValue() const;
            uint64_t getIntegerValue() const;
            void print() const;

            
            ASN1DERElement operator[](uint32_t i) const;
            ASN1DERElement &operator+=(const ASN1DERElement &add);
            ASN1DERElement &operator=(ASN1DERElement &&old);
            ASN1DERElement &operator=(const ASN1DERElement &obj);

            ASN1DERElementIterator begin() const;
            ASN1DERElementIterator end() const;
            
            static std::string makeASN1Size(size_t size);
            static ASN1DERElement makeASN1Integer(uint64_t num);
        };
        
    };
};

#endif /* ASN1DER_hpp */
