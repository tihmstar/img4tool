//
//  img4.h
//  img4tool
//
//  Created by tihmstar on 15.06.16.
//  Copyright © 2016 tihmstar. All rights reserved.
//

#ifndef img4_h
#define img4_h

#include <stdio.h>
#define LEN_XTND  0x80		/* Indefinite or long form */
typedef unsigned char byte;

//TagClass
#define kASN1TagClassUniversal       0
#define kASN1TagClassApplication     1
#define kASN1TagClassContextSpecific 2
#define kASN1TagClassPrivate        3

//primitive
#define kASN1Primitive  0
#define kASN1Contructed 1

//tagNumber
#define kASN1TagEnd_of_Content	0
#define kASN1TagBOOLEAN         1
#define kASN1TagINTEGER         2
#define kASN1TagBIT             3
#define kASN1TagOCTET           4
#define kASN1TagNULL            5
#define kASN1TagOBJECT          6
#define kASN1TagObject          7
#define kASN1TagEXTERNAL        8
#define kASN1TagREAL            9
#define kASN1TagENUMERATED      10
#define kASN1TagEMBEDDED        11
#define kASN1TagUTF8String      12
#define kASN1TagRELATIVE_OID	13
#define kASN1TagReserved        (14 | 15)
#define kASN1TagSEQUENCE        16
#define kASN1TagSET             17
#define kASN1TagNumericString	18
#define kASN1TagPrintableString	19
#define kASN1TagT61String       20
#define kASN1TagVideotexString	21
#define kASN1TagIA5String       22
#define kASN1TagUTCTime         23
#define kASN1TagGeneralizedTime	24
#define kASN1TagGraphicString	25
#define kASN1TagVisibleString	26
#define kASN1TagGeneralString	27
#define kASN1TagUniversalString	28
#define kASN1TagCHARACTER       29
#define kASN1TagBMPString       30

typedef struct{
    byte tagNumber : 5;
    byte isConstructed : 1;
    byte tagClass : 2;
}t_asn1Tag;

typedef struct{
    byte len : 7;
    byte isLong : 1;
}t_asn1Length;

char *ans1GetString(char *buf, char **outString);


#endif /* img4_h */
