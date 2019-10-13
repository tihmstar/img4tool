//
//  img4tool.hpp
//  img4tool
//
//  Created by tihmstar on 04.10.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef img4tool_hpp
#define img4tool_hpp

#include <unistd.h>
#include <iostream>
#include <plist/plist.h>


#include <img4tool/ASN1DERElement.hpp>

namespace tihmstar {
    namespace img4tool {
        const char *version();
        void printIMG4(const void *buf, size_t size, bool printAll, bool im4pOnly);
        void printIM4P(const void *buf, size_t size);
        void printIM4M(const void *buf, size_t size, bool printAll);
//        void printIM4R(const void *buf, size_t size);
        
        std::string getNameForSequence(const void *buf, size_t size);
        
        ASN1DERElement getIM4PFromIMG4(const ASN1DERElement &img4);
        ASN1DERElement getIM4MFromIMG4(const ASN1DERElement &img4);
        
        ASN1DERElement getEmptyIMG4Container();
        ASN1DERElement appendIM4PToIMG4(const ASN1DERElement &img4, const ASN1DERElement &im4p);
        ASN1DERElement appendIM4MToIMG4(const ASN1DERElement &img4, const ASN1DERElement &im4m);
    
        ASN1DERElement getPayloadFromIM4P(const ASN1DERElement &im4p, const char *decryptIv = NULL, const char *decryptKey = NULL);
        ASN1DERElement decryptPayload(const ASN1DERElement &payload, const char *decryptIv, const char *decryptKey);
        
        ASN1DERElement getEmptyIM4PContainer(const char *type, const char *desc);

        ASN1DERElement appendPayloadToIM4P(const ASN1DERElement &im4p, const void *buf, size_t size);

        bool isIMG4(const ASN1DERElement &img4);
        bool isIM4P(const ASN1DERElement &im4p);
        bool isIM4M(const ASN1DERElement &im4m);

        ASN1DERElement renameIM4P(const ASN1DERElement &im4p, const char *type);
        
        bool isIM4MSignatureValid(const ASN1DERElement &im4m);
        
        bool doesIM4MBoardMatchBuildIdentity(const ASN1DERElement &im4m, plist_t buildIdentity) noexcept;
        bool im4mMatchesBuildIdentity(const ASN1DERElement &im4m, plist_t buildIdentity) noexcept;
        const plist_t getBuildIdentityForIm4m(const ASN1DERElement &im4m, plist_t buildmanifest);
        void printGeneralBuildIdentityInformation(plist_t buildidentity);
        bool isValidIM4M(const ASN1DERElement &im4m, plist_t buildmanifest);

        std::string getIM4PSHA1(const ASN1DERElement &im4p);
        std::string getIM4PSHA384(const ASN1DERElement &im4p);

        bool im4mContainsHash(const ASN1DERElement &im4m, std::string hash);
        
    };
};
#endif /* img4tool_hpp */
