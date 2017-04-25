//
//  img4tool.h
//  futurerestore
//
//  Created by tihmstar on 03.09.16.
//  Copyright © 2016 tihmstar. All rights reserved.
//

#ifndef img4tool_h
#define img4tool_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

char *im4mFormShshFile(const char *shshfile, char **generator);
char *readFromFile(const char *filePath);
char *parseNonce(const char *nonce,size_t noncelen);

    
#ifdef __cplusplus
}
#endif
    
#endif /* img4tool_h */
