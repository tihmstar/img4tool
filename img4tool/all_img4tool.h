//
//  all.h
//  img4tool
//
//  Created by tihmstar on 15.06.16.
//  Copyright © 2016 tihmstar. All rights reserved.
//

#ifndef all_h
#define all_h

#include <config.h>

#define error(a ...) printf("[Error] %s: ",__func__),printf(a)
#define warning(a ...) printf("[Warning] %s: ",__func__),printf(a)

#define VERSION_COMMIT_COUNT "103"
#define VERSION_COMMIT_SHA "3c153b91a0d60c28810e5992df4ba01ae5c8b541"


#endif /* all_h */
