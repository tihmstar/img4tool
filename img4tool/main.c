//
//  main.c
//  img4tool
//
//  Created by tihmstar on 15.06.16.
//  Copyright © 2016 tihmstar. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include "img4.h"

int main(int argc, const char * argv[]) {
    
    
    FILE *f = fopen("iBEC.n66.RELEASE.im4p", "r");
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char * buf = malloc(size);
    fread(buf, size, 1, f);
    
    char *str;
    char *b2 = ans1GetString(buf+5, &str);
    
    free(buf);
    fclose(f);
    
    return 0;
}
