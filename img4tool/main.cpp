//
//  main.c
//  img4tool
//
//  Created by tihmstar on 02.10.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <plist/plist.h>

#include "img4tool/libgeneral/macros.h"
#include "img4tool.hpp"

using namespace tihmstar::img4tool;
using namespace std;

#define FLAG_EXTRACT     1 << 0
#define FLAG_CREATE_IMG4 1 << 1
#define FLAG_ALL         1 << 2
#define FLAG_IM4PONLY    1 << 3
#define FLAG_VERIFY      1 << 4
#define FLAG_CONVERT     1 << 5
#define FLAG_CREATE_FILE 1 << 6

static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "print-all",      no_argument,        NULL, 'a' },
//    { "extract",        no_argument,        NULL, 'e' },
//    { "im4p-only",      no_argument,        NULL, 'i' },
//    { "shsh",           required_argument,  NULL, 's' },
//    { "im4p",           required_argument,  NULL, 'p' },
//    { "im4m",           required_argument,  NULL, 'm' },
//    { "im4r",           required_argument,  NULL, 'r' },
//    { "outfile",        required_argument,  NULL, 'o' },
//    { "create",         required_argument,  NULL, 'c' },
//    { "rename-payload", required_argument,  NULL, 'n' },
//    { "verify",         required_argument,  NULL, 'v' },
//    { "raw",            required_argument,  NULL, '1' },
//    { "convert",        no_argument,        NULL, '2' },
//    { "tag",            required_argument,  NULL, '3' },
//    { "info",           required_argument,  NULL, '4' },
    { NULL, 0, NULL, 0 }
};


char *readFromFile(const char *filePath, size_t *outSize){
    FILE *f = fopen(filePath, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
#error make a fancy file-to-buf reader
    char *ret = malloc(size);
    if (ret) fread(ret, size, 1, f);
    fclose(f);
    if (outSize) *outSize = size;
    
    return ret;
}

void cmd_help(){
    printf("Usage: img4tool [OPTIONS] FILE\n");
    printf("Parses img4, im4p, im4m files\n\n");
    printf("  -h, --help\t\t\tprints usage information\n");
    printf("  -a, --print-all\t\tprint everything from im4m\n");
//    printf("  -i, --im4p-only\t\tprint only im4p\n");
//    printf("  -e, --extract\t\t\textracts im4m/im4p payload\n");
//    printf("  -o, --outfile\t\t\toutput path for extracting im4p payload (does nothing without -e)\n");
//    printf("  -s, --shsh    PATH\t\tFilepath for shsh (for reading/writing im4m)\n");
//    printf("  -c, --create  PATH\t\tcreates an img4 with the specified im4m, im4p\n");
//    printf("  -m, --im4m    PATH\t\tFilepath for im4m (depending on -e being set)\n");
//    printf("  -p, --im4p    PATH\t\tFilepath for im4p (depending on -e being set)\n");
//    printf("  -r, --im4r    <nonce>\t\tnonce to be set for BNCN in im4r\n");
//    printf("  -v, --verify BUILDMANIFEST\tverify img4, im4m\n");
//    printf("  -n, --rename-payload NAME\trename im4p payload (NAME must be exactly 4 bytes)\n");
//    printf("      --raw     <bytes>\t\twrite bytes to file if combined with -c (does nothing else otherwise)\n");
//    printf("      --convert\t\t\tconvert IM4M file to .shsh (use with -s)\n");
//    printf("      --tag\t\t\tset tag for creating IM4P files from raw\n");
//    printf("      --info\t\t\tset info for creating IM4P files from raw\n");
    
    printf("\n");
}

int main_r(int argc, const char * argv[]) {
    int optindex = 0;
    int opt = 0;
    long flags = 0;
    const char *lastArg = NULL;
    printf("%s\n",version());

    while ((opt = getopt_long(argc, (char* const *)argv, "has:em:p:o:c:ir:n:v:", longopts, &optindex)) > 0) {
        switch (opt) {
            case 'h':
                cmd_help();
                return 0;
            case 'a':
                flags |= FLAG_ALL;
                break;
            default:
                cmd_help();
                return -1;
        }
    }
    
    if (argc-optind == 1) {
        argc -= optind;
        argv += optind;
        lastArg = argv[0];
    }else{
        cmd_help();
        return -2;
    }
    
    
    return 0;
}

int main(int argc, const char * argv[]) {
    try {
        return main_r(argc, argv);
    } catch (tihmstar::exception &e) {
        printf("%s: failed with exception:\n",PACKAGE_NAME);
        e.dump();
        return e.code();
    }
}
