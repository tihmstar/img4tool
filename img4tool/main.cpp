//
//  main.c
//  img4tool
//
//  Created by tihmstar on 02.10.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <plist/plist.h>

#include "img4tool/libgeneral/macros.h"
#include "img4tool.hpp"

using namespace tihmstar::img4tool;
using namespace std;

#define FLAG_ALL         1 << 0
#define FLAG_IM4PONLY    1 << 1
#define FLAG_EXTRACT     1 << 2
//#define FLAG_CREATE_IMG4 1 << 1
//#define FLAG_VERIFY      1 << 4
//#define FLAG_CONVERT     1 << 5
//#define FLAG_CREATE_FILE 1 << 6

static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "print-all",      no_argument,        NULL, 'a' },
    { "im4p-only",      no_argument,        NULL, 'i' },
    { "shsh",           required_argument,  NULL, 's' },
    { "extract",        no_argument,        NULL, 'e' },
    { "im4m",           required_argument,  NULL, 'm' },
    { "im4p",           required_argument,  NULL, 'p' },
    { "create",         required_argument,  NULL, 'c' },
//    { "im4r",           required_argument,  NULL, 'r' },
//    { "rename-payload", required_argument,  NULL, 'n' },
//    { "verify",         required_argument,  NULL, 'v' },
//    { "raw",            required_argument,  NULL, '1' },
//    { "convert",        no_argument,        NULL, '2' },
//    { "tag",            required_argument,  NULL, '3' },
//    { "info",           required_argument,  NULL, '4' },
    { NULL, 0, NULL, 0 }
};

char *im4mFormShshFile(const char *shshfile, size_t *outSize, char **generator){
    FILE *f = fopen(shshfile,"rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    
    size_t fSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char*)malloc(fSize);
    fread(buf, fSize, 1, f);
    fclose(f);
    
    plist_t shshplist = NULL;
    
    if (memcmp(buf, "bplist00", 8) == 0)
        plist_from_bin(buf, (uint32_t)fSize, &shshplist);
    else
        plist_from_xml(buf, (uint32_t)fSize, &shshplist);
    
    plist_t ticket = plist_dict_get_item(shshplist, "ApImg4Ticket");
    
    char *im4m = 0;
    uint64_t im4msize=0;
    plist_get_data_val(ticket, &im4m, &im4msize);
    if (outSize) {
        *outSize = im4msize;
    }
    
    if (generator){
        if ((ticket = plist_dict_get_item(shshplist, "generator")))
            plist_get_string_val(ticket, generator);
    }
    
    plist_free(shshplist);
    
    return im4msize ? im4m : NULL;
}

char *readFromFile(const char *filePath, size_t *outSize){
    FILE *f = fopen(filePath, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *ret = (char*)malloc(size);
    if (ret) fread(ret, size, 1, f);
    fclose(f);
    if (outSize) *outSize = size;
    
    return ret;
}

void saveToFile(const char *filePath, const void *buf, size_t bufSize){
    FILE *f = NULL;
    cleanup([&]{
        if (f) {
            fclose(f);
        }
    });
    
    assure(f = fopen(filePath, "wb"));
    assure(fwrite(buf, 1, bufSize, f) == bufSize);
}

void cmd_help(){
    printf("Usage: img4tool [OPTIONS] FILE\n");
    printf("Parses img4, im4p, im4m files\n\n");
    printf("  -h, --help\t\t\tprints usage information\n");
    printf("  -a, --print-all\t\tprint everything from im4m\n");
    printf("  -i, --im4p-only\t\tprint only im4p\n");
    printf("  -e, --extract\t\t\textracts im4m/im4p payload\n");
    printf("  -s, --shsh\t<PATH>\t\tFilepath for shsh (for reading/writing im4m)\n");
    printf("  -m, --im4m\t<PATH>\t\tFilepath for im4m (depending on -e being set)\n");
    printf("  -p, --im4p\t<PATH>\t\tFilepath for im4p (depending on -e being set)\n");
    printf("  -c, --create\t<PATH>\t\tcreates an img4 with the specified im4m, im4p\n");
//    printf("  -o, --outfile\t\t\toutput path for extracting im4p payload (does nothing without -e)\n");
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
    printf("%s\n",version());
    
    const char *lastArg = NULL;
    const char *shshFile = NULL;
    const char *im4mFile = NULL;
    const char *im4pFile = NULL;
    const char *outFile = NULL;

    int optindex = 0;
    int opt = 0;
    long flags = 0;

    char *workingBuffer = NULL;
    size_t workingBufferSize = 0;
    char *generator = NULL;

    
    cleanup([&]{
        safeFree(workingBuffer);
        safeFree(generator);
    });
    
    
    while ((opt = getopt_long(argc, (char* const *)argv, "has:em:p:c:ir:n:v:", longopts, &optindex)) > 0) {
        switch (opt) {
            case 'h':
                cmd_help();
                return 0;
            case 'a':
                flags |= FLAG_ALL;
                break;
            case 'i':
                flags |= FLAG_IM4PONLY;
                break;
            case 's':
                shshFile = optarg;
                break;
            case 'e':
                flags |= FLAG_EXTRACT;
                break;
            case 'm':
                im4mFile = optarg;
                break;
            case 'p':
                im4pFile = optarg;
                break;
            case 'c':
                outFile = optarg;
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
        if (!shshFile && !outFile) {
            cmd_help();
            return -2;
        }
    }
    
    
    if (!outFile) { //don't load shsh if we create a new file
        if (lastArg) {
            assure((workingBuffer = readFromFile(lastArg, &workingBufferSize)) && workingBufferSize);
        } else if (shshFile){
            assure((workingBuffer = im4mFormShshFile(shshFile, &workingBufferSize, &generator)));
        }
    }
    
    if (workingBuffer) {
        if (flags & FLAG_EXTRACT) {
            //extract
            if (im4pFile) {
                auto im4p = getIM4PFromIMG4(workingBuffer, workingBufferSize);
                saveToFile(im4pFile, im4p.buf(), im4p.size());
                printf("Extracted IM4P to %s\n",im4pFile);
            }
            if (im4mFile) {
                auto im4m = getIM4MFromIMG4(workingBuffer, workingBufferSize);
                saveToFile(im4mFile, im4m.buf(), im4m.size());
                printf("Extracted IM4M to %s\n",im4mFile);
            }
        }else {
            //printing only
            string seqName = getNameForSequence(workingBuffer, workingBufferSize);
            if (seqName == "IMG4") {
                printIMG4(workingBuffer, workingBufferSize, flags & FLAG_ALL, flags & FLAG_IM4PONLY);
            } else if (seqName == "IM4P"){
                printIM4P(workingBuffer, workingBufferSize);
            } else if (seqName == "IM4M"){
                printIM4M(workingBuffer, workingBufferSize, flags & FLAG_ALL);
            }
            else{
                reterror("File not recognised");
            }
        }
    } else if (outFile){
        //create file
        ASN1DERElement img4 = getEmptyIMG4Container();
        
        retassure(im4pFile, "im4p file is required for img4");
        
        if (im4pFile) {
            char *buf = NULL;
            size_t bufSize = 0;
            cleanup([&]{
                safeFree(buf);
            });
            buf = readFromFile(im4pFile, &bufSize);
            
            ASN1DERElement im4p(buf,bufSize);
            
            img4 = appendIM4PToIMG4(img4, im4p);
        }
        
        if (im4mFile || shshFile){
            char *buf = NULL;
            size_t bufSize = 0;
            cleanup([&]{
                safeFree(buf);
            });

            if (im4mFile) {
                buf = readFromFile(im4mFile, &bufSize);
            }else if (shshFile){
                buf = im4mFormShshFile(shshFile, &bufSize, NULL);
            }
            ASN1DERElement im4m(buf,bufSize);
            img4 = appendIM4MToIMG4(img4, im4m);
        }

        saveToFile(outFile, img4.buf(), img4.size());
        printf("Created IMG4 file at %s\n",outFile);
    }
    else{
        reterror("No working buffer");
    }
    
    return 0;
}

int main(int argc, const char * argv[]) {
#ifdef DEBUG
    return main_r(argc, argv);
#else
    try {
        return main_r(argc, argv);
    } catch (tihmstar::exception &e) {
        printf("%s: failed with exception:\n",PACKAGE_NAME);
        e.dump();
        return e.code();
    }
#endif
}
