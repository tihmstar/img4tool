//
//  main.c
//  img4tool
//
//  Created by tihmstar on 15.06.16.
//  Copyright © 2016 tihmstar. All rights reserved.
//

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <plist/plist.h>
#include "img4.h"
#include "img4tool.h"
#include "all_img4tool.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __APPLE__
#   include <CommonCrypto/CommonDigest.h>
#   define SHA1(d, n, md) CC_SHA1(d, n, md)
#   define SHA384(d, n, md) CC_SHA384(d, n, md)
#else
#   include <openssl/sha.h>
#endif // __APPLE__


#define safeFree(buf) if (buf) free(buf), buf = NULL
#define swapchar(a,b) ((a) ^= (b),(b) ^= (a),(a) ^= (b)) //swaps a and b, unless they are the same variable

char *im4mFormShshFile(const char *shshfile, char **generator){
    FILE *f = fopen(shshfile,"rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    
    size_t fSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(fSize);
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
    
    if (generator){
        if ((ticket = plist_dict_get_item(shshplist, "generator")))
            plist_get_string_val(ticket, generator);
    }
    
    plist_free(shshplist);
    
    return im4msize ? im4m : NULL;
}

char *readFromFile(const char *filePath){
    FILE *f = fopen(filePath, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *ret = malloc(size);
    if (ret) fread(ret, size, 1, f);
    fclose(f);
    
    return ret;
}

plist_t readPlistFromFile(const char *filePath){
    FILE *f = fopen(filePath, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *buf = malloc(size);
    if (!buf)
        return fclose(f),NULL;
    
    fread(buf, size, 1, f);
    fclose(f);
    
    plist_t rt = NULL;
    
    if (memcmp(buf, "bplist00", 8) == 0)
        plist_from_bin(buf, (uint32_t)size, &rt);
    else
        plist_from_xml(buf, (uint32_t)size, &rt);
    
    free(buf);
    
    return rt;
}

char *parseNonce(const char *nonce,size_t noncelen){
    //    size_t noncelen = 8;
    
    char *ret = malloc((noncelen+1)*sizeof(char));
    memset(ret, 0, noncelen+1);
    int nlen = 0;
    
    int next = strlen(nonce)%2 == 0;
    char tmp = 0;
    while (*nonce) {
        char c = *(nonce++);
        
        tmp *=16;
        if (c >= '0' && c<='9') {
            tmp += c - '0';
        }else if (c >= 'a' && c <= 'f'){
            tmp += 10 + c - 'a';
        }else if (c >= 'A' && c <= 'F'){
            tmp += 10 + c - 'A';
        }else {
            free(ret);
            return 0; //ERROR parsing failed
        }
        if ((next =! next) && nlen < noncelen) ret[nlen++] = tmp,tmp=0;
    }
    
    return ret;
}

#define FLAG_EXTRACT    1 << 0
#define FLAG_CREATE     1 << 1
#define FLAG_ALL        1 << 2
#define FLAG_IM4PONLY   1 << 3
#define FLAG_VERIFY     1 << 4
#define FLAG_CONVERT    1 << 5


#ifndef IMG4TOOL_NOMAIN
#define MAX_PRINT_LEN 64*1024
void debug_plist(plist_t plist) {
    uint32_t size = 0;
    char* data = NULL;
    plist_to_xml(plist, &data, &size);
    if (size <= MAX_PRINT_LEN)
        printf("%s:printing %i bytes plist:\n%s", __FILE__, size, data);
    else
        printf("%s:supressed printing %i bytes plist...\n", __FILE__, size);
    free(data);
}

static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "extract",        no_argument,        NULL, 'e' },
    { "print-all",      no_argument,        NULL, 'a' },
    { "im4p-only",      no_argument,        NULL, 'i' },
    { "shsh",           required_argument,  NULL, 's' },
    { "im4p",           required_argument,  NULL, 'p' },
    { "im4m",           required_argument,  NULL, 'm' },
    { "im4r",           required_argument,  NULL, 'r' },
    { "outfile",        required_argument,  NULL, 'o' },
    { "create",         required_argument,  NULL, 'c' },
    { "rename-payload", required_argument,  NULL, 'n' },
    { "verify",         required_argument,  NULL, 'v' },
    { "raw",            required_argument,  NULL, '1' },
    { "convert",        no_argument,        NULL, '2' },
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf("Usage: img4tool [OPTIONS] FILE\n");
    printf("Parses img4, im4p, im4m files\n\n");
    
    printf("  -h, --help\t\t\tprints usage information\n");
    printf("  -a, --print-all\t\tprint everything from IM4M\n");
    printf("  -i, --im4p-only\t\tprint only IM4P\n");
    printf("  -e, --extract\t\t\textracts im4p payload,im4m,im4p\n");
    printf("  -o, --outfile\t\t\toutput path for extracting im4p payload (does nothing without -e)\n");
    printf("  -s, --shsh    PATH\t\tFilepath for shsh (for reading/writing im4m)\n");
    printf("  -c, --create  PATH\t\tcreates an img4 with the specified im4m, im4p\n");
    printf("  -m, --im4m    PATH\t\tFilepath for im4m (reading or writing, depending on -e being set)\n");
    printf("  -p, --im4p    PATH\t\tFilepath for im4p (reading or writing, depending on -e being set)\n");
    printf("  -r, --im4r    <nonce>\t\tnonce to be set for BNCN in im4r\n");
    printf("  -v, --verify BUILDMANIFEST\tverify IMG4, IM4M\n");
    printf("  -n, --rename-payload NAME\trename IM4P payload (NAME must be exactly 4 bytes)\n");
    printf("      --raw     <bytes>\t\twrite bytes to file if combined with -c (does nothing else otherwise)\n");
    printf("      --convert\t\t\tconvert IM4M file to .shsh (use with -s)\n");
    
    printf("\n");
}

static int parseHex(const char *nonce, size_t *parsedLen, char *ret, size_t *retSize){
    size_t nonceLen = strlen(nonce);
    nonceLen = nonceLen/2 + nonceLen%2; //one byte more if len is odd
    
    if (retSize) *retSize = (nonceLen+1)*sizeof(char);
    if (!ret) return 0;
    
    memset(ret, 0, nonceLen+1);
    unsigned int nlen = 0;
    
    int next = strlen(nonce)%2 == 0;
    char tmp = 0;
    while (*nonce) {
        char c = *(nonce++);
        
        tmp *=16;
        if (c >= '0' && c<='9') {
            tmp += c - '0';
        }else if (c >= 'a' && c <= 'f'){
            tmp += 10 + c - 'a';
        }else if (c >= 'A' && c <= 'F'){
            tmp += 10 + c - 'A';
        }else{
            return -1; //ERROR parsing failed
        }
        if ((next =! next) && nlen < nonceLen) ret[nlen++] = tmp,tmp=0;
    }
    
    if (parsedLen) *parsedLen = nlen;
    return 0;
}

int main(int argc, const char * argv[]) {
    printf("Version: "IMG4TOOL_VERSION_COMMIT_SHA" - "IMG4TOOL_VERSION_COMMIT_COUNT"\n");
    int error = 0;
    int optindex = 0;
    int opt = 0;
    
    long flags = 0;
    const char *img4File = NULL;
    const char *im4pFile = NULL;
    const char *im4mFile = NULL;
    const char *shshFile = NULL;
    const char *extractFile = NULL;
    const char *createFile = NULL;
    const char *newPayloadName = NULL;
    const char *rawBytes = NULL;
    char *generator = NULL;
    
    if (sizeof(uint64_t) != 8){
        printf("[FATAL] sizeof(uint64_t) != 8 (size is %lu byte). This program might function incorrectly\n",sizeof(uint64_t));
//        return 64;
    }
    
    char *buf = NULL;
    char *im4m = NULL;
    char *im4p = NULL;
    char *im4r = NULL;
    
    const char *buildmanifestPath = NULL;
    plist_t buildManifest = NULL;
    
    while ((opt = getopt_long(argc, (char* const *)argv, "has:em:p:o:c:ir:n:1:v:", longopts, &optindex)) > 0) {
        switch (opt) {
            case '1':
                rawBytes = optarg;
                break;
            case 'a':
                flags |= FLAG_ALL;
                break;
            case '2':
                flags |= FLAG_CONVERT;
                break;
            case 'i':
                flags |= FLAG_IM4PONLY;
                break;
            case 'v':
                flags |= FLAG_VERIFY;
                if (strcmp(buildmanifestPath = optarg,"NULL") == 0) buildmanifestPath = NULL;
                break;
            case 's':
                shshFile = optarg;
                break;
            case 'm':
                im4mFile = optarg;
                break;
            case 'p':
                im4pFile = optarg;
                break;
            case 'n':
                if (strlen(newPayloadName = optarg) != 4){
                    printf("[Error] new payload name must be exaclty 4 Bytes (currently=\"%s\")\n",newPayloadName);
                    exit(-2);
                }
                break;
            case 'r':
                im4r = parseNonce(optarg,8);
                break;
            case 'o':
                extractFile = optarg;
                break;
            case 'c':
                flags |= FLAG_CREATE;
                createFile = optarg;
                break;
            case 'e':
                flags |= FLAG_EXTRACT;
                break;
            default:
                cmd_help();
                return -1;
        }
    }
    
    if (argc-optind == 1) {
        argc -= optind;
        argv += optind;
        
        img4File = argv[0];
    }else if (shshFile && !(flags & FLAG_CONVERT)){
        if (!(im4m = im4mFormShshFile(shshFile, &generator))){
            printf("[Error] reading file failed %s\n",shshFile);
            return -1;
        }
    }else if (!img4File && !(flags & FLAG_CREATE)){
        cmd_help();
        return -2;
    }
    
    if (!(flags & FLAG_CREATE)){
        buf = readFromFile(img4File);
        if (!buf && !(buf = im4m)){
            printf("[Error] reading file failed %s\n",img4File);
            return -1;
        }
        if (*(unsigned char*)buf != 0x30) {
            printf("[Error] file %s doesn't seem to be img4, im4p, im4m or im4r file\n",img4File);
            return -5;
        }
    }
    
    if (buildmanifestPath) {
        if (!(buildManifest = readPlistFromFile(buildmanifestPath))){
            error("failed to read buildmanifest from %s\n",buildmanifestPath);
            goto error;
        }
        
    }
    
    if (newPayloadName){
        
        FILE *f = fopen(img4File, "r");
        if (!f){
            printf("[Error] reading file failed\n");
            error= -8;
            goto error;
        }
        fseek(f, 0, SEEK_END);
        size_t size = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        buf = malloc(size);
        if (buf) fread(buf, size, 1, f);
        fclose(f);
        
        
        char *im4pbuf = NULL;
        if (sequenceHasName(buf, "IMG4")){
            im4pbuf = getElementFromIMG4(buf, "IM4P");
        }else if (sequenceHasName(buf, "IM4P")){
            im4pbuf = buf;
        }
        if (!im4pbuf){
            printf("[Error] can't rename IM4P because it wasn't found\n");
            error = -6;
            goto error;
        }
        if (replaceNameInIM4P(im4pbuf, newPayloadName)){
            printf("[Error] renaming failed\n");
            error = -7;
            goto error;
        }
        
        f = fopen(img4File, "w");
        fwrite(buf, size, 1, f);
        fclose(f);
        printf("[Success] renamed IM4P\n");
        
    }else if (flags & FLAG_CONVERT){
        if (!shshFile) {
            printf("[Error] --convert also requires output to be defined with -s\n");
            error = -9;
            goto error;
        }
        
        FILE *im4m = fopen(img4File, "rb");
        if (!im4m){
            printf("[Error] reading file failed\n");
            error= -8;
            goto error;
        }
        fseek(im4m, 0, SEEK_END);
        size_t size = ftell(im4m);
        fseek(im4m, 0, SEEK_SET);
        
        buf = malloc(size);
        if (buf) fread(buf, size, 1, im4m);
        fclose(im4m);
        
        plist_t newshsh = plist_new_dict();
        if (!newshsh){
            printf("[Error] can't alloc new plist\n");
            error = -10;
            goto error;
        }
        
        plist_t data = plist_new_data(buf, size);
        
        plist_dict_set_item(newshsh, "ApImg4Ticket", data);
        
        char *xml = NULL;
        uint32_t xmlSize = 0;
        plist_to_xml(newshsh, &xml, &xmlSize);
        
        if (!xml){
            printf("[Error] plist to xml failed\n"),error=-11;
        }else{
            FILE *f = NULL;
            if ((f = fopen(shshFile, "r"))){
                printf("[Error] shshFile=%s already exists, not overwriting\n",shshFile),error=-12;
                fclose(f);
            }else{
                f = fopen(shshFile, "w");
                if (!f){
                    printf("[Error] failed to open shshfile for writing\n"),error=-13;
                }else{
                    if (fwrite(xml, 1, xmlSize, f) != xmlSize)
                        printf("[Error] saving shsh file failed!\n"),error=-14;
                    else
                        printf("Successfully converted IM4M to .shsh\n");
                    fclose(f);
                }
            }
            free(xml);
        }
        
        
        plist_free(newshsh);
        
    }else if (flags & FLAG_EXTRACT) {
        char *im4pbuf = NULL;
        if (!im4mFile && !im4pFile && !extractFile){
            printf("[Error] you need to specify at least one of --outfile --im4p --im4m when using -e\n");
            cmd_help();
            goto error;
        }
        if (sequenceHasName(buf, "IMG4")){
            if (im4mFile) {
                if (extractElementFromIMG4(buf, "IM4M", im4mFile)) printf("[Error] extracting IM4M failed\n");
                else printf("[Success] extracted IM4M to %s\n",im4mFile);
            }
            if (im4pFile) {
                if (extractElementFromIMG4(buf, "IM4P", im4pFile)) printf("[Error] extracting IM4P failed\n");
                else printf("[Success] extracted IM4P to %s\n",im4pFile);
            }
            if (extractFile){
                im4pbuf = getElementFromIMG4(buf, "IM4P");
            }
        }else if(sequenceHasName(buf, "IM4P")){
            im4pbuf = buf;
        }else if(sequenceHasName(buf, "IM4M")){
            
            FILE *f = fopen(im4mFile, "wb");
            if (!f) {
                error("can't open file %s\n",im4mFile);
                return -1;
            }
            
            t_asn1ElemLen len = asn1Len((char*)buf+1);
            size_t flen = len.dataLen + len.sizeBytes +1;
            fwrite(buf, flen, 1, f);
            fclose(f);
            printf("[Success] extracted IM4M to %s\n",im4mFile);

        }else{
            char *name;
            size_t nameLen;
            getSequenceName(buf, &name, &nameLen);
            printf("[Error] can't extract elements from ");
            putStr(name, nameLen);
            printf("\n");
        }
        if (im4pbuf) {
            if (extractFileFromIM4P(im4pbuf, extractFile)) printf("[Error] extracting payload from IM4P failed\n");
            else printf("[Success] extracted IM4P payload to %s\n",extractFile);
        }
        
        
        //creating
    }else if (flags & FLAG_CREATE){
        size_t bufSize = 0;
        
        if (!rawBytes){
            printf("building img4 with: ");
            if (im4pFile && (im4p = readFromFile(im4pFile))) printf("IM4P ");
            if (im4m || (im4mFile && (im4m = readFromFile(im4mFile)))) printf("IM4M ");
            if (im4r) printf("IM4R ");
            if (!im4m && !im4p && !im4r) printf("<empty>");
            printf("\n");
            
            buf = makeIMG4(im4p, im4m, im4r, &bufSize);
        }else{
            bufSize = strlen(rawBytes)/2;
            buf = parseNonce(rawBytes,bufSize);
        }
        
        FILE *f = fopen(createFile, "w");
        if (!f) {
            printf("[Error] creating file %s failed\n",img4File);
            goto error;
        }
        fwrite(buf, bufSize, 1, f);
        fclose(f);
        printf("[Success] created %s\n",(rawBytes) ? "file" : "IMG4");
        
        //printing
    }else if (sequenceHasName(buf, "IMG4")){
        printElemsInIMG4(buf,(flags & FLAG_ALL), (flags & FLAG_IM4PONLY));
    }else if(sequenceHasName(buf, "IM4P")){
        printIM4P(buf);
    }else if(sequenceHasName(buf, "IM4M")){
        printIM4M(buf,(flags & FLAG_ALL));
    }else if (sequenceHasName(buf, "IM4R")){
        printIM4R(buf);
    }
    if (flags & FLAG_VERIFY) {
        unsigned char genHash[48]; //SHA384 digest length
        size_t bnchSize = 0;
        int isIM4M = 0;
        if (sequenceHasName(buf, "IMG4") || (isIM4M = sequenceHasName(buf, "IM4M"))){
            char *bnch = getBNCHFromIM4M(isIM4M ? buf : getIM4MFromIMG4(buf), &bnchSize);
            if (generator) {
                if (bnch && strlen(generator) == 18 && generator[0] == '0' && generator[1] == 'x') {
                    unsigned char zz[9] = {0};
                    parseHex(generator+2, NULL, (char*)zz, NULL);
                    swapchar(zz[0], zz[7]);
                    swapchar(zz[1], zz[6]);
                    swapchar(zz[2], zz[5]);
                    swapchar(zz[3], zz[4]);
                    
                    if (bnchSize == 32)
                        SHA384(zz, 8, genHash);
                    else
                        SHA1(zz, 8, genHash);
                    if (memcmp(genHash, bnch, bnchSize) == 0) {
                        printf("[OK] verified generator \"%s\" to be valid for BNCH \"",generator);
                    }else{
                        printf("[Error] generator does not generate same nonce as inside IM4M, but instead it'll generate \"");
                    }
                    
                    for (int i=0; i<bnchSize; i++)
                        printf("%02x",*(unsigned char*)(bnch+i));
                    printf("\"\n");
                } else if (bnch) {
                    printf("[Error] generator \"%s\" is invalid\n", generator);
                    error = -16;
                } else {
                    printf("[Error] Failed to validate generator.\n");
                    error = -17;
                }
            }
            if (!error)
                printf("[IMG4TOOL] file is %s!\n",verifyIMG4(buf,buildManifest) ? "invalid" : "valid");
            
        }
        else
            printf("[Error] can't verify non IM4M file\n"),error = -15;
    }
   
error:
    if (im4m == buf) im4m = NULL;
    if (buildManifest) plist_free(buildManifest);
    safeFree(generator);
    safeFree(buf);
    safeFree(im4m);
    safeFree(im4p);
    safeFree(im4r);
    
    return error;
}
#endif
