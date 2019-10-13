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

#define FLAG_ALL        (1 << 0)
#define FLAG_IM4PONLY   (1 << 1)
#define FLAG_EXTRACT    (1 << 2)
#define FLAG_CREATE     (1 << 3)
#define FLAG_RENAME     (1 << 4)
#define FLAG_CONVERT    (1 << 5)

static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "print-all",      no_argument,        NULL, 'a' },
    { "im4p-only",      no_argument,        NULL, 'i' },
    { "shsh",           required_argument,  NULL, 's' },
    { "extract",        no_argument,        NULL, 'e' },
    { "im4m",           required_argument,  NULL, 'm' },
    { "im4p",           required_argument,  NULL, 'p' },
    { "create",         required_argument,  NULL, 'c' },
    { "outfile",        required_argument,  NULL, 'o' },
    { "type",           required_argument,  NULL, 't' },
    { "desc",           required_argument,  NULL, 'd' },
    { "rename-payload", required_argument,  NULL, 'n' },
    { "verify",         required_argument,  NULL, 'v' },
    { "iv",             required_argument,  NULL, '1' },
    { "key",            required_argument,  NULL, '2' },
    { "convert",        no_argument,        NULL, '3' },
    { NULL, 0, NULL, 0 }
};

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

plist_t readPlistFromFile(const char *filePath){
    FILE *f = fopen(filePath,"rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    
    size_t fSize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char*)malloc(fSize);
    fread(buf, fSize, 1, f);
    fclose(f);
    
    plist_t plist = NULL;
    
    if (memcmp(buf, "bplist00", 8) == 0)
        plist_from_bin(buf, (uint32_t)fSize, &plist);
    else
        plist_from_xml(buf, (uint32_t)fSize, &plist);
    
    return plist;
}

char *im4mFormShshFile(const char *shshfile, size_t *outSize, char **generator){
    plist_t shshplist = readPlistFromFile(shshfile);
    
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
    printf("  -c, --create\t<PATH>\t\tcreates an img4 with the specified im4m, im4p or creates im4p with raw file (last argument)\n");
    printf("  -o, --outfile\t\t\toutput path for extracting im4p payload (-e) or renaming im4p (-n)\n");
    printf("  -t, --type\t\t\tset type for creating IM4P files from raw\n");
    printf("  -d, --desc\t\t\tset desc for creating IM4P files from raw\n");
    printf("  -n, --rename-payload NAME\trename im4p payload (NAME must be exactly 4 bytes)\n");
    printf("  -v, --verify BUILDMANIFEST\tverify img4, im4m\n");
    printf("      --iv\t\t\tIV  for decrypting payload when extracting (requires -e and -o)\n");
    printf("      --key\t\t\tKey for decrypting payload when extracting (requires -e and -o)\n");
    printf("      --convert\t\t\tconvert IM4M file to .shsh (use with -s)\n");

    printf("\n");
}

int main_r(int argc, const char * argv[]) {
    printf("%s\n",version());
    
    const char *lastArg = NULL;
    const char *shshFile = NULL;
    const char *im4mFile = NULL;
    const char *im4pFile = NULL;
    const char *outFile = NULL;
    const char *decryptIv = NULL;
    const char *decryptKey = NULL;
    const char *im4pType = NULL;
    const char *im4pDesc = "Image created by img4tool";
    const char *buildmanifestFile = NULL;

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
    
    while ((opt = getopt_long(argc, (char* const *)argv, "hais:em:p:c:o:1:2:t:d:n:3v:", longopts, &optindex)) > 0) {
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
                retassure(!(flags & FLAG_CREATE), "Invalid command line arguments. can't extract and create at the same time");
                flags |= FLAG_EXTRACT;
                break;
            case 'm':
                im4mFile = optarg;
                break;
            case 'p':
                im4pFile = optarg;
                break;
            case 'c':
                flags |= FLAG_CREATE;
                retassure(!(flags & FLAG_EXTRACT), "Invalid command line arguments. can't extract and create at the same time");
                retassure(!outFile, "Invalid command line arguments. outFile already set!");
                outFile = optarg;
                break;
            case 'o':
                retassure(!outFile, "Invalid command line arguments. outFile already set!");
                outFile = optarg;
                break;
            case '1':  //iv
                decryptIv = optarg;
                break;
            case '2':  //key
                decryptKey = optarg;
                break;
            case '3':  //convert
                flags |= FLAG_CONVERT;
                break;
            case 't':
                retassure(!(flags & FLAG_RENAME), "Invalid command line arguments. can't rename and create at the same time");
                retassure(!im4pType, "Invalid command line arguments. im4pType already set!");
                im4pType = optarg;
                break;
            case 'd':  //info
                im4pDesc = optarg;
                break;
            case 'n': //rename-payload
                retassure(!im4pType, "Invalid command line arguments. im4pType already set!");
                im4pType = optarg;
                flags |= FLAG_RENAME;
                break;
            case 'v':
                buildmanifestFile = optarg;
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
        if (!shshFile && !(flags & FLAG_CREATE)) {
            cmd_help();
            return -2;
        }
    }
    
    
    if (!(flags & FLAG_CREATE && im4pFile) ) { //don't load shsh if we create a new img4 file
        if (lastArg) {
            assure((workingBuffer = readFromFile(lastArg, &workingBufferSize)) && workingBufferSize);
        } else if (shshFile){
            assure((workingBuffer = im4mFormShshFile(shshFile, &workingBufferSize, &generator)));
        }
    }
    
    if (workingBuffer) {
        if (flags & FLAG_EXTRACT) {
            //extract
            bool didExtract = false;
            ASN1DERElement file(workingBuffer, workingBufferSize);
            
            if (outFile) {
                //check for payload extraction
                if (isIMG4(file)) {
                    file = getIM4PFromIMG4(file);
                } else if (!isIM4P(file)){
                    reterror("File not recognised");
                }
                
                ASN1DERElement payload = getPayloadFromIM4P(file, decryptIv, decryptKey);
                saveToFile(outFile, payload.payload(), payload.payloadSize());
                printf("Extracted IM4P payload to %s\n",outFile);
                didExtract = true;
            } else if (isIMG4(file)) {
                //extract im4p an im4m from img4
                if (im4pFile) {
                    auto im4p = getIM4PFromIMG4(file);
                    saveToFile(im4pFile, im4p.buf(), im4p.size());
                    printf("Extracted IM4P to %s\n",im4pFile);
                    didExtract = true;
                }
                if (im4mFile) {
                    auto im4m = getIM4MFromIMG4(file);
                    saveToFile(im4mFile, im4m.buf(), im4m.size());
                    printf("Extracted IM4M to %s\n",im4mFile);
                    didExtract = true;
                }
            }else if (isIM4M(file)){
                assure(im4mFile);
                saveToFile(im4mFile, file.buf(), file.size());
                printf("Saved IM4M to %s\n",im4mFile);
                didExtract = true;
            }

            if (!didExtract) {
                error("Failed to extract!\n");
                return -1;
            }
        } else if (flags & FLAG_CREATE && im4pType){
            ASN1DERElement im4p = getEmptyIM4PContainer(im4pType, im4pDesc);

            im4p = appendPayloadToIM4P(im4p, workingBuffer, workingBufferSize);

            saveToFile(outFile, im4p.buf(), im4p.size());
            printf("Created IM4P file at %s\n",outFile);
        } else if (flags & FLAG_RENAME){
            retassure(im4pType, "typen required");
            retassure(outFile, "outputfile required");
            
            ASN1DERElement im4p(workingBuffer, workingBufferSize);
            string seqName = getNameForSequence(workingBuffer, workingBufferSize);
            if (seqName != "IM4P"){
                reterror("File not an IM4P");
            }
            
            im4p = renameIM4P(im4p, im4pType);
            saveToFile(outFile, im4p.buf(), im4p.size());
            printf("Saved new renamed IM4P to %s\n",outFile);
        } else if (flags & FLAG_CONVERT){
            retassure(shshFile, "output path for shsh file required");
            ASN1DERElement im4m(workingBuffer, workingBufferSize);
            retassure(isIM4M(im4m), "lastarg needs to be IM4M");
            
            plist_t newshsh = NULL;
            plist_t data = NULL;
            char *xml = NULL;
            uint32_t xmlSize = 0;
            cleanup([&]{
                if (newshsh) {
                    plist_free(newshsh);
                }
                if (data) {
                    plist_free(data);
                }
                safeFree(xml);
            });
            assure(newshsh = plist_new_dict());
            assure(data = plist_new_data((const char*)im4m.buf(), im4m.size()));
            
            plist_dict_set_item(newshsh, "ApImg4Ticket", data); data = NULL;
            
            retassure((plist_to_xml(newshsh, &xml, &xmlSize),xml), "failed to convert plist to xml");
            saveToFile(shshFile, xml, xmlSize);
            printf("Saved IM4M to %s\n",shshFile);
        } else if (buildmanifestFile){
            //verify
            ASN1DERElement file(workingBuffer, workingBufferSize);
            std::string im4pSHA1;
            std::string im4pSHA384;

            if (isIMG4(file)) {
                ASN1DERElement im4p = getIM4PFromIMG4(file);
                file = getIM4MFromIMG4(file);
                
                im4pSHA1 = getIM4PSHA1(im4p);
                im4pSHA384 = getIM4PSHA384(im4p);
            }
            
            if (isIM4M(file)) {
                plist_t buildmanifest = NULL;
                cleanup([&]{
                    if (buildmanifest) {
                        plist_free(buildmanifest);
                    }
                });
                assure(buildmanifest = readPlistFromFile(buildmanifestFile));
                
                printf("APTicket is %s!\n",isValidIM4M(file, buildmanifest) ? "valid" : "invalid");
                
                if (im4pSHA1.size() || im4pSHA384.size()) {
                    //verify payload hash too
                    retassure(im4mContainsHash(file, im4pSHA1) || im4mContainsHash(file, im4pSHA384), "IM4P hash not in IM4M");
                    printf("[IMG4TOOL] IMG4 contains an IM4P which is correctly signed by IM4M\n");
                }
            }else{
                reterror("File not recognised");
            }
        }
        else {
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
    } else if (flags & FLAG_CREATE){
        //create IMG4 file
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
