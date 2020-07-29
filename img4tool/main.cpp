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
#include <algorithm>

#include <libgeneral/macros.h>
#include "img4tool.hpp"

#ifdef HAVE_PLIST
#include <plist/plist.h>
#endif //HAVE_PLIST


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
#ifdef HAVE_PLIST
    { "shsh",           required_argument,  NULL, 's' },
#endif //HAVE_PLIST
    { "extract",        no_argument,        NULL, 'e' },
    { "im4m",           required_argument,  NULL, 'm' },
    { "im4p",           required_argument,  NULL, 'p' },
    { "create",         required_argument,  NULL, 'c' },
    { "outfile",        required_argument,  NULL, 'o' },
    { "type",           required_argument,  NULL, 't' },
    { "desc",           required_argument,  NULL, 'd' },
    { "rename-payload", required_argument,  NULL, 'n' },
#ifdef HAVE_PLIST
    { "verify",         required_argument,  NULL, 'v' },
#endif //HAVE_PLIST
    { "iv",             required_argument,  NULL, '1' },
    { "key",            required_argument,  NULL, '2' },
#ifdef HAVE_PLIST
    { "convert",        no_argument,        NULL, '3' },
#endif //HAVE_PLIST
    { "compression",    required_argument,  NULL, '4' },
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

#ifdef HAVE_PLIST
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
#endif //HAVE_PLIST


void saveToFile(const char *filePath, const void *buf, size_t bufSize){
    FILE *f = NULL;
    cleanup([&]{
        if (f) {
            fclose(f);
        }
    });

    retassure(f = fopen(filePath, "wb"), "failed to create file");
    retassure(fwrite(buf, 1, bufSize, f) == bufSize, "failed to write to file");
}

void cmd_help(){
    printf("Usage: img4tool [OPTIONS] FILE\n");
    printf("Parses img4, im4p, im4m files\n\n");
    printf("  -h, --help\t\t\tprints usage information\n");
    printf("  -a, --print-all\t\tprint everything from im4m\n");
    printf("  -i, --im4p-only\t\tprint only im4p\n");
    printf("  -e, --extract\t\t\textracts im4m/im4p payload\n");
#ifndef HAVE_PLIST
    printf("UNAVAILABLE: ");
#endif //HAVE_PLIST
    printf("  -s, --shsh\t<PATH>\t\tFilepath for shsh (for reading/writing im4m)\n");
    printf("  -m, --im4m\t<PATH>\t\tFilepath for im4m (depending on -e being set)\n");
    printf("  -p, --im4p\t<PATH>\t\tFilepath for im4p (depending on -e being set)\n");
    printf("  -c, --create\t<PATH>\t\tcreates an img4 with the specified im4m, im4p or creates im4p with raw file (last argument)\n");
    printf("  -o, --outfile\t\t\toutput path for extracting im4p payload (-e) or renaming im4p (-n)\n");
    printf("  -t, --type\t\t\tset type for creating IM4P files from raw\n");
    printf("  -d, --desc\t\t\tset desc for creating IM4P files from raw\n");
    printf("  -n, --rename-payload NAME\trename im4p payload (NAME must be exactly 4 bytes)\n");
#ifndef HAVE_PLIST
    printf("UNAVAILABLE: ");
#endif //HAVE_PLIST
    printf("  -v, --verify BUILDMANIFEST\tverify img4, im4m\n");
    printf("      --iv\t\t\tIV  for decrypting payload when extracting (requires -e and -o)\n");
    printf("      --key\t\t\tKey for decrypting payload when extracting (requires -e and -o)\n");
#ifndef HAVE_PLIST
    printf("UNAVAILABLE: ");
#endif //HAVE_PLIST
    printf("      --convert\t\t\tconvert IM4M file to .shsh (use with -s)\n");
    printf("      --compression\t\t\tset compression type when creating im4p from raw file\n");
    
    printf("\n");
}

int main_r(int argc, const char * argv[]) {
    printf("%s\n",version());
    printf("Compiled with plist: %s\n",
#ifdef HAVE_PLIST
    "YES"
#else
    "NO"
#endif
    );
    
    
    const char *lastArg = NULL;
    const char *shshFile = NULL;
    const char *im4mFile = NULL;
    const char *im4pFile = NULL;
    const char *outFile = NULL;
    const char *decryptIv = NULL;
    const char *decryptKey = NULL;
    const char *im4pType = NULL;
    const char *im4pDesc = "Image created by img4tool";
    const char *compressionType = NULL;
#ifdef HAVE_PLIST
    const char *buildmanifestFile = NULL;
#endif //HAVE_PLIST

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
#ifdef HAVE_PLIST
            case 's':
                shshFile = optarg;
                break;
#endif //HAVE_PLIST
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
#ifdef HAVE_PLIST
            case '3':  //convert
                flags |= FLAG_CONVERT;
                break;
#endif //HAVE_PLIST
            case '4': //compression
                compressionType = optarg;
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
#ifdef HAVE_PLIST
            case 'v':
                buildmanifestFile = optarg;
                break;
#endif //HAVE_PLIST
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
            retassure((workingBuffer = readFromFile(lastArg, &workingBufferSize)) && workingBufferSize, "failed to read lastArgFile");
        }
#ifdef HAVE_PLIST
        else if (shshFile){
            retassure((workingBuffer = im4mFormShshFile(shshFile, &workingBufferSize, &generator)), "Failed to read shshFile");
        }
#endif //HAVE_PLIST
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
                
                const char *compression = NULL;
                ASN1DERElement payload = getPayloadFromIM4P(file, decryptIv, decryptKey, &compression);
                saveToFile(outFile, payload.payload(), payload.payloadSize());

                if (compression) {
                    printf("Extracted (and uncompressed %s) IM4P payload to %s\n",compression,outFile);
                }else{
                    printf("Extracted IM4P payload to %s\n",outFile);
                }
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
                retassure(im4mFile, "requested extracting IM4M from SHSH but no output path was given");
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

            im4p = appendPayloadToIM4P(im4p, workingBuffer, workingBufferSize, compressionType);

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
        }
#ifdef HAVE_PLIST
        else if (flags & FLAG_CONVERT){
            plist_t newshsh = NULL;
            plist_t generator = NULL;
            plist_t data = NULL;
            char *xml = NULL;
            uint32_t xmlSize = 0;
            cleanup([&]{
                safeFreeCustom(newshsh,plist_free);
                safeFreeCustom(data,plist_free);
                safeFreeCustom(generator,plist_free);
                safeFree(xml);
            });
            retassure(shshFile, "output path for shsh file required");
            ASN1DERElement im4m(workingBuffer, workingBufferSize);
            
            
            if (isIMG4(im4m)) {
                try {
                    printf("Found IM4R extracting generator: ");
                    char *generatorStr = NULL;
                    cleanup([&]{
                        safeFree(generatorStr);
                    });
                    ASN1DERElement im4r = getIM4RFromIMG4(im4m);
                    ASN1DERElement bncn = getBNCNFromIM4R(im4r);
                    
                    size_t generatorStrSize = bncn.payloadSize()*2+2+1;
                    generatorStr = (char*)malloc(generatorStrSize);
                    strcpy(generatorStr, "0x");
                    std::string octetString = bncn.getStringValue();
                    std::reverse(octetString.begin(), octetString.end());
                    for (char c : octetString) {
                        assure(generatorStrSize-strlen(generatorStr)>=3);
                        snprintf(&generatorStr[strlen(generatorStr)], 3, "%02x",(unsigned char)c);
                    }
                    assure(generator = plist_new_string(generatorStr));
                    printf("ok\n");
                } catch (...) {
                    printf("failed!\n");
                }
                
                im4m = getIM4MFromIMG4(im4m);
            }
            
            retassure(isIM4M(im4m), "Not IM4M file");

            retassure(newshsh = plist_new_dict(),"failed to create new plist dict");
            retassure(data = plist_new_data((const char*)im4m.buf(), im4m.size()),"failed to create plist data from im4m buf");

            plist_dict_set_item(newshsh, "ApImg4Ticket", data); data = NULL;
            if (generator) {
                plist_dict_set_item(newshsh, "generator", generator); generator = NULL;
            }

            retassure((plist_to_xml(newshsh, &xml, &xmlSize),xml), "failed to convert plist to xml");
            saveToFile(shshFile, xml, xmlSize);
            printf("Saved IM4M to %s\n",shshFile);
        } else if (buildmanifestFile){
            //verify
            ASN1DERElement file(workingBuffer, workingBufferSize);
            std::string im4pSHA1;
            std::string im4pSHA384;
                        
            if (isIMG4(file)) {
#ifdef HAVE_CRYPTO
                ASN1DERElement im4p = getIM4PFromIMG4(file);
                file = getIM4MFromIMG4(file);

                printIM4P(im4p.buf(), im4p.size());
                
                im4pSHA1 = getIM4PSHA1(im4p);
                im4pSHA384 = getIM4PSHA384(im4p);
#else
                printf("[WARNING] COMPILED WITHOUT CRYPTO: can not verify im4p payload hash!\n");
#endif //HAVE_CRYPTO
            }

            if (isIM4M(file)) {
                plist_t buildmanifest = NULL;
                cleanup([&]{
                    if (buildmanifest) {
                        plist_free(buildmanifest);
                    }
                });
                std::string im4pElemDgstName;
#ifdef HAVE_CRYPTO
                if (im4pSHA1.size() || im4pSHA384.size()) {
                    //verify payload hash too
                    try {
                        im4pElemDgstName = dgstNameForHash(file, im4pSHA1);
                    } catch (...) {
                        //
                    }
                    try {
                        im4pElemDgstName = dgstNameForHash(file, im4pSHA384);
                    } catch (...) {
                        //
                    }
                    retassure(im4pElemDgstName.size(), "IM4P hash not in IM4M");
                }
#endif //HAVE_CRYPTO
                retassure(buildmanifest = readPlistFromFile(buildmanifestFile),"failed to read buildmanifest");
                
                bool isvalid = isValidIM4M(file, buildmanifest, im4pElemDgstName);
                printf("\n");
                printf("[IMG4TOOL] APTicket is %s!\n", isvalid ? "GOOD" : "BAD");
                if (im4pElemDgstName.size()) {
                    printf("[IMG4TOOL] IMG4 contains an IM4P which is correctly signed by IM4M\n");
                }
                if (generator) {
                    bool isGenValid = isGeneratorValidForIM4M(file,generator);
                    printf("[IMG4TOOL] SHSH2 contains generator %s which is %s for nonce in IM4M!\n", generator, isGenValid ? "GOOD" : "BAD");
                }
                
            }else if (isIM4M(file)){
                reterror("Verify does not make sense on IM4P file!");
            }else{
                reterror("File not recognised");
            }
        }
#endif //HAVE_PLIST
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
            }
#ifdef HAVE_PLIST
            else if (shshFile){
                buf = im4mFormShshFile(shshFile, &bufSize, NULL);
            }
#endif //HAVE_PLIST
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
