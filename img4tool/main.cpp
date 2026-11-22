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
#include <sys/stat.h>
#include <fcntl.h>


#include <libgeneral/macros.h>
#include <libgeneral/Mem.hpp>
#include <libgeneral/Utils.hpp>
#include <libgeneral/ByteOrder.hpp>
#include "../include/img4tool/img4tool.hpp"

#ifdef HAVE_PLIST
#include <plist/plist.h>
#endif //HAVE_PLIST

#ifdef HAVE_LIBFWKEYFETCH
#include <libfwkeyfetch/libfwkeyfetch.hpp>
#endif //HAVE_LIBFWKEYFETCH

using namespace tihmstar::img4tool;
using namespace std;

#define FLAG_ALL        (1 << 0)
#define FLAG_IM4PONLY   (1 << 1)
#define FLAG_EXTRACT    (1 << 2)
#define FLAG_CREATE     (1 << 3)
#define FLAG_RENAME     (1 << 4)
#define FLAG_CONVERT    (1 << 5)
#define FLAG_VERIFY     (1 << 6)

#define IMG4TOOL_DEFAULT_CREATE_DESCRIPTION "Image created by img4tool"

static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "print-all",      no_argument,        NULL, 'a' },
    { "create",         required_argument,  NULL, 'c' },
    { "desc",           required_argument,  NULL, 'd' },
    { "extract",        no_argument,        NULL, 'e' },
    { "generator",      required_argument,  NULL, 'g' },
    { "im4p-only",      no_argument,        NULL, 'i' },
    { "im4m",           required_argument,  NULL, 'm' },
    { "rename-payload", required_argument,  NULL, 'n' },
    { "outfile",        required_argument,  NULL, 'o' },
    { "im4p",           required_argument,  NULL, 'p' },
    { "copy-payp",      required_argument,  NULL, 'P' },
    { "type",           required_argument,  NULL, 't' },

    { "iv",             required_argument,  NULL,  0  },
    { "key",            required_argument,  NULL,  0  },
    { "compression",    required_argument,  NULL,  0  },
    { "kbag",           required_argument,  NULL,  0  },
    { "impl-tz0s",      required_argument,  NULL,  0  },

#ifdef HAVE_LIBFWKEYFETCH
    { "fetch",          no_argument,        NULL, 'f' },
#endif //HAVE_LIBFWKEYFETCH
#ifdef HAVE_PLIST
    { "shsh",           required_argument,  NULL, 's' },
    { "verify",         optional_argument,  NULL, 'v' },
    { "convert",        no_argument,        NULL,  0  },
#endif //HAVE_PLIST
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf(
           "Usage: img4tool [OPTIONS] FILE\n"
           "Parses img4, im4p, im4m files\n\n"
           "  -h, --help\t\t\tprints usage information\n"
           "  -a, --print-all\t\tprint everything from im4m\n"
           "  -e, --extract\t\t\textracts im4m/im4p payload\n"
           "  -i, --im4p-only\t\tprint only im4p\n"
           "  -m, --im4m\t\t<PATH>\tFilepath for im4m (depending on -e being set)\n"
           "  -p, --im4p\t\t<PATH>\tFilepath for im4p (depending on -e being set)\n"
           "  -P, --copy-payp\t\t<PATH>\tCopy PAYP from im4p, when creating new im4p\n"
           "  -c, --create\t\t<PATH>\tcreates an img4 with the specified im4m, im4p or creates im4p with raw file (last argument)\n"
           "  -o, --outfile\t\t\toutput path for extracting im4p payload (-e) or renaming im4p (-n)\n"
           "  -t, --type\t\t\tset type for creating IM4P files from raw\n"
           "  -d, --desc\t\t\tset desc for creating IM4P files from raw\n"
           "  -n, --rename-payload\t<NAME>\trename im4p payload (NAME must be exactly 4 bytes)\n"
           "  -g, --generator\t<GEN>\tAdd generator to img4 (eg. 0x726174736d686974)\n"
           "      --iv\t\t\tIV  for decrypting payload when extracting (requires -e and -o)\n"
           "      --key\t\t\tKey for decrypting payload when extracting (requires -e and -o)\n"
           "      --kbag\t\t\tKBag for re-encrypting im4p (requires --iv and --key)\n"
           "      --compression\t\tset compression type when creating im4p from raw file\n"
           "      --impl-tz0s <size>\t\tCreate impl-sepidesc with tzs0 element\n"
#ifdef HAVE_LIBFWKEYFETCH
           "[libfwkeyfetch]\n"
#else
           "[libfwkeyfetch] (UNAVAILABLE)\n"
#endif //HAVE_LIBFWKEYFETCH
           "  -f, --fetch\t\t\tTry to get IV/KEY based on KBAG from fwkeydb\n"

#ifdef HAVE_PLIST
           "[plist]\n"
#else
           "[plist] (UNAVAILABLE)\n"
#endif //HAVE_PLIST
           "  -s, --shsh\t\t<PATH>\tFilepath for shsh (for reading/writing im4m)\n"
           "  -v, --verify\t<BUILDMANIFEST>\tverify img4, im4m\n"
           "      --convert\t\t\tconvert IM4M file to .shsh (use with -s)\n"
           "\n"
           
           "Features:\n"
#ifdef HAVE_LIBFWKEYFETCH
           "libfwkeyfetch: yes\n"
#else
           "libfwkeyfetch: no\n"
#endif //HAVE_LIBFWKEYFETCH

#ifdef HAVE_PLIST
           "plist: yes\n"
#else
           "plist: no\n"
#endif //HAVE_PLIST

#ifdef HAVE_OPENSSL
           "openssl: yes\n"
#else
           "openssl: no\n"
#endif //HAVE_OPENSSL
           
#ifdef HAVE_LIBCOMPRESSION
           "bvx2: yes\n"
#else
           "bvx2: no\n"
#endif //HAVE_LIBCOMPRESSION
           "\n"
           );
}

void saveToFile(const char *filePath, const void *buf, size_t bufSize){
    if (strcmp(filePath, "-") == 0) {
        write(STDERR_FILENO, buf, bufSize);
    }else{
        tihmstar::writeFile(filePath, buf, bufSize);
    }
}

MAINFUNCTION
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
    const char *encryptKBAG = NULL;
    const char *im4pType = NULL;
    const char *im4pDesc = NULL;
    const char *compressionType = NULL;
    const char *copyPayp = NULL;
#ifdef HAVE_PLIST
    const char *buildmanifestFile = NULL;
#endif //HAVE_PLIST

    int optindex = 0;
    int opt = 0;
    long flags = 0;

    tihmstar::Mem workingBuf;
    char *generator = NULL;
    uint64_t bnch = 0;
    bool fetchKeys = false;
    
    cleanup([&]{
        safeFree(generator);
    });
    
    std::vector<ASN1DERElement> sepidescImplElements;

    while ((opt = getopt_long(argc, (char* const *)argv, "hac:d:efg:im:n:o:p:P:s:t:v::", longopts, &optindex)) >= 0) {
        switch (opt) {
            case 0: //long opts
            {
                std::string curopt = longopts[optindex].name;
                
#ifdef HAVE_PLIST
                if (curopt == "convert") {
                    flags |= FLAG_CONVERT;
                }else
#endif //HAVE_PLIST
                if (curopt == "compression") {
                    compressionType = optarg;
                }else if (curopt == "iv") {
                    decryptIv = optarg;
                }else if (curopt == "key") {
                    decryptKey = optarg;
                }else if (curopt == "kbag") {
                    encryptKBAG = optarg;
                }else if (curopt == "impl-tz0s") {
                    uint32_t tz0s = (uint32_t)tihmstar::parseNum(optarg);
                    ASN1DERElement etz0s;
                    {
                        ASN1DERElement etz0s_seq{{ASN1DERElement::TagSEQUENCE,1,0}, NULL, 0};
                        {
                            ASN1DERElement e{{ASN1DERElement::TagIA5String,0,0}, "tz0s", 4};
                            etz0s_seq += e;
                        }
                        {
                            uint32_t be_tz0s = cnvHTOBE(tz0s);
                            ASN1DERElement e{{ASN1DERElement::TagINTEGER,0,0}, &be_tz0s, sizeof(be_tz0s)};
                            etz0s_seq += e;
                        }
                        etz0s = genPrivTagForNumberWithPayload('tz0s', etz0s_seq);
                    }
                    sepidescImplElements.push_back(etz0s);
                }else{
                    error("Unknoen curopt '%s'",curopt.c_str());
                    return -1;
                }
                break;
            }
                
            case 'h':
                cmd_help();
                return 0;
            case 'a':
                flags |= FLAG_ALL;
                break;
            case 'c':
                flags |= FLAG_CREATE;
                retassure(!(flags & FLAG_EXTRACT), "Invalid command line arguments. can't extract and create at the same time");
                retassure(!outFile, "Invalid command line arguments. outFile already set!");
                outFile = optarg;
                break;
            case 'd':
                im4pDesc = optarg;
                break;
            case 'e':
                retassure(!(flags & FLAG_CREATE), "Invalid command line arguments. can't extract and create at the same time");
                flags |= FLAG_EXTRACT;
                break;
            case 'f':
                fetchKeys = true;
                break;
            case 'g': //generator
                bnch = strtoull(optarg, NULL, 16);
                retassure(bnch, "Failed to set generator!");
                break;
            case 'i':
                flags |= FLAG_IM4PONLY;
                break;
            case 'm':
                im4mFile = optarg;
                break;
            case 'n': //rename-payload
                retassure(!im4pType, "Invalid command line arguments. im4pType already set!");
                im4pType = optarg;
                flags |= FLAG_RENAME;
                break;
            case 'o':
                retassure(!outFile, "Invalid command line arguments. outFile already set!");
                outFile = optarg;
                break;
            case 'p':
                im4pFile = optarg;
                break;
            case 'P':
                copyPayp = optarg;
                break;
#ifdef HAVE_PLIST
            case 's':
                shshFile = optarg;
                break;
#endif //HAVE_PLIST
            case 't':
                retassure(!(flags & FLAG_RENAME), "Invalid command line arguments. can't rename and create at the same time");
                retassure(!im4pType, "Invalid command line arguments. im4pType already set!");
                im4pType = optarg;
                break;
#ifdef HAVE_PLIST
            case 'v':
                flags |= FLAG_VERIFY;
                buildmanifestFile = optarg;
                break;
#endif //HAVE_PLIST
            default:
                cmd_help();
                return -1;
        }
    }
#ifdef HAVE_LIBFWKEYFETCH
    tihmstar::libfwkeyfetch::fw_key fwKey = {};
#endif //HAVE_LIBFWKEYFETCH
    
    if (outFile && strcmp(outFile, "-") == 0) {
        int s_out = -1;
        int s_err = -1;
        cleanup([&]{
            safeClose(s_out);
            safeClose(s_err);
        });
        s_out = dup(STDOUT_FILENO);
        s_err = dup(STDERR_FILENO);
        dup2(s_out, STDERR_FILENO);
        dup2(s_err, STDOUT_FILENO);
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
            if (strcmp(lastArg, "-") == 0){
                char cbuf[0x1000] = {};
                ssize_t didRead = 0;
                
                while ((didRead = read(STDIN_FILENO, cbuf, sizeof(cbuf))) > 0) {
                    workingBuf.append(cbuf, didRead);
                }
                
            }else{
                workingBuf = tihmstar::readFile(lastArg);
            }
        }
#ifdef HAVE_PLIST
        else if (shshFile){
            try {
                workingBuf = im4mFormShshFile(shshFile, &generator);
            } catch (...) {
                reterror("Failed to read shshFile");
            }
        }
#endif //HAVE_PLIST
    }

    if (workingBuf.size()) {
        if (flags & FLAG_EXTRACT) {
            //extract
            bool didExtract = false;
            ASN1DERElement file(workingBuf.data(), workingBuf.size());

            if (outFile) {
                const char *compression = NULL;
                ASN1DERElement payload;
                //check for payload extraction
                if (isIMG4(file)) {
                    file = getIM4PFromIMG4(file);
                } else if (!isIM4P(file)){
                    reterror("File not recognised");
                }
                
                if (fetchKeys && (!decryptIv || !strlen(decryptIv)) && (!decryptKey || !strlen(decryptKey))) {
#ifndef HAVE_LIBFWKEYFETCH
                    reterror("Compiled without libfwkeyfetch");
#else
                    for (int i=1; i>0; i++) {
                        std::string kbagstr;
                        try {
                            tihmstar::Mem kbag = getKBAG(file, i);
                            for (int z=0; z<kbag.size(); z++) {
                                char cur[4] = {};
                                snprintf(cur, sizeof(cur), "%02x",kbag.data()[z]);
                                kbagstr += cur;
                            }
                        } catch (tihmstar::exception &e) {
#ifdef DEBUG
                            e.dump();
#endif
                            warning("Failed to get KBAG at index %d, falling back to extraction without keys!",i);
                            goto failedToFindKeys;
                        }
                        try {
                            info("Fetching keys for KBAG %d",i);
                            fwKey = tihmstar::libfwkeyfetch::getFirmwareKeyForKBAG(kbagstr);
                        } catch (tihmstar::exception &e) {
#ifdef DEBUG
                            e.dump();
#endif
                            error("Failed to fetch IV/Key for KBAG %d (%s), retrying with next...",i,kbagstr.c_str());
                            continue;
                        }
                        decryptIv = fwKey.iv;
                        decryptKey = fwKey.key;
                        info("Found IV: %s KEY: %s", decryptIv, decryptKey);
                        break;
                    }
#endif
                failedToFindKeys:;
                }
                payload = getPayloadFromIM4P(file, decryptIv, decryptKey, &compression);
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
            ASN1DERElement im4p;
            if (sepidescImplElements.size()) {
                ASN1DERElement eimpl_seq{{ASN1DERElement::TagSEQUENCE,1,0}, NULL, 0};
                {
                    ASN1DERElement e{{ASN1DERElement::TagIA5String,0,0}, "impl", 4};
                    eimpl_seq += e;
                }
                {
                    ASN1DERElement set{{ASN1DERElement::TagSET,1,0}, NULL, 0};
                    for (auto e : sepidescImplElements) {
                        set += e;
                    }
                    eimpl_seq += set;
                }
                ASN1DERElement impl = genPrivTagForNumberWithPayload('impl', eimpl_seq);
                std::string implhex;
                implhex.resize(impl.size()*2+1);
                for (int i=0; i<impl.size(); i++) {
                    snprintf((char*)&implhex.data()[i*2], 3, "%02x",((uint8_t*)impl.buf())[i]);
                }
                im4p = getEmptyIM4PContainer(im4pType, implhex.c_str());
            }else{
                if (!im4pDesc) im4pDesc = IMG4TOOL_DEFAULT_CREATE_DESCRIPTION;
                im4p = getEmptyIM4PContainer(im4pType, im4pDesc);
            }

            im4p = appendPayloadToIM4P(im4p, workingBuf.data(), workingBuf.size(), compressionType);
            if (encryptKBAG && decryptIv && decryptKey) {
                im4p = encryptIM4P(im4p, decryptIv, decryptKey, encryptKBAG);
                info("Encrypted IM4P with:\n"
                     "\tIV: '%s'\n"
                     "\tKEY: '%s'\n"
                     "\tKBAG: '%s'", decryptIv, decryptKey, encryptKBAG);
            }

            if (copyPayp) {
                auto paypF = tihmstar::readFile(copyPayp);
                ASN1DERElement payp(paypF.data(), paypF.size());
                if (isIMG4(payp)){
                    payp = getIM4PFromIMG4(payp);
                }
                if (im4pContainsPAYP(payp)) {
                    payp = getPAYPFromIM4P(payp);
                    im4p = appendPAYPToIM4P(im4p, payp);
                }else{
                    warning("Template IM4P does not contain PAYP");
                }
            }
            
            saveToFile(outFile, im4p.buf(), im4p.size());
            printf("Created IM4P file at %s\n",outFile);
        } else if (flags & FLAG_RENAME){
            retassure(im4pType, "typen required");
            retassure(outFile, "outputfile required");

            ASN1DERElement img4;
            ASN1DERElement im4p(workingBuf.data(), workingBuf.size());
            string seqName = getNameForSequence(workingBuf.data(), workingBuf.size());
            if (seqName == "IMG4"){
                img4 = im4p;
                im4p = getIM4PFromIMG4(img4);
                seqName = getNameForSequence(im4p.buf(), im4p.size());
            }
            retassure(seqName == "IM4P","File not an IM4P");
            im4p = renameIM4P(im4p, im4pType);
            if (img4.size() > 10) {
                auto newimg4 = getEmptyIMG4Container();
                newimg4 = appendIM4PToIMG4(newimg4, im4p);
                //
                im4p = {};
                try {im4p = getIM4MFromIMG4(img4);} catch (...) {}
                if (im4p.size() > 10) newimg4 = appendIM4MToIMG4(newimg4, im4p);
                //
                im4p = {};
                try {im4p = getIM4RFromIMG4(img4);} catch (...) {}
                if (im4p.size() > 10) newimg4 = appendIM4RToIMG4(newimg4, im4p);
                im4p = newimg4;
            }
            saveToFile(outFile, im4p.buf(), im4p.size());
            if (img4.size() > 10) {
                printf("Saved new renamed IMG4 to %s\n",outFile);
            }else{
                printf("Saved new renamed IM4P to %s\n",outFile);
            }
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
            ASN1DERElement im4m(workingBuf.data(), workingBuf.size());
            
            
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
        } else if (flags & FLAG_VERIFY){
            //verify
            ASN1DERElement file(workingBuf.data(), workingBuf.size());
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
                if (buildmanifestFile){
                    retassure(!plist_read_from_file(buildmanifestFile, &buildmanifest, NULL), "failed to read buildmanifest");
                }
                
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
                
            }else if (isIM4P(file)){
                reterror("Verify does not make sense on IM4P file!");
            }else{
                reterror("File not recognised");
            }
        }
#endif //HAVE_PLIST
        else {
            //printing only
            string seqName = getNameForSequence(workingBuf.data(), workingBuf.size());
            if (seqName == "IMG4") {
                printIMG4(workingBuf.data(), workingBuf.size(), flags & FLAG_ALL, flags & FLAG_IM4PONLY);
            } else if (seqName == "IM4P"){
                printIM4P(workingBuf.data(), workingBuf.size());
            } else if (seqName == "IM4M"){
                printIM4M(workingBuf.data(), workingBuf.size(), flags & FLAG_ALL);
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
            tihmstar::Mem wbuf = tihmstar::readFile(im4pFile);
            ASN1DERElement im4p(wbuf.data(),wbuf.size());

            img4 = appendIM4PToIMG4(img4, im4p);
        }

        if (im4mFile || shshFile){
            tihmstar::Mem obuf;
            
            if (im4mFile) {
                obuf = tihmstar::readFile(im4mFile);
            }
#ifdef HAVE_PLIST
            else if (shshFile){
                obuf = im4mFormShshFile(shshFile, NULL);
            }
#endif //HAVE_PLIST
            assure(obuf.size());
            ASN1DERElement im4m(obuf.data(),obuf.size());
            img4 = appendIM4MToIMG4(img4, im4m);
        }
        
        if (bnch){
            img4 = appendIM4RToIMG4(img4, getIM4RFromGenerator(bnch));
        }

        saveToFile(outFile, img4.buf(), img4.size());
        printf("Created IMG4 file at %s\n",outFile);
    }
    else{
        reterror("No working buffer");
    }

    return 0;
}
