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

char *im4mFormShshFile(char *shshfile){
    FILE *f = fopen(shshfile,"rb");
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
    
    plist_free(shshplist);
    
    return im4m;
}

static struct option longopts[] = {
    { "help",           no_argument,       NULL, 'h' },
    { "extract",        optional_argument,  NULL, 'e' },
    { "create-img4",     required_argument, NULL, 'c'},
    { "all-headers",     no_argument,        NULL, 'a'},
    { "im4m",           required_argument,        NULL, 'm'},
    { "shsh",           required_argument,        NULL, 's'},
    { "im4p",           required_argument,        NULL, 'p'},
    { "im4r",           optional_argument,        NULL, 'r'},
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf("Usage: img4tool [OPTIONS] FILE\n");
    printf("Parses img4 or im4p files\n\n");
    printf("Last argument must be an img4/im4p file\n");
    
    printf("  -h, --help                prints usage information\n");
    printf("  -e, --extract FILEPATH    extracts data to file (payload to file specified, im4m, im4p and im4r to files specified by the argument)\n");
    printf("  -c, --create-img4 FILEPATH creates an img4 with the specified im4m, im4p and optionally an im4r(see options below)");
    printf("  -a, --all-headers         print all headers of all IM4Ps\n");
    printf("  -m, --im4m FILEPATH       Filepath for im4m (reading or writing, depending on Option)\n");
    printf("  -s, --shsh FILEPATH       Filepath for shsh (for reading im4m)\n");
    printf("  -p, --im4p FILEPATH       Filepath for im4p (reading or writing, depending on Option)\n");
    printf("  -r, --im4r Nonce          Nonce for im4r (with hexadecimal encoding) reading or printing\n");
    printf("\n");
}

int main(int argc, const char * argv[]) {
    
    int optindex = 0;
    int opt = 0;
    
    char *img4FilePath = 0;
    char *extractedFilePath = 0;
    char *createdImg4FilePath = 0;
    char *im4mFilePath = 0;
    char *shshFilePath = 0;
    char *im4pFilePath = 0;
    char *im4rNonce = 0;
    
    
    int extract_flag = 0;
    int create_flag = 0;
    int printNonceFlag = 0;
    int allHeaders_flag = 0;
    
    if (argc == 1){
        cmd_help();
        return -1;
    }
    
    while ((opt = getopt_long(argc, (char* const *)argv, "e:c:m:p:r:s:ha", longopts, &optindex)) > 0) {
        switch (opt) {
            case 'h': // long option: "help"; can be called as short option
                cmd_help();
                return 0;
            case 'e': // long option: "extract"; can be called as short option
                extract_flag = 1;
                extractedFilePath = optarg;
                break;
            case 'c': // long option: "create-img4"; can be called as short option
                create_flag = 1;
                createdImg4FilePath = optarg;
                break;
            case 'a': // long option: "all-headers"; can be called as short option
                allHeaders_flag = 1;
                break;
            case 'm': // long option: "im4m"; can be called as short option
                im4mFilePath = optarg;
                break;
            case 's': // long option: "shsh"; can be called as short option
                shshFilePath = optarg;
                break;
            case 'p': // long option: "im4p"; can be called as short option
                im4pFilePath = optarg;
                break;
            case 'r': // long option: "im4r"; can be called as short option
                im4rNonce = optarg;
                printNonceFlag = 1;
                break;
            default:
                 cmd_help();
                 return -1;
        }
    }
    
    
    
    // TODO: Use function to determine wether you have an img4 or only an im4p
    // if(IS IM4P)
    //     if (extract_flag)
    //         EXTRACT FILE
    //     else
    //         printIM4P(buf,size);
    //
    // else
    //      if (extract_flag)
    //          EXTRACT FILES
    //      else if(allHeaders_flag)
    //          print all header data of all im4ps
    //      else
    //          print all im4p names
    
    // CHECK IF WE HAVE AN IMG4::: if (!sequenceHasName(buf, "IMG4")) reterror("not img4 sequcence\n");
    
    if (create_flag && extract_flag) {
        printf("ERROR: Invalid options! You can either create an img4 or extract from an existing one!\n");
        return -1;
    }
    
    if (create_flag) {
        if (!im4pFilePath) {
            printf("ERROR: im4p file path needed to create an img4!\n");
            return -1;
        }
        if (!im4mFilePath && !shshFilePath) {
            printf("ERROR: im4m file path needed to create an img4!\n");
            return -1;
        }
        if (!createdImg4FilePath) {
            printf("ERROR: img4 file path needed to write the result!\n");
            return -1;
        }
        
        char * im4p;
        char * im4m;
        
        // Read im4p to buffer
        {
            FILE *f = fopen(im4pFilePath, "r");
            fseek(f, 0, SEEK_END);
            size_t size = ftell(f);
            fseek(f, 0, SEEK_SET);
            
            im4p = malloc(size);
            fread(im4p, size, 1, f);
            fclose(f);
        }
        // Read im4m to buffer
        if (shshFilePath) {
            im4m = im4mFormShshFile(shshFilePath);
        }else{
            FILE *f = fopen(im4mFilePath, "r");
            fseek(f, 0, SEEK_END);
            size_t size = ftell(f);
            fseek(f, 0, SEEK_SET);
            
            im4m = malloc(size);
            fread(im4m, size, 1, f);
            fclose(f);
        }
        
        // Create img4 and write it to file
        {
            size_t s = 0;
            char * img4new = makeIMG4WithIM4PAndIM4M(im4p, im4m,&s);
            FILE *f = fopen(createdImg4FilePath, "w");
            fwrite(img4new, s, 1, f);
            fclose(f);
        }
        return 0;
        
    }
    
    // read img4 from disk to print and extract data
    
    img4FilePath = malloc(strlen(argv[argc-1])+1);
    strcpy(img4FilePath, argv[argc-1]);
    
    
    FILE *f = fopen(img4FilePath, "r");
    if (!f) {
        printf("ERROR: Unable to open %s\n",img4FilePath);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char * buf = malloc(size);
    fread(buf, size, 1, f);
    if (extract_flag) {
        if (sequenceHasName(buf, "IMG4")) {
            // Extract an img4
            if (extractedFilePath) {
                // Find im4p payload and write it to the file
                int elemsInIMG4 = asn1ElementsInObject(buf);
                // Go through all elems one by one until you find an im4p
                for (int i=1;i<elemsInIMG4; i++) {
                    char* elem = (char*)asn1ElementAtIndex(buf, i);
                    if (sequenceHasName(elem, "IM4P")){
                        // Write im4p to file
                        extractFileFromIM4P(elem, extractedFilePath);
                        break;
                    }
                    
                }
            }
            if (im4mFilePath) {
                // Find im4m inside the img4 and write it to the file
                extractElementFromIMG4(buf, "IM4M", im4mFilePath);
            }
            if (im4pFilePath) {
                extractElementFromIMG4(buf, "IM4P", im4pFilePath);
            }
        }
    }
    
    char *sname;
    getSequenceName(buf, &sname, 0);
    if (strncmp("IMG4", sname, 4) == 0){
        printElemsInIMG4(buf);
        
        
        printf("im4m extraction error=%d\n",extractElementFromIMG4(buf, "IM4M", "apticket.im4m"));
        uint64_t ecid = getECIDFromIM4M(getIM4MFromIMG4(buf));
        printf("ecid=%llu\n",ecid);
        
        if (extract_flag) printf("todo extracting from img4\n");
    }
    else {
        printIM4P(buf);
        if (extract_flag) {
            int ex = extractFileFromIM4P(buf, extractedFilePath);
            printf("Extracting payload from IMP4 %s\n", (!ex) ? "SUCCEEDED" : "FAILED");
        }
    }
    
    
    
    free(buf);
    fclose(f);
    
    // free arguments
    /*free(img4FilePath);
    free(extractedFilePath);*/
    
    return 0;
}
