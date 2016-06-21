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
#include "img4.h"


static struct option longopts[] = {
    { "help",           no_argument,       NULL, 'h' },
    { "extract",        required_argument,  NULL, 'e' },
    { "all-headers",     no_argument,        NULL, 'a'},
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf("Usage: img4tool [OPTIONS] FILE\n");
    printf("Parses img4 files\n\n");
    printf("Last argument must be an img4 file\n");
    
    printf("  -h, --help                prints usage information\n");
    printf("  -e, --extract FILEPATH    extracts data to file\n");
    printf("  -a, --all-headers         print all headers of all IM4Ps\n");
    printf("\n");
}

int main(int argc, const char * argv[]) {
    
    int optindex = 0;
    int opt = 0;
    
    char *img4FilePath = 0;
    char *extractedFilePath = 0;
    
    int extract_flag = 0;
    int allHeaders_flag = 0;
    
    if (argc == 1){
        cmd_help();
        return -1;
    }
    
    while ((opt = getopt_long(argc, (char* const *)argv, "e:ha", longopts, &optindex)) > 0) {
        switch (opt) {
            case 'h': // long option: "help"; can be called as short option
                cmd_help();
                return 0;
            case 'e': // long option: "extract"; can be called as short option
                extract_flag = 1;
                extractedFilePath = optarg;
                break;
            case 'a': // long option: "all-headers"; can be called as short option
                allHeaders_flag = 1;
                break;
            default:
                 cmd_help();
                 return -1;
        }
    }
    
    img4FilePath = malloc(strlen(argv[argc-1])+1);
    strcpy(img4FilePath, argv[argc-1]);
    
    
    FILE *f = fopen(img4FilePath, "r");
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char * buf = malloc(size);
    fread(buf, size, 1, f);
    
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
    char *sname;
    getSequenceName(buf, &sname, 0);
    if (strncmp("IMG4", sname, 4) == 0){
        printElemsInIMG4(buf);
        uint64_t ecid = getECIDFromIM4M(getIM4MFromIMG4(buf));
        printf("ecid=%lu\n",ecid);
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
    free(img4FilePath);
    free(extractedFilePath);
    
    return 0;
}
