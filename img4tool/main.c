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

//TODO: Parse arguments
static struct option longopts[] = {
    { "help",           no_argument,       NULL, 'h' },
    { "extract",        required_argument,  NULL, 'e' },
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf("Usage: img4tool [OPTIONS] FILE\n");
    printf("Parses img4 files\n\n");
    printf("Last argument must be an img4 file\n");
    
    printf("  -h, --help                prints usage information\n");
    printf("  -e, --extract FILEPATH    extracts data to file\n");
    printf("\n");
}


int main(int argc, const char * argv[]) {
    
    int optindex = 0;
    int opt = 0;
    
    char *img4FilePath = 0;
    char *extractedFilePath = 0;
    
    if (argc == 1){
        cmd_help();
        return -1;
    }
    
    while ((opt = getopt_long(argc, (char* const *)argv, "e:h", longopts, &optindex)) > 0) {
        switch (opt) {
            case 'h': // long option: "help"; can be called as short option
                cmd_help();
                return 0;
            case 'e': // long option: "extract"; can be called as short option
                extractedFilePath = optarg;
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
    
    printElemsInIMG4(buf,size);
    
    free(buf);
    fclose(f);
    
    
    return 0;
}
