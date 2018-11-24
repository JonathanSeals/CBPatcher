//
//  CBPatcher.c
//  CBPatcher
//
//  Created by JonathanSeals on 11/18/18.
//  Copyright © 2018 JonathanSeals. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "CBPUtils.h"
#include "CBPatch.h"

int main(int argc, char **argv) {
    
    if (argc < 4) {
        printf("Missing args (cbpatcher infile outfile version)\n");
        return -1;
    }
    
    char *fileName = argv[1];
    
    void *fileBuf = 0;
    
    size_t fileLen = 0;
    
    int ret = openFile(fileName, &fileLen, &fileBuf);
    
    if (ret) {
        printf("Failed to open %s\n", fileName);
        return -1;
    }
    
    char *versionNum = argv[3];
    
    ret = kernPat(fileBuf, fileLen, versionNum);
    
    if (ret) {
        printf("Failed to patch kernel\n");
        free(fileBuf);
        return -1;
    }
    
    printf("Kernel patched successfully\n");
    
    FILE *outFile = fopen(argv[2], "w");
    fwrite(fileBuf, fileLen, 1, outFile);
    fflush(outFile);
    fclose(outFile);
    
    free(fileBuf);
    
    return 0;
}
