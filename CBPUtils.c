//
//  CBPUtils.c
//  CBPatcher
//
//  Created by JonathanSeals on 11/18/18.
//  Copyright © 2018 JonathanSeals. All rights reserved.
//

#include "CBPUtils.h"

/* Get a buffer from a file name. Returns -1 on failure, 0 on success */
int openFile(char *fileName, size_t *fileSize, void **outBuf) {
    
    /* Try to open the file */
    FILE *fd = fopen(fileName, "r");
    
    /* Make sure it opens successfully */
    if (!fd) {
        printf("Error opening %s\n", fileName);
        return -1;
    }
    
    /* Seek to end of file descriptor */
    fseek(fd, 0, SEEK_END);
    
    /* Get the current position */
    *fileSize = ftell(fd);
    
    /* Rewind */
    fseek(fd, 0, SEEK_SET);
    
    /* File must be at least 0x800 bytes, and at most 100MB */
    if (*fileSize < 0x800 || *fileSize > (100*1000*1000)) {
        printf("Suspicious file length %zu, refusing to malloc\n", *fileSize);
        fclose(fd);
        return -1;
    }
    
    /* Allocate the buffer */
    *outBuf = (void*)malloc(*fileSize);
    
    if (!*outBuf) {
        printf("Error allocating file buffer\n");
        fclose(fd);
        return -1;
    }
    
    /* Zero the buffer */
    bzero(*outBuf, *fileSize);
    
    /* Read in the file */
    fread(*outBuf, *fileSize, 1, fd);
    
    /* Close the file descriptor */
    fclose(fd);
    
    return 0;
}
