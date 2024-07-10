#include "add/inputs.h"
#include "chk/pkgchk.h"
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**
 * Reads through a label when reading from bpkg
 * files (allows us to ignore the label)
 * @param fp, pointer to file object
 */
void read_label(FILE *fp){
	while(1) {
        // Get next character
        char c = fgetc(fp);

        // If we reach a colon, we've read through the label
        if(c == ':')
            break;
    }
}


/**
 * Indicates whether an ident is valid by checking
 * that each character is a hexadecimal digit and
 * that the length is no less than 1024 bytes
 * @param ident, the ident to be checked
 */
int is_valid_ident(char* ident) {
    // Create a variable that stores the result of hex check
    int res;        

    for(int i = 0; i < IDENT_SIZE - 2; i ++) {
        res = isxdigit(ident[i]);
        if((res == 0) | (ident[i] == '\0'))
            return 0;
    }

    return 1;
}


/**
 * Indicates whether a hash is valid by checking
 * that each character is a hexadecimal digit and
 * that the length is no less than 64 bytes
 * @param hash, the hash to be checked
 */
int is_valid_hash(char* hash) {
    // Create a variable that stores the result of hex check
    int res;        

    for(int i = 0; i < HASH_SIZE - 1; i ++) {
        res = isxdigit(hash[i]);
        if((res == 0) | (hash[i] == '\0'))
            return 0;
    }

    return 1;
}


/**
 * Checks to see if data contains characters
 * @param data, the data to be checked
 */
int is_empty(char *data) {
    // Check if pointer is pointing to any data
    if(data == NULL) {
        return 1;
    }

    // If there's addtional data, make sure it's not a newline character
    while(*data) {
        if(*data != '\n') {
            return 0;
        }
        data++;
    }

    // If it was whitespace or newline, return 1 -> empty
    return 1;
}


/**
 * Checks if a bpkg file has a valid format
 * @param path, path to bpkg file
 */
int is_valid_bpkg(const char* path) {
    FILE *fp = fopen(path, "r");
    
    if(fp == NULL)
        return 0;
    // Check if file empty
    else {
        // Go to the end of the file and read the size in bytes
        fseek(fp, 0, SEEK_END);
        
        // If file is empty
        if (ftell(fp) == 0) {
            fclose(fp);
            return 0;
        // Else go back to beginning of file and continue
        } else
            fseek(fp, 0, SEEK_SET);
    }

    // Allocate memory for bpkg object
    struct bpkg_obj* obj = (struct bpkg_obj*) malloc(sizeof(struct bpkg_obj));

    char ident[] = "ident:";

    // Check label
    for(int i = 0; i < 6; i++) {
        if(fgetc(fp) != ident[i])
            return 0;
    }

    // Read in ident and assign to struct field
    int res = fscanf(fp, IDENT_READ, obj->ident);

    // Check that ident is valid
    if(!is_valid_ident(obj->ident))
        return 0;

    // Check newline
    if(fgetc(fp) != '\n')
        return 0;

    if(res <= 0) {
        free(obj);
        return 0;
    }

    char filename[] = "filename:";

    for(int i = 0; i < 9; i++) {
        if(fgetc(fp) != filename[i])
            return 0;
    }

    // Read in filename and assign to struct field
    res = fscanf(fp, FILENAME_READ, obj->filename);

    if(res <= 0) {
        free(obj);
        return 0;
    }

    if(fgetc(fp) != '\n')
        return 0;

    char size[] = "size:";

    for(int i = 0; i < 5; i++) {
        if(fgetc(fp) != size[i])
            return 0;
    }

    // Read in size and assign to struct field
    res = fscanf(fp, "%u", &(obj->size));

    if(res <= 0) {
        printf("1\n");
        free(obj);
        return 0;
    }

    if(fgetc(fp) != '\n')
        return 0;

    char nhashes[] = "nhashes:";

    for(int i = 0; i < 8; i++) {
        if(fgetc(fp) != nhashes[i])
            return 0;
    }

    // Read in nhashes and assign to struct field
    res = fscanf(fp, "%u", &(obj->nhashes));

    if(res <= 0) {
        free(obj);
        return 0;
    }

    if(fgetc(fp) != '\n')
        return 0;

    char hashes[] = "hashes:";

    for(int i = 0; i < 7; i++) {
        if(fgetc(fp) != hashes[i])
            return 0;
    }

    if(fgetc(fp) != '\n')
        return 0;

    // Allocate memory for an array of char pointers to store hashes
    obj->hashes = (char**) malloc(sizeof(char*) * obj->nhashes);

    for(int i = 0; i < obj->nhashes; i++) {
        // Read passed the tab character
        if(fgetc(fp) != 9)
            return 0;
        
        // Allocate memory for a single hash, set characters to null, and assign it a hash from file
        obj->hashes[i] = (char*) malloc(sizeof(char) * HASH_SIZE);
        memset(obj->hashes[i], '\0', sizeof(char) * HASH_SIZE);
        res = fscanf(fp, HASH_READ, obj->hashes[i]);

        // Check that data is read and the hash is valid
        if((res <= 0) | (!is_valid_hash(obj->hashes[i]))) {
            for(int j = 0; j <= i; j++) 
                free(obj->hashes[j]);

            free(obj->hashes);

            free(obj);
            return 0;
        }

        if(fgetc(fp) != '\n')
            return 0;
    }

    char nchunks[] = "nchunks:";

    for(int i = 0; i < 8; i++) {
        if(fgetc(fp) != nchunks[i])
            return 0;
    }

    // Read in nchunks and assign to struct field
    res = fscanf(fp, "%u", &(obj->nchunks));

    if(res <= 0) {
        for(int i = 0; i <= obj->nhashes; i++) 
            free(obj->hashes[i]);

        free(obj->hashes);
        
        free(obj);
        return 0;
    }

    if(fgetc(fp) != '\n')
        return 0;

    char chunks[] = "chunks:";

    for(int i = 0; i < 7; i++) {
        if(fgetc(fp) != chunks[i])
            return 0;
    }

    if(fgetc(fp) != '\n')
        return 0;

    // Allocate memory for an array of char pointers to store hashes
    obj->chunks = (struct chunk**) malloc(sizeof(struct chunk*) * obj->nchunks);

    for(int i = 0; i < obj->nchunks; i++) {
        // Check tab character
        if(fgetc(fp) != 9)
            return 0;
        
        // Allocate memory for a single hash, read a hash in and store it
        obj->chunks[i] = (struct chunk*) malloc(sizeof(struct chunk));
        res = fscanf(fp, HASH_READ, obj->chunks[i]->hash);

        // Check that data is read and the hash is valid
        if((res <= 0) | (!is_valid_hash(obj->chunks[i]->hash))) {
            for(int j = 0; j <= i; j++) 
                free(obj->chunks[j]);

            free(obj->chunks);

            for(int i = 0; i <= obj->nhashes; i++) 
                free(obj->hashes[i]);

            free(obj->hashes);
            
            free(obj);
            return 0;
        }

        // Check comma
        if(fgetc(fp) != ',')
            return 0;
        
        // Read an offset from file and store it
        res = fscanf(fp, "%u", &(obj->chunks[i]->offset));

        if(res <= 0) {
            for(int i = 0; i <= obj->nchunks; i++) 
                free(obj->chunks[i]);

            free(obj->chunks);

            for(int i = 0; i <= obj->nhashes; i++) 
                free(obj->hashes[i]);

            free(obj->hashes);
            
            free(obj);
            return 0;
        }
        
        if(fgetc(fp) != ',')
            return 0;
        
        // Read a size from file and store it
        res = fscanf(fp, "%u", &(obj->chunks[i]->size));

        if(res <= 0) {
            for(int i = 0; i <= obj->nchunks; i++) 
                free(obj->chunks[i]);

            free(obj->chunks);

            for(int i = 0; i <= obj->nhashes; i++) 
                free(obj->hashes[i]);

            free(obj->hashes);
            
            free(obj);
            return 0;
        }
        
        if(fgetc(fp) != '\n')
            return 0;
    }

    // If that we've reached end of file
    if(fgetc(fp) != EOF) {
        return 0;
    }

    // Free resources
    fclose(fp);
    bpkg_obj_destroy(obj);
    
    return 1;
}
