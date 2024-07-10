#ifndef INPUTS_H
#define INPUTS_H

#include <stdio.h>

#define COMMAND_LEN 5521


/**
 * Reads through a label when reading from bpkg
 * files (allows us to ignore the label)
 * @param fp, pointer to file object
 */
void read_label(FILE *fp);


/**
 * Indicates whether an ident is valid by checking
 * that each character is a hexadecimal digit and
 * that the length is no less than 1024 bytes
 * @param ident, the ident to be checked
 */
int is_valid_ident(char* ident);


/**
 * Indicates whether a hash is valid by checking
 * that each character is a hexadecimal digit and
 * that the length is no less than 64 bytes
 * @param hash, the hash to be checked
 */
int is_valid_hash(char* hash);


/**
 * Checks to see if data contains characters
 * @param data, the data to be checked
 */
int is_empty(char *data); 


/**
 * Checks if a bpkg file has a valid format
 * @param path, path to bpkg file
 */
int is_valid_bpkg(const char* path);


#endif