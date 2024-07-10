#include "add/keys.h"
#include "chk/pkgchk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**
 * Converts integer into binary string
 * @param num, integer number
 * @return bin, the binary conversion as a string
 */
char* int_to_bin(int num, int height) {
    // Allocate memory to store binary number and set values to null
    char *bin = malloc(sizeof(char) * (height + 1));
    memset(bin, '\0', sizeof(char) * (height + 1));


    for (int i = height - 1; i >= 0; i--) {
        // Assign binary digit
        bin[i] = (num & 1) + '0';
        // Right shift bits by 1
        num >>= 1;
    }

    return bin;
}


/**
 * Generates a new non-leaf node key using
 * the key of either left or right child and
 * omitting the last bit e.g. 01010 -> 0101
 * @param child_key, string containing a child's key
 * @return key, newly generated non-leaf node key
 */
char* gen_hash_key(char* child_key, int height) {
    // Allocate memory to store new key, set values to null, and assign it the child_key value
    char *key = malloc(sizeof(char) * (height + 1));
    memset(key, '\0', sizeof(char) * (height + 1));
    strcpy(key, child_key);

    // Remove last bit by making it null
    for (int i = height - 1; i >= 0; i--) {
        if(key[i] != '\0') {
            key[i] = '\0';
            break;
        }
    }

    return key;
}
