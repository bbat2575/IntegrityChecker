#ifndef KEYS_H
#define KEYS_H

#include <stdio.h>


/**
 * Converts integer into binary string
 * @param num, integer number
 * @return bin, the binary conversion as a string
 */
char* int_to_bin(int num, int height);


/**
 * Generates a new non-leaf node key using
 * the key of either left or right child and
 * omitting the last bit e.g. 01010 -> 0101
 * @param child_key, string containing a child's key
 * @return key, newly generated non-leaf node key
 */
char* gen_hash_key(char* child_key, int height);


#endif