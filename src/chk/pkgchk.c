#include "add/inputs.h"
#include "add/keys.h"
#include "chk/pkgchk.h"
#include "crypt/sha256.h"
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>


// PART 1


/**
 * Loads the package for when a valid path is given
 * @param path, path to bpkg file
 */
struct bpkg_obj* bpkg_load(const char* path) {
    FILE *fp = fopen(path, "r");
    
    if(fp == NULL)
        return NULL;
    // Check if file empty
    else {
        // Go to the end of the file and read the size in bytes
        fseek(fp, 0, SEEK_END);
        
        // If file is empty
        if (ftell(fp) == 0) {
            fclose(fp);
            return NULL;
        // Else go back to beginning of file and continue
        } else
            fseek(fp, 0, SEEK_SET);
    }

    // Allocate memory for bpkg object
    struct bpkg_obj* obj = (struct bpkg_obj*) malloc(sizeof(struct bpkg_obj));

    // Read passed the label
    read_label(fp);

    // Read in ident and assign to struct field
    int res = fscanf(fp, IDENT_READ, obj->ident);

    // Check that data was read and ident is valid
    if((res <= 0) | (!is_valid_ident(obj->ident))) {
        free(obj);
        return NULL;
    }

    read_label(fp);

    // Read in filename and assign to struct field
    res = fscanf(fp, FILENAME_READ, obj->filename);

    if(res <= 0) {
        free(obj);
        return NULL;
    }

    read_label(fp);

    // Read in size and assign to struct field
    res = fscanf(fp, "%u", &(obj->size));

    if(res <= 0) {
        free(obj);
        return NULL;
    }

    read_label(fp);

    // Read in nhashes and assign to struct field
    res = fscanf(fp, "%u", &(obj->nhashes));

    if(res <= 0) {
        free(obj);
        return NULL;
    }

    // Read passed the label and newline
    read_label(fp);
    fgetc(fp);

    // Allocate memory for an array of char pointers to store hashes
    obj->hashes = (char**) malloc(sizeof(char*) * obj->nhashes);

    for(int i = 0; i < obj->nhashes; i++) {
        // Read passed the tab character
        int tab = fgetc(fp);
        
        // Allocate memory for a single hash, set characters to null, and assign it a hash from file
        obj->hashes[i] = (char*) malloc(sizeof(char) * HASH_SIZE);
        memset(obj->hashes[i], '\0', sizeof(char) * HASH_SIZE);
        res = fscanf(fp, HASH_READ, obj->hashes[i]);

        // Check that data is read, the hash is valid, and hash is indented by a tab
        if((res <= 0) | (!is_valid_hash(obj->hashes[i])) | (tab != 9)) {
            for(int j = 0; j <= i; j++) 
                free(obj->hashes[j]);

            free(obj->hashes);

            free(obj);
            return NULL;
        }

        // Read passed the newline
        fgetc(fp);
    }

    read_label(fp);

    // Read in nchunks and assign to struct field
    res = fscanf(fp, "%u", &(obj->nchunks));

    if(res <= 0) {
        for(int i = 0; i <= obj->nhashes; i++) 
            free(obj->hashes[i]);

        free(obj->hashes);
        
        free(obj);
        return NULL;
    }

    // Read passed the label and newline
    read_label(fp);
    fgetc(fp);

    // Allocate memory for an array of char pointers to store hashes
    obj->chunks = (struct chunk**) malloc(sizeof(struct chunk*) * obj->nchunks);

    for(int i = 0; i < obj->nchunks; i++) {
        // Read passed the tab character
        int tab = fgetc(fp);
        
        // Allocate memory for a single hash, read a hash in and store it
        obj->chunks[i] = (struct chunk*) malloc(sizeof(struct chunk));
        res = fscanf(fp, HASH_READ, obj->chunks[i]->hash);

        // Check that data is read, the hash is valid, and hash is indented by a tab
        if((res <= 0) | (!is_valid_hash(obj->chunks[i]->hash)) | (tab != 9)) {
            for(int j = 0; j <= i; j++) 
                free(obj->chunks[j]);

            free(obj->chunks);

            for(int i = 0; i <= obj->nhashes; i++) 
                free(obj->hashes[i]);

            free(obj->hashes);
            
            free(obj);
            return NULL;
        }

        // Read passed the comma
        fgetc(fp);
        
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
            return NULL;
        }
        
        // Read passed the comma
        fgetc(fp);
        
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
            return NULL;
        }
        
        // Read passed the newline
        fgetc(fp);
    }

    // Close the file
    fclose(fp);
    
    return obj;
}


/**
 * Checks to see if the referenced filename in the bpkg file
 * exists or not.
 * @param bpkg, constructed bpkg object
 * @return query_result, a single string should be
 *      printable in hashes with len sized to 1.
 * 		If the file exists, hashes[0] should contain "File Exists"
 *		If the file does not exist, hashes[0] should contain "File Created"
 */
struct bpkg_query bpkg_file_check(struct bpkg_obj* bpkg) {
    struct bpkg_query qry = { 0 };

    qry.len = 1;

    qry.hashes = (char**) malloc(sizeof(char*));

    // Allocate memory to store file check result
    qry.hashes[0] = (char*) malloc(sizeof(char) * HASH_SIZE);
    memset(qry.hashes[0], '\0', sizeof(char) * HASH_SIZE);

    FILE *fp = fopen(bpkg->filename, "r");

    // If file exists
    if(fp != NULL) {
        fclose(fp);
        strcpy(qry.hashes[0], "File Exists");
    // If file doesn't exist, create it
    } else {
        FILE *fp = fopen(bpkg->filename, "w");

        // Change the size of the file to match the one specified in bpkg
        ftruncate(fileno(fp), bpkg->size);

        fclose(fp);
        strcpy(qry.hashes[0], "File Created");
    }

    return qry;
}


/**
 * Builds a merkle tree using a bpkg object.
 * @param bpkg, constructed bpkg object
 * @return tree, merkle_tree object pointer
 */
struct merkle_tree* merkle_tree_build(struct bpkg_obj* bpkg) {
    // Calculate the height of the tree
    int height = log(bpkg->nchunks) / log(2);
    // Calculate the size of each data block
    size_t block_size = bpkg->size / bpkg->nchunks;

    FILE *fp = fopen(bpkg->filename, "r");

    if(fp == NULL) {
        perror("Unable to open data file");
        return NULL;
    }

    // Create a buffer for incoming data blocks from file
    char buffer[block_size + 1];
    memset(buffer, '\0', block_size + 1);

    struct merkle_tree_node *leaf_nodes[bpkg->nchunks];

    // Iterate over each leaf node and fill in their data
    for(int i = 0; i < bpkg->nchunks; i++) {
        // Allocate memory for a single node and key
        leaf_nodes[i] = (struct merkle_tree_node*) malloc(sizeof(struct merkle_tree_node));
        leaf_nodes[i]->key = malloc(sizeof(char) * (height + 1));
        memset(leaf_nodes[i]->key, '\0', sizeof(char) * (height + 1));

        // Obtain binary value of current leaf node number
        char *bin = int_to_bin(i, height);
        strcpy(leaf_nodes[i]->key, bin);
        free(bin);

        leaf_nodes[i]->left = NULL;
        leaf_nodes[i]->right = NULL;
        leaf_nodes[i]->is_leaf = 1;

        // Assign the expected hash value
        strcpy(leaf_nodes[i]->expected_hash, bpkg->chunks[i]->hash);

        // Calculate the computed hash
        // Create a sha256 data struct & initialise it
        struct sha256_compute_data buff;
        sha256_compute_data_init(&buff);

        // Read one data block from the file and hash it
        fread(buffer, 1, block_size, fp);

        sha256_update(&buff, buffer, block_size);
        uint8_t hash[HASH_SIZE];
        memset(hash, '\0', HASH_SIZE);
        sha256_finalize(&buff, hash);

        // Convert to hexidecimal hash
        sha256_output_hex(&buff, (char*)hash);

        // Store computed hash in node struct
        strcpy(leaf_nodes[i]->computed_hash, (char*)hash);

        // Assign data block to value field
        leaf_nodes[i]->value = malloc(sizeof(char) * block_size + 1);
        memset(leaf_nodes[i]->value, '\0', block_size + 1);
        strcpy(leaf_nodes[i]->value, buffer);
    }

    fclose(fp);

    struct merkle_tree *tree = NULL;

    // Create a variable to store the number of nodes at each level
    size_t level_size = bpkg->nchunks;

    struct merkle_tree_node *non_leaf_nodes[bpkg->nhashes];

    int index = 0; // an index to track non_leaf_nodes
    int offset = 0; // an offset to track child nodes in non_leaf_nodes

    for(int i = height - 1; i >= 0; i--) {
        // Calculate number of nodes at this level
        level_size = level_size / 2;

        for(int j = 0; j < level_size; j++) {
            // Allocate memory for a single node and key
            non_leaf_nodes[index] = (struct merkle_tree_node*) malloc(sizeof(struct merkle_tree_node));
            non_leaf_nodes[index]->key = malloc(sizeof(char) * (height + 3));
            memset(non_leaf_nodes[index]->key, '\0', sizeof(char) * (height + 3));

            char *bin = NULL;

            // Assign left and right children and obtain key for current node using a child key
            // If last non-leaf level
            if(i == height - 1) {
                non_leaf_nodes[index]->left = leaf_nodes[j * 2];
                non_leaf_nodes[index]->right = leaf_nodes[j * 2 + 1];

                bin = gen_hash_key(non_leaf_nodes[index]->left->key, height);
            // If any other non-leaf level
            } else {
                non_leaf_nodes[index]->left = non_leaf_nodes[offset];
                non_leaf_nodes[index]->right = non_leaf_nodes[offset + 1];
                
                offset += 2;

                // If root node set key to "root" and create a merkle tree object
                if(i == 0) {
                    bin = malloc(sizeof(char) * 5);
                    memset(bin, '\0', 5);
                    memcpy(bin, "root", 5);

                    // Allocate memory for merkle tree object and assign the root node and n_nodes values
                    tree = (struct merkle_tree*) malloc(sizeof(struct merkle_tree));
                    tree->root = non_leaf_nodes[index];
                    tree->n_nodes = bpkg->nhashes + bpkg->nchunks;
                // If any other non-leaf level than root
                } else {
                    bin = gen_hash_key(non_leaf_nodes[index]->left->key, height);
                }
            }
            
            memcpy(non_leaf_nodes[index]->key, bin, strlen(bin));
            free(bin);

            non_leaf_nodes[index]->is_leaf = 0;

            // Assign the expected hash value
            strcpy(non_leaf_nodes[index]->expected_hash, bpkg->hashes[level_size + j - 1]);

            // Calculate the computed hash using two child computed hashes
            // Create a sha256 data struct & initialise it
            struct sha256_compute_data buff;
            sha256_compute_data_init(&buff);

            // Combine child hashes
            char combined_hash[HASH_SIZE * 2 - 1];
            memset(combined_hash, '\0', HASH_SIZE * 2 - 1);
            strcpy(combined_hash, non_leaf_nodes[index]->left->computed_hash);
            strcat(combined_hash, non_leaf_nodes[index]->right->computed_hash);

            // Compute the hash of combined child hashes
            sha256_update(&buff, combined_hash, HASH_SIZE * 2 - 2);
            uint8_t hash[HASH_SIZE];
            memset(hash, '\0', HASH_SIZE);
            sha256_finalize(&buff, hash);

            // Convert to hexidecimal hash
            sha256_output_hex(&buff, (char*)hash);

            // Store computed hash in node struct
            strcpy(non_leaf_nodes[index]->computed_hash, (char*)hash);
            
            index++;
        }
    }

    return tree;
}


/**
 * Retrieves a list of all hashes within the package/tree
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_all_hashes(struct bpkg_obj* bpkg) {
    struct bpkg_query qry = { 0 };

    qry.len = bpkg->nhashes + bpkg->nchunks;
    
    qry.hashes = (char**) malloc(sizeof(char*) * (bpkg->nhashes + bpkg->nchunks));

    // Populate hashes
    for(int i = 0; i < (bpkg->nhashes + bpkg->nchunks); i++) {
        qry.hashes[i] = (char*) malloc(sizeof(char) * HASH_SIZE);
        memset(qry.hashes[i], '\0', sizeof(char) * HASH_SIZE);

        // If non-leaf hash
        if( i < bpkg->nhashes)
            strcpy(qry.hashes[i], bpkg->hashes[i]);
        // If leaf/chunk hash
        else
            strcpy(qry.hashes[i], bpkg->chunks[i - bpkg->nhashes]->hash);
    }
    
    return qry;
}


/**
 * Retrieves all completed chunks of a package object
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_completed_chunks(struct bpkg_obj* bpkg) { 
    struct merkle_tree *tree = merkle_tree_build(bpkg);
    
    struct bpkg_query qry = { 0 };

    // Allocate memory for hashes with initial max size = nchunks
    qry.hashes = (char** ) malloc(sizeof(char*) * bpkg->nchunks);

    // Allocate memory to count actual number of hashes stored
    int* len = (int*) malloc(sizeof(int));
    (*len) = 0;

    // Get the completed chunk hashes
    get_completed_chunks(qry.hashes, tree->root, len);

    qry.len = *len;
    free(len);
    merkle_tree_destroy(tree);

    // If the number of hashes is not the maximum (nchunks), adjust the size of hashes array
    if(qry.len != bpkg->nchunks)
        qry.hashes = (char**) realloc(qry.hashes, sizeof(char*) * qry.len);

    return qry;
}


/**
 * Gets the mininum of hashes to represented the current completion state
 * Example: If chunks representing start to mid have been completed but
 * 	mid to end have not been, then we will have (N_CHUNKS/2) + 1 hashes
 * 	outputted
 *
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_min_completed_hashes(struct bpkg_obj* bpkg) {
    struct merkle_tree *tree = merkle_tree_build(bpkg);
    
    struct bpkg_query qry = { 0 };

    // Allocate memory for hashes with initial max size = nchunks
    qry.hashes = (char** ) malloc(sizeof(char*) * bpkg->nchunks);

    // Allocate memory to count actual number of hashes stored
    int* len = (int*) malloc(sizeof(int));
    (*len) = 0;

    // Get the completed hashes
    get_completed_hashes(qry.hashes, tree->root, len);

    qry.len = *len;
    free(len);
    merkle_tree_destroy(tree);

    // If the number of hashes is not the maximum (nchunks), adjust the size of hashes array
    if(qry.len != bpkg->nchunks)
        qry.hashes = (char**) realloc(qry.hashes, sizeof(char*) * qry.len);

    return qry;
}


/**
 * Retrieves all chunk hashes given a certain an ancestor hash (or itself)
 * Example: If the root hash was given, all chunk hashes will be outputted
 * 	If the root's left child hash was given, all chunks corresponding to
 * 	the first half of the file will be outputted
 * 	If the root's right child hash was given, all chunks corresponding to
 * 	the second half of the file will be outputted
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_all_chunk_hashes_from_hash(struct bpkg_obj* bpkg, 
    char* hash) {
    
    struct bpkg_query qry = { 0 };

    // Check that the hash is valid
    if(!is_valid_hash(hash)) {
        // qry.len = 0;
        return qry;
    }

    struct merkle_tree *tree = merkle_tree_build(bpkg);

    // Allocate memory for hashes with initial max size = nchunks
    qry.hashes = (char**) malloc(sizeof(char*) * bpkg->nchunks);

    // Allocate memory to store the node with the hash we're looking for
    struct merkle_tree_node* node = (struct merkle_tree_node*) malloc(sizeof(struct merkle_tree_node));

    // Find the node with the given hash value
    find_node(tree->root, node, hash);

    // Allocate memory to count actual number of hashes stored
    int* len = (int*) malloc(sizeof(int));
    (*len) = 0;

    // Get the chunk hashes of the ancestral node
    get_chunk_hashes_of_ancestor(qry.hashes, node, len);

    qry.len = *len;
    free(len);
    free(node);
    merkle_tree_destroy(tree);

    // If the number of hashes is not the maximum (nchunks), adjust the size of hashes array
    if(qry.len != bpkg->nchunks)
        qry.hashes = (char**) realloc(qry.hashes, sizeof(char*) * qry.len);

    return qry;
}


/**
 * A recursive function that uses in-order traversal
 * to find all completed chunks of a merkle tree
 * @param hashes, an array to store completed chunk hashes
 * @param node, initally the root node of the tree, 
 * it holds the current node of the in-order traversal
 * @param len, stores the total number of completed chunk hashes
 */
void get_completed_chunks(char** hashes, struct merkle_tree_node* node, int* len) {
    // If a child doesn't exist then we have a leaf node
    if(node->left == NULL) {
        // Check that it's a completed chunk hash
        if(memcmp(node->computed_hash, node->expected_hash, HASH_SIZE - 1) == 0) {
            // Store the hash in hashes and increment len
            hashes[*len] = (char*) malloc(sizeof(char) * HASH_SIZE);
            memset(hashes[*len], '\0', sizeof(char) * HASH_SIZE);
            strcpy(hashes[*len], node->computed_hash);
            (*len)++;
        }
    // If a non-leaf node, use recursion for in-order traversal
    } else {
        get_completed_chunks(hashes, node->left, len);
        get_completed_chunks(hashes, node->right, len);
    }
}


/**
 * A recursive function that uses in-order traversal
 * to find all completed hashes of a merkle tree
 * @param hashes, an array to store completed chunk hashes
 * @param node, initally the root node of the tree, 
 * it holds the current node of the in-order traversal
 * @param len, stores the total number of completed chunk hashes
 */
int get_completed_hashes(char** hashes, struct merkle_tree_node* node, int* len) {
    // If a child doesn't exist then we have a leaf node
    if(node->left == NULL) {
        // Return 1 if it's a completed chunk hash, otherwise return 0
        if(memcmp(node->expected_hash, node->computed_hash, HASH_SIZE - 1) == 0) {
            return 1;
        } else {
            return 0;
        }
    // If children are non-leaf nodes, use recursion for in-order traversal
    } else {
        int res_left = get_completed_hashes(hashes, node->left, len);
        int res_right = get_completed_hashes(hashes, node->right, len);

        // If both children are completed hashes, return 1
        if((res_left) & (res_right)) {
            // However if current node is root, then store it (we're done)
            if(memcmp(node->key, "root", 5) == 0) {
                // Store the hash in hashes and increment len
                hashes[*len] = (char*) malloc(sizeof(char) * HASH_SIZE);
                memset(hashes[*len], '\0', sizeof(char) * HASH_SIZE);
                strcpy(hashes[*len], node->computed_hash);
                (*len)++;
            }
            return 1;
        // If only the left child is a completed hash, store it and increment len
        } else if(res_left){
            hashes[*len] = (char*) malloc(sizeof(char) * HASH_SIZE);
            memset(hashes[*len], '\0', sizeof(char) * HASH_SIZE);
            strcpy(hashes[*len], node->left->computed_hash);
            (*len)++;
            return 0;
        // If only the right child is a completed hash, store it and increment len
        } else if(res_right){
            hashes[*len] = (char*) malloc(sizeof(char) * HASH_SIZE);
            memset(hashes[*len], '\0', sizeof(char) * HASH_SIZE);
            strcpy(hashes[*len], node->right->computed_hash);
            (*len)++;
            return 0;
        } else 
            return 0;
    }
}


/**
 * A recursive function that uses in-order traversal
 * find a node with a corresponding hash in a merkle tree
 * @param curr_node, initally the root node of the tree, 
 * it holds the current node of the in-order traversal
 * @param node, allocated memory used to store the node
 * @param hash, the expected hash of the node being searched for
 */
void find_node(struct merkle_tree_node* curr_node, struct merkle_tree_node* node, char* hash) {
    // If left child exists, search recursively
    if(curr_node->left)
        find_node(curr_node->left, node, hash);
    
    // If node found, store details in node struct
    if(memcmp(curr_node->expected_hash, hash, HASH_SIZE - 1) == 0) {
    	node->key = curr_node->key;
        node->value = curr_node->value;
        node->left = curr_node->left;
        node->right = curr_node->right;
        node->is_leaf = curr_node->is_leaf;
        strcpy(node->expected_hash, curr_node->expected_hash);
        strcpy(node->computed_hash, curr_node->computed_hash);
    }

    // If right child exists, search recursively
    if(curr_node->right)
        find_node(curr_node->right, node, hash);
}


/**
 * A recursive function that uses in-order traversal
 * to find all the chunk hashes of an ancestor node
 * in a merkle tree
 * @param hashes, an array to store the chunk hashes
 * @param node, initally the ancestor node, holds the 
 * current node of the in-order traversal
 * @param len, stores the total number of chunk hashes
 */
void get_chunk_hashes_of_ancestor(char** hashes, struct merkle_tree_node* node, int* len) {
    // If a child doesn't exist then we have a leaf node
    if(node->left == NULL) {
        // Store the chunk hash in hashes and increment len
        hashes[*len] = (char*) malloc(sizeof(char) * HASH_SIZE);
        memset(hashes[*len], '\0', sizeof(char) * HASH_SIZE);
        strcpy(hashes[*len], node->expected_hash);
        (*len)++;
    // If children are non-leaf nodes, use recursion for in-order traversal
    } else {
        get_chunk_hashes_of_ancestor(hashes, node->left, len);
        get_chunk_hashes_of_ancestor(hashes, node->right, len);
    }
}


/**
 * Deallocates the query result after it has been 
 * constructed from the relevant queries above.
 * @param qry, pointer to query object
 */
void bpkg_query_destroy(struct bpkg_query* qry) {
    // Deallocate hash memory
    for(int i = 0; i < qry->len; i++) {
        free(qry->hashes[i]);
    }

    free(qry->hashes);
}


/**
 * Deallocates memory of bpkg object - for use 
 * at the end of the program
 * @param obj, pointer to bpkg object
 */
void bpkg_obj_destroy(struct bpkg_obj* obj) {
    // Deallocate hash memory
    for(int i = 0; i < obj->nhashes; i++) {
        free(obj->hashes[i]);
    }

    free(obj->hashes);

    // Deallocate chunk memory
    for(int i = 0; i < obj->nchunks; i++) {
        free(obj->chunks[i]);
    }

    free(obj->chunks);

    free(obj);
}


/**
 * Deallocates the memory for a merkle tree
 * @param tree, pointer to merkle tree object
 */
void merkle_tree_destroy(struct merkle_tree *tree) {
    merkle_nodes_destroy(tree->root);
    free(tree);    
}


/**
 * Deallocates the memory for all leaf and 
 * non-leaf nodes of a merkle tree
 * @param node, pointer to merkle tree node
 */
void merkle_nodes_destroy(struct merkle_tree_node *node) {
    // If left child exists, recurse on left child
    if(node->left != NULL)
        merkle_nodes_destroy(node->left);
    
    // If right child exists, recurse on right child
    if(node->right != NULL)
        merkle_nodes_destroy(node->right);
    // If leaf-node, free value
    else
        free(node->value);

    free(node->key);
    free(node);
}
