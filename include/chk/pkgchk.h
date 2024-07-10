#ifndef PKGCHK_H
#define PKGCHK_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#define IDENT_SIZE 1025
#define IDENT_READ "%1024[^\n]"
#define FILENAME_SIZE 257
#define FILENAME_READ "%256[^\n]"
#define HASH_SIZE 65
#define HASH_READ "%64[^\n]"
#define PACKAGES_MAX 50


/**
 * Query object, allows you to assign
 * hash strings to it.
 * Typically: malloc N number of strings for hashes
 *    after malloc the space for each string
 *    Make sure you deallocate in the destroy function
 */
struct bpkg_query {
	char** hashes;
	size_t len;
};


/**
 * bpkg object, holds all the data of
 * a bpkg file.
 */
struct bpkg_obj {
	char ident[IDENT_SIZE];
	char filename[FILENAME_SIZE];
	uint32_t size;
	uint32_t nhashes;
	char **hashes;
	uint32_t nchunks;
	struct chunk **chunks;

};


/**
 * chunk object, holds the information of
 * a single chunk from a bpkg file/object.
 */
struct chunk {
	char hash[HASH_SIZE];
	uint32_t offset;
	uint32_t size;
};


/**
 * merkle tree node object, holds the information 
 * of a single merkle tree node.
 */
struct merkle_tree_node {
	void* key;
	void* value;
	struct merkle_tree_node* left;
	struct merkle_tree_node* right;
	int is_leaf;
	char expected_hash[HASH_SIZE]; //Refer to SHA256 Hexadecimal size
	char computed_hash[HASH_SIZE];
};


/**
 * merkle tree object, holds the information 
 * of a merkle tree including root node object
 * and number of nodes.
 */
struct merkle_tree {
	struct merkle_tree_node* root;
	size_t n_nodes;
};


/**
 * Loads the package for when a value path is given
 * @param path, path to bpkg file
 */
struct bpkg_obj* bpkg_load(const char* path);


/**
 * Checks to see if the referenced filename in the bpkg file
 * exists or not.
 * @param bpkg, constructed bpkg object
 * @return query_result, a single string should be
 *      printable in hashes with len sized to 1.
 * 		If the file exists, hashes[0] should contain "File Exists"
 *		If the file does not exist, hashes[0] should contain "File Created"
 */
struct bpkg_query bpkg_file_check(struct bpkg_obj* bpkg);


/**
 * Builds a merkle tree using a bpkg object.
 * @param bpkg, constructed bpkg object
 * @return merkle_tree object pointer
 */
struct merkle_tree* merkle_tree_build(struct bpkg_obj* bpkg);


/**
 * Retrieves a list of all hashes within the package/tree
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_all_hashes(struct bpkg_obj* bpkg);


/**
 * Retrieves all completed chunks of a package object
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_completed_chunks(struct bpkg_obj* bpkg);


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
struct bpkg_query bpkg_get_min_completed_hashes(struct bpkg_obj* bpkg); 


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
struct bpkg_query bpkg_get_all_chunk_hashes_from_hash(struct bpkg_obj* bpkg, char* hash);


/**
 * A recursive function that uses in-order traversal
 * to find all completed chunks of a merkle tree
 * @param hashes, an array to store completed chunk hashes
 * @param node, initally the root node of the tree, 
 * it holds the current node of the in-order traversal
 * @param len, stores the total number of completed chunk hashes
 */
void get_completed_chunks(char** hashes, struct merkle_tree_node* node, int* len);


/**
 * A recursive function that uses in-order traversal
 * to find all completed hashes of a merkle tree
 * @param hashes, an array to store completed chunk hashes
 * @param node, initally the root node of the tree, 
 * it holds the current node of the in-order traversal
 * @param len, stores the total number of completed chunk hashes
 */
int get_completed_hashes(char** hashes, struct merkle_tree_node* node, int* len);


/**
 * A recursive function that uses in-order traversal
 * find a node with a corresponding hash in a merkle tree
 * @param curr_node, initally the root node of the tree, 
 * it holds the current node of the in-order traversal
 * @param node, allocated memory used to store the node
 * @param hash, the expected hash of the node being searched for
 */
void find_node(struct merkle_tree_node* curr_node, struct merkle_tree_node* node, char* hash);


/**
 * A recursive function that uses in-order traversal
 * to find all the chunk hashes of an ancestor node
 * in a merkle tree
 * @param hashes, an array to store the chunk hashes
 * @param node, initally the ancestor node, holds the 
 * current node of the in-order traversal
 * @param len, stores the total number of chunk hashes
 */
void get_chunk_hashes_of_ancestor(char** hashes, struct merkle_tree_node* node, int* len);


/**
 * Deallocates the query result after it has been 
 * constructed from the relevant queries above.
 * @param qry, pointer to query object
 */
void bpkg_query_destroy(struct bpkg_query* qry);


/**
 * Deallocates memory of bpkg object - for use 
 * at the end of the program
 * @param obj, pointer to bpkg object
 */
void bpkg_obj_destroy(struct bpkg_obj* obj);


/**
 * Deallocates the memory for a merkle tree
 * @param tree, pointer to merkle tree object
 */
void merkle_tree_destroy(struct merkle_tree *tree);


/**
 * Deallocates the memory for all leaf and 
 * non-leaf nodes of a merkle tree
 * @param node, pointer to merkle tree node
 */
void merkle_nodes_destroy(struct merkle_tree_node *node);


int ftruncate(int fd, off_t length);
int fileno(FILE *stream);


#endif

