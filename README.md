# Description

The following program carries out integrity checks on data files through the use of bpkg files and merkle tree construction.

How To Use:

1. Create a bpkg file for the data file being checked.  
1. Run an integrity check.

# How To Create A BPKG File

Navigate to resources, run the binary executable and follow the prompts.
```bash
cd resources
./pkgmake
```

Example:
```bash
./pkgmake pkgs/file1.data --nchunks 128 --output pkgs/file1-2.bpkg
```
NOTE: nchunks is always a multiple of 8 (due to hash size) and will round down accordingly.

# How To Run An Integrity Check

Create the pkgmain binary executable.

```bash
make
```

To run an integrity check.

```bash
./pkgmain [bpkg-file] -integrity_check
```

Example:
```bash
./pkgmain resources/pkgs/file1.bpkg -integrity_check
```

# Additional: Retrieving Hashes

To retrieve all hashes of a bpkg file.

```bash
./pkgmain [bpkg-file] -all_hashes
```

To retrieve all valid chunk hashes of a bpkg file. NOTE: Chunk hashes are simply the leaf nodes of the merkle tree.

```bash
./pkgmain [bpkg-file] -chunk_check
```

To retrieve the minimum of hashes to represent the completion state. This simply retrieves all nodes of the merkle tree that have valid descendants. E.g. if all hashes are valid, the root node is returned.

```bash
./pkgmain [bpkg-file] -min_hashes
```

To retrieve all descendant hashes given a certain ancestor hash. E.g. given the root node, all hashes are retrieved:
```bash
./pkgmain [bpkg-file] -hashes_of [hash]
```

Example:
```bash
./pkgmain resources/pkgs/file1.bpkg -hashes_of 4e4dcf5cb1f3cfb33e5b93f760f79fc34a5b627454081f586685b808b972107e
```

# Software Architecure
The entry point of the program is the pkgmain.c file which calls on pkgchk.c functions to carry out user requested tasks established via the command-line. The program focuses on retrieving information about bkpg files and the integrity of their corresponding data files.  

Each time the pkgmain binary is executed with one of its designated flags, the bpkg_load() and bpkg_file_check() functions are first executed to retrieve the bpkg contents and store it in a bpkg object, and then to ensure that the corrseponding data file exists.  

There's a few things to note about pkgmain:
1. All query objects from pkgchk.c are returned to pkgmain where their results are displayed to stdout at the end of the process.
1. All query and bpkg objects are freed via bpkg_query_destroy() and bpkg_obj_destroy() (from pkgchk.c) in pkgmain at the completion of a task.
1. Any tasks requiring a merkle tree construction will destroy the merkle tree using merkle_tree_destroy() (from pkgchk.c) inside the corresponding pkgchk.c function before returning the query object to pkgmain. 

Note: The merkle_tree_destroy() function relies on the merkle_nodes_destroy() function which uses recursion to carry out an in-order traversal and destroy the nodes of the tree.

The pkgmain flags and their corresponding tasks work like this:
- -all_hashes
    - This flag calls on the bpkg_get_all_hashes() function in pkgchk.c to store all the hashes of a bpkg object inside a query object.
- -chunk_check
    - This flag calls on the bpkg_get_completed_chunks() function in pkgchk.c which in turn calls on the merkle_tree_build() function to construct a merkle tree object. The root node of the merkle tree is then passed to the get_completed_chunks() function to populate a query object containing all completed chunk hashes from the merkle tree.
- -min_hashes
    - This flag calls on the bpkg_get_min_completed_hashes() function in pkgchk.c which in turn also calls on merkle_tree_build(). The root node of the merkle tree is then passed to the get_completed_hashes() function to populate a query object with the minimum hashes that represent all completed hashes in the tree.
- -hashes_of [hash]
    - This flag, along with its required hash argument, calls on the bpkg_get_all_chunk_hashes_from_hash() function in pkgchk.c which in turn calls on merkle_tree_build(). The merkle tree object is then passed to the find_node() function to find the node that contains the hash that was passed as an argument. This node is then passed to the get_chunk_hashes_of_ancestor() function to populate a query object with all the hashes of its descendants in the merkle tree.

# Modularity
The sha256.c/sha256.h handles the hashing of data chunks inside the merkle_tree_build() function.  

The inputs.c/inputs.h handles several functions, three of which are used to read the contents of bpkg files in bpkg_load():  
- The read_label() function reads passed a field label in a bpkg file so only the values can be extracted. 
- The is_valid_ident() function checks that the ident read from a bpkg file has a valid format.   
- The is_valid_hash() function checks that each hash read from a bpkg file has a valid format.  

The keys.c/keys.h handles two functions used to create node keys in merkle_tree_build():  
- The int_to_bin() function generates the keys of leaf nodes by converting the position of its chunk amongst the other chunks, represented by an integer, into a binary number.
- The gen_hash_key() function generates the keys of non-leaf nodes by truncating the right-most bit of a child node binary key.

# Testing

Unit testing is carried out using the cmocka framework and is followed by code coverage analysis using Gcov.  

The source code for the cmocka testing files are stored in the tests/ directory along with the pkgs/ directory which contains the bpkg and data files used for testing.  

Test descriptions are located in test.sh in the main directory.  

# How To Run Tests

Simply execute the testing script.

```bash
./test.sh
```