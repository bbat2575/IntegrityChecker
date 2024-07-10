#!/bin/bash

# Compile tests
make testing > /dev/null

# Run tests
./testing

# Newline
echo

# Genereate coverage report
gcov testing-pkgchk.c

# Clean up
make clean-tests > /dev/null

# -- PART 1 TEST DESCRIPTIONS --

### Test 1 − Valid Bpkg File (Positive Test Case)
# Testing bpkg_load() with a valid bpkg file and data file

### Test 2− Large Number of Hashes (Positive Test Case)
# Testing bpkg_load() with a bpkg file containing over 1000 hashes in total (512 chunk hashes)

### Test 3 - Fake Path (Negative Test Case)
# Testing bpkg_load() with a fake path to a bpkg file

### Test 4 − Invalid Identifier #1 - Non-Hexadecimal Values (Negative Test Case)
# Testing bpkg_load() with a bpkg file that has an invalid ident value containing non-hexadecimal characters

### Test 5 − Invalid Identifier #2 - Too Short (Negative Test Case)
# Testing bpkg_load() with a bpkg file that has an invalid ident that's too short

### Test 6 − Invalid Bpkg File #1 - Missing Values (Negative Test Case)
# Testing bpkg_load() with a bpkg file that has missing nhashes and nchunks field values

### Test 7 − Invalid Bpkg File #2 - Invalid Indent (Negative Test Case)
# Testing bpkg_load() with a bpkg file that uses spaces instead of tabs to indent some of its hashes

### Test 8 − Empty Bpkg File (Negative Test Case)
# Testing bpkg_load() with an empty bpkg file

### Test 9 − Incorrect Number of Hashes (Negative Test Case)
# Testing bpkg_load() with a bpkg file that has nhashes and nchunks values much greater than the actual number of hashes provided

### Test 10 - Description − Corrupted Bpkg File #1 - Non-Hexadecimal Hashes (Negative Test Case)
# Testing bpkg_load() with a bpkg file that has hashes containing non-hexadecimal characters

### Test 11 - Description − Corrupted Bpkg File #2 - Hashes of Varying Lengths (Negative Test Case)
# Testing bpkg_load() with a bpkg file that has hashes of different lengths (16, 32, and 64 bytes)

### Test 12 - Existing File Check (Positive Test Case)
# Testing bpkg_file_check() with a bpkg object that references an existing data file

### Test 13 - Non-Existing File Check (Positive Test Case)
# Testing bpkg_file_check() with a bpkg object that references a non-existing data file

### Test 14 - Merkle Tree Construction (Positive Test Case)
# Testing merkle_tree_build() with a valid bpkg object and corresponding data file

### Test 15 - Get All Hashes (Positive Test Case)
# Testing bpkg_get_all_hashes() with a valid bpkg object

### Test 16 - Get Completed Chunks (Positive Test Case)
# Testing bpkg_get_completed_chunks() with a valid bpkg object and corresponding data file

### Test 17 - Get Min Hashes (Positive Test Case)
# Testing bpkg_get_min_completed_hashes() with a valid bpkg object and corresponding data file

### Test 18 − Failed Interity Check (Positive Test Case)
# Testing bpkg_get_min_completed_hashes() with a valid bpkg object but compromised data file; hence, we don't expect the root node to be returned when bpkg_get_min_completed_hashes() is called.

### Test 19 − Hashes of Ancestor (Positive Test Case)
# Testing bpkg_get_all_chunk_hashes_from_hash() with a valid bpkg object and valid ancestor hash

### Test 20 − Hashes of Fake Ancestor (Negative Test Case)
# Testing bpkg_get_all_chunk_hashes_from_hash() with a valid bpkg object and fake ancestor hash

### Test 21 − Hashes of Empty Ancestor (Edge Case)
# Testing bpkg_get_all_chunk_hashes_from_hash() with a valid bpkg object and empty ancestor hash
