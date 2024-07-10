#include "chk/pkgchk.h"
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>


// Test 1 − Valid Bpkg File (Positive Test Case)
static void load_valid_bpkg_test(void **state) {
    struct bpkg_obj *bpkg = bpkg_load("tests/pkgs/file1.bpkg");
    // Check that a bpkg object is created
    assert_non_null(bpkg);
    bpkg_obj_destroy(bpkg);
}


// Test 2 − Large Number of Hashes (Positive Test Case)
static void load_large_bpkg_test(void **state) {
    struct bpkg_obj *bpkg = bpkg_load("tests/pkgs/file2.bpkg");
    // Check that a bpkg object is created
    assert_non_null(bpkg);
    bpkg_obj_destroy(bpkg);
}


// Test 3 - Fake Path (Negative Test Case)
static void load_fake_bpkg_test(void **state) {
    // Check that no bpkg object is created
    assert_null(bpkg_load("path/to/fake.bpkg"));
} 


// Test 4 − Invalid Bpkg File #1 - Invalid Identifier (Negative Test Case)
static void load_invalid_ident1(void **state) {
    // Check that no bpkg object is created
    assert_null(bpkg_load("tests/pkgs/file4.bpkg"));
}


// Test 5 − Invalid Identifier #2 - Too Short (Negative Test Case)
static void load_invalid_ident2(void **state) {
    // Check that no bpkg object is created
    assert_null(bpkg_load("tests/pkgs/file5.bpkg"));
}


// Test 6 − Invalid Bpkg File #2 - Missing Values (Negative Test Case)
static void load_invalid_bpkg_test1(void **state) {
    // Check that no bpkg object is created
    assert_null(bpkg_load("tests/pkgs/file6.bpkg"));
}


// Test 7 − Invalid Bpkg File #3 - Invalid Indent (Negative Test Case)
static void load_invalid_bpkg_test2(void **state) {
    // Check that no bpkg object is created
    assert_null(bpkg_load("tests/pkgs/file7.bpkg"));
}


// Test 8 − Empty Bpkg File (Negative Test Case)
static void load_empty_bpkg_test(void **state) {
    // Check that no bpkg object is created
    assert_null(bpkg_load("tests/pkgs/file8.bpkg"));
}


// Test 9 − Incorrect Number of Hashes (Negative Test Case)
static void load_incorrect_bpkg_test(void **state) {
    // Check that no bpkg object is created
    assert_null(bpkg_load("tests/pkgs/file9.bpkg"));
}


// Test 10 − Corrupted Bpkg File #1 - Non-Hexadecimal Hashes (Negative Test Case)
static void load_corrupted_bpkg_test1(void **state) {
    // Check that no bpkg object is created
    assert_null(bpkg_load("tests/pkgs/file10.bpkg"));
}


// Test 11 − Corrupted Bpkg File #2 - Hashes of Varying Lengths (Negative Test Case)
static void load_corrupted_bpkg_test2(void **state) {
    // Check that no bpkg object is created
    assert_null(bpkg_load("tests/pkgs/file11.bpkg"));
}


// Test 12 - Existing File Check (Positive Test Case)
static void existing_file_check_test(void **state) {
    struct bpkg_obj *bpkg = bpkg_load("tests/pkgs/file1.bpkg");
    struct bpkg_query qry = bpkg_file_check(bpkg);
    // Check that the existing file is detected
    assert_string_equal(qry.hashes[0], "File Exists");
    bpkg_query_destroy(&qry);
    bpkg_obj_destroy(bpkg);
}


// Test 13 - Non-Existing File Check (Positive Test Case)
static void non_existing_file_check_test(void **state) {
    struct bpkg_obj *bpkg = bpkg_load("tests/pkgs/file13.bpkg");
    struct bpkg_query qry = bpkg_file_check(bpkg);
    // Check that the missing file is created
    assert_string_equal(qry.hashes[0], "File Created");
    remove("tests/pkgs/file13.data");
    bpkg_query_destroy(&qry);
    bpkg_obj_destroy(bpkg);
    
} 


// Test 14 − Merkle Tree Construction (Positive Test Case)
static void merkle_tree_build_test(void **state) {
    struct bpkg_obj *bpkg = bpkg_load("tests/pkgs/file1.bpkg");
    struct merkle_tree *tree = merkle_tree_build(bpkg);
    // Check that the tree contains the correct number of nodes
    assert_int_equal(tree->n_nodes, bpkg->nhashes + bpkg->nchunks);
    merkle_tree_destroy(tree);
    bpkg_obj_destroy(bpkg);
}


// Test 15 - Get All Hashes (Positive Test Case)
static void get_all_hashes_test(void **state) {
    struct bpkg_obj *bpkg = bpkg_load("tests/pkgs/file1.bpkg");
    struct bpkg_query qry = bpkg_get_all_hashes(bpkg);
    // Check that all hashes are returned
    assert_int_equal(qry.len, bpkg->nhashes + bpkg->nchunks);
    bpkg_query_destroy(&qry);
    bpkg_obj_destroy(bpkg);
}


// Test 16 - Get Completed Chunks (Positive Test Case)
static void get_completed_chunks_test(void **state) {
    struct bpkg_obj *bpkg = bpkg_load("tests/pkgs/file1.bpkg");
    struct bpkg_query qry = bpkg_get_completed_chunks(bpkg);
    // Check that all chunk hashes are returned
    assert_int_equal(qry.len, bpkg->nchunks);
    bpkg_query_destroy(&qry);
    bpkg_obj_destroy(bpkg);
}


// Test 17 − Get Min Hashes (Positive Test Case)
static void get_min_hashes_test(void **state) {
    struct bpkg_obj *bpkg = bpkg_load("tests/pkgs/file1.bpkg");
    struct bpkg_query qry = bpkg_get_min_completed_hashes(bpkg);
    // Make sure the single root node not returned
    assert_int_equal(qry.len, 1);
    bpkg_query_destroy(&qry);
    bpkg_obj_destroy(bpkg);
}


// Test 18 − Failed Interity Check (Positive Test Case)
static void failed_integrity_check_test(void **state) {
    struct bpkg_obj *bpkg = bpkg_load("tests/pkgs/file18.bpkg");
    struct bpkg_query qry = bpkg_get_min_completed_hashes(bpkg);
    // Make sure the single root node is not returned
    assert_int_not_equal(qry.len, 1);
    bpkg_query_destroy(&qry);
    bpkg_obj_destroy(bpkg);
}


// Test 19 − Hashes of Ancestor (Positive Test Case)
static void get_hashes_of_ancestor_test(void **state) {
    struct bpkg_obj *bpkg = bpkg_load("tests/pkgs/file1.bpkg");
    struct bpkg_query qry = bpkg_get_all_chunk_hashes_from_hash(bpkg, "6b003fdf993699058a4925a2b91946dfe4f016f3e287c0f45f12a700f83ab4c1");
    // Check that no hashes are returned
    assert_int_equal(qry.len, bpkg->nchunks);
    bpkg_query_destroy(&qry);
    bpkg_obj_destroy(bpkg);
}


// Test 20 − Hashes of Fake Ancestor (Negative Test Case)
static void get_hashes_of_fake_ancestor_test(void **state) {
    struct bpkg_obj *bpkg = bpkg_load("tests/pkgs/file1.bpkg");
    struct bpkg_query qry = bpkg_get_all_chunk_hashes_from_hash(bpkg, "fake-hash-b93f760f79fc3474-fake-hash-4081f5b808b97207e-fake-hash");
    // Check that no hashes are returned
    assert_int_equal(qry.len, 0);
    bpkg_query_destroy(&qry);
    bpkg_obj_destroy(bpkg);
}


// Test 21 − Hashes of Empty Ancestor (Edge Case)
static void get_hashes_of_empty_ancestor_test(void **state) {
    struct bpkg_obj *bpkg = bpkg_load("tests/pkgs/file1.bpkg");
    struct bpkg_query qry = bpkg_get_all_chunk_hashes_from_hash(bpkg, "");
    // Check that no hashes are returned
    assert_int_equal(qry.len, 0);
    bpkg_query_destroy(&qry);
    bpkg_obj_destroy(bpkg);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(load_valid_bpkg_test),
        cmocka_unit_test(load_large_bpkg_test),
        cmocka_unit_test(load_fake_bpkg_test),
        cmocka_unit_test(load_invalid_ident1),
        cmocka_unit_test(load_invalid_ident2),
        cmocka_unit_test(load_invalid_bpkg_test1),
        cmocka_unit_test(load_invalid_bpkg_test2),
        cmocka_unit_test(load_empty_bpkg_test),
        cmocka_unit_test(load_incorrect_bpkg_test),
        cmocka_unit_test(load_corrupted_bpkg_test1),
        cmocka_unit_test(load_corrupted_bpkg_test2),
        cmocka_unit_test(existing_file_check_test),
        cmocka_unit_test(non_existing_file_check_test),
        cmocka_unit_test(merkle_tree_build_test),
        cmocka_unit_test(get_all_hashes_test),
        cmocka_unit_test(get_completed_chunks_test),
        cmocka_unit_test(get_min_hashes_test),
        cmocka_unit_test(failed_integrity_check_test),
        cmocka_unit_test(get_hashes_of_ancestor_test),
        cmocka_unit_test(get_hashes_of_fake_ancestor_test),
        cmocka_unit_test(get_hashes_of_empty_ancestor_test),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}