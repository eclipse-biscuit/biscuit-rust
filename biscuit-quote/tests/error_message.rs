/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
*/
//! Test for compilation error messages.
//! Compile each file in tests/error_message/ and check that error messages haven't changed.
//!
//! run with `TRYBUILD=overwrite cargo test` to update the .stderr files containing expected error messages 

#[test]
fn test_error_msg () {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/error_message/*.rs");
}
