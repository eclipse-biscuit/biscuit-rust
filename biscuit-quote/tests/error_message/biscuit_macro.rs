/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! Triggers compilation errors on the biscuit! proc macro.

use biscuit_quote::biscuit;

fn main() {
    // empty biscuit, no error
    let _ = biscuit!("");

    // a valid content that doesn't trigger any arror
    let _ = biscuit!(r#"
        can_view("/file1");
        can_view("/file2");
        file("/file1");
    "#);

    // parsing error
    let _ = biscuit!(r#"
        can_view("/file1");
        typo can_view("/file2");
        file("/file1");
    "#);

    // parsing error, missing semicolon
    let _ = biscuit!(r#"
        can_view("/file1")
        can_view("/file2");
    "#);

    let _ = biscuit!(r#"
        can_view($file) <- right($file, "read");
        allow if file($f), operation($op), right($f, $op);
    "#);
}