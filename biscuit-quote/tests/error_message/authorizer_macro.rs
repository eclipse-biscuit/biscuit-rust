/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! Triggers compilation errors on the authorizer! proc macro.

use biscuit_quote::authorizer;

fn main() {
    // empty biscuit, no error
    let _ = authorizer!("");

    // a valid content that doesn't trigger any error
    let _ = authorizer!(r#"
        can_view($file) <- right($file, "read");
        allow if file($f), operation($op), right($f, $op);
    "#);

    // syntax error, missing < in <- arrow
    let _ = authorizer!(r#"
        can_view($file) - right($file, "read");
        allow if file($f), operation($op), right($f, $op);
    "#);

    // unbound variable
    let _ = authorizer!(r#"
        can_view($file, $unused) <- right($file, "read");
        allow if file($f), operation($op), right($f, $op);
    "#);
}