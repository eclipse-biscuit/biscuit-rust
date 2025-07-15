# Eclipse Biscuit authentication and authorization token

Eclipse Biscuit is an authorization token for microservices architectures with the following properties:

- decentralized validation: any node could validate the token only with public information;
- offline delegation: a new, valid token can be created from another one by attenuating its rights, by its holder, without communicating with anyone;
- capabilities based: authorization in microservices should be tied to rights related to the request, instead of relying to an identity that might not make sense to the authorizer;
- flexible rights managements: the token uses a logic language to specify attenuation and add bounds on ambient data;
- small enough to fit anywhere (cookies, etc).

Non goals:

- This is not a new authentication protocol. Biscuit tokens can be used as opaque tokens delivered by other systems such as OAuth.
- Revocation: while tokens come with expiration dates, revocation requires external state management.

# Usage

In this example we will see how we can create a token, add some checks, serialize and deserialize a token, append more checks, and validate those checks in the context of a request:

```rust
extern crate biscuit_auth as biscuit;

use biscuit::{KeyPair, Biscuit, error};

fn main() -> Result<(), error::Token> {
  // let's generate the root key pair. The root public key will be necessary
  // to verify the token
  let root = KeyPair::new();
  let public_key = root.public();

  // creating a first token
  let token1 = {
    // the first block of the token is the authority block. It contains global
    // information like which operation types are available
    let biscuit = biscuit!(r#"
          right("/a/file1.txt", "read");
          right("/a/file1.txt", "write");
          right("/a/file2.txt", "read");
          right("/b/file3.txt", "write");
    "#).build(&root)?; // the first block is signed

    println!("biscuit (authority): {}", biscuit);

    biscuit.to_vec()?
  };

  // this token is only 258 bytes, holding the authority data and the signature
  assert_eq!(token1.len(), 258);

  // now let's add some restrictions to this token
  // we want to limit access to `/a/file1.txt` and to read operations
  let token2 = {
    // the token is deserialized, the signature is verified
    let deser = Biscuit::from(&token1, root.public())?;

    // biscuits can be attenuated by appending checks
    let biscuit = deser.append(block!(r#"
      // checks are implemented as logic rules. If the rule produces something,
      // the check is successful
      // here we verify the presence of a `resource` fact with a path set to "/a/file1.txt"
      // and a read operation
      check if resource("/a/file1.txt"), operation("read");
    "#));
    println!("biscuit (authority): {}", biscuit);

    biscuit.to_vec()?
  };

  // this new token fits in 400 bytes
  assert_eq!(token2.len(), 400);

  /************** VERIFICATION ****************/

  // let's deserialize the token:
  let biscuit2 = Biscuit::from(&token2, public_key)?;

  // let's define 3 authorizers (corresponding to 3 different requests):
  // - one for /a/file1.txt and a read operation
  // - one for /a/file1.txt and a write operation
  // - one for /a/file2.txt and a read operation

  let v1 = authorizer!(r#"
     resource("/a/file1.txt");
     operation("read");
     
     // an authorizer can come with allow/deny policies. While checks are all tested
     // and must all succeed, allow/deny policies are tried one by one in order,
     // and we stop verification on the first that matches
     //
     // here we will check that the token has the corresponding right
     allow if right("/a/file1.txt", "read");
     // explicit catch-all deny. here it is not necessary: if no policy
     // matches, a default deny applies
     deny if true;
  "#)
  .build(&biscuit2)?;

  let mut v2 = authorizer!(r#"
     resource("/a/file1.txt");
     operation("write");
     allow if right("/a/file1.txt", "write");
  "#)
  .build(&biscuit2)?;
  
  let mut v3 = authorizer!(r#"
     resource("/a/file2.txt");
     operation("read");
     allow if right("/a/file2.txt", "read");
  "#)
  .build(&biscuit2)?;

  // the token restricts to read operations:
  assert!(v1.authorize().is_ok());
  // the second authorizer requested a read operation
  assert!(v2.authorize().is_err());
  // the third authorizer requests /a/file2.txt
  assert!(v3.authorize().is_err());

  Ok(())
}
```

## Concepts

### blocks

A Biscuit token is made with a list of blocks defining data and checks that must
be validated upon reception with a request. Any failed check will invalidate the
entire token.

If you hold a valid token, it is possible to add a new block to restrict further
the token, like limiting access to one particular resource, or adding a short
expiration date. This will generate a new, valid token. This can be done offline,
without asking the original token creator.

On the other hand, if a block is modified or removed, the token will fail the
cryptographic signature verification.

### Cryptography

Biscuit tokens get inspiration from macaroons and JSON Web Tokens, reproducing useful features from both:

- offline delegation like macaroons
- based on public key cryptography like JWT, so any application holding the root public key can verify a token (while macaroons are based on a root shared secret)

### A logic language for authorization policies: Datalog

We rely on a modified version of Datalog, that can represent complex behaviours in a compact form, and add flexible constraints on data.

Here are examples of checks that can be implemented with that language:

- valid if the requested resource is "file.txt" and the operation is "read"
- valid if current time is before January 1st 2030, 00h00mn00s UTC
- source IP is in set [1.2.3.4, 5.6.7.8]
- resource matches prefix "/home/biscuit/data/"
- But it can also combine into more complex patterns, like: right is read if user has read or user is member of organisation and organisation has read right or other user with read right has delegated to user.

Like Datalog, this language is based around facts and rules, but with some slight modifications:

- Blocks can provide facts but they are not visible from other blocks. They contain rules that use facts from the current block, or from the authority and ambient contexts. If all rules in a block succeed, the block is validated.

A check rule requires the presence of one or more facts, and can have additional expressions on these facts. It is possible to create rules like these ones:

- check if resource("file1")
- check if resource($path) & owner("user1", $path) // the $path represents a variable. We look for a set of paths where $path resolves to the same value everywhere
- check if time($t), $t < 2019-02-05T23:00:00Z // expiration date
- check if application($app), operation($op), user($user), right("app", $app, $op), owner($user, $app), credit($user, $amount), $amount > 0 // verifies that the user owns the applications, the application has the right on the operation, there's a credit information for the operation, and the credit is larger than 0

### Symbols and symbol tables
To reduce the size of tokens, the format holds a symbol table containing strings. Any string is then serialized as an index into this table.

They can be used for pretty printing of a fact or rule. As an example, with a table containing ["resource", "operation", "read", "rule1", "file.txt"], we could have the following rule: `#4 <- #0(#5) & #1(#2)` that would be printed as `rule1 <- resource("file.txt"), operation("read")`

biscuit implementations come with a default symbol table to avoid transmitting frequent values with every token.

# C bindings

You can find the C bindings and documentation in the [`biscuit-capi`](./biscuit-capi/README.md) crate.

## License

Licensed under Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be licensed as above, without any additional terms or
conditions.
