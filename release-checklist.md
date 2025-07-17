# Release checklist

biscuit-rust is part of the [Eclipse Biscuit](https://projects.eclipse.org/projects/technology.biscuit) project and as such needs to conform the eclipse project management guidelines.

Eclipse projects can only be released within the validity period of a release review (they last for 1 year).

## Pre-release

- make sure `README.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md` are present and up-to-date
- make sure `LICENSE` is present and that all source files are properly annotated with copyright and license information
- make sure dependency license information is correctly vetted:

```bash
 cargo tree -e normal --prefix none --no-dedupe | sort -u | grep -v '^[[:space:]]*$'  | grep -v biscuit  | sed -E 's|([^ ]+) v([^ ]+).*|crate/cratesio/-/\1/\2|' | java -jar org.eclipse.dash.licenses-1.1.0.jar - 
```
(you’ll need to download the [eclipse dash licenses jar](repo.eclipse.org/content/repositories/dash-licenses/org/eclipse/dash/org.eclipse.dash.licenses/))

This step should be automated at some point.

## Requesting a release review

If the most recent release review is outdated, we will need to start a new one on the [project governance page](https://projects.eclipse.org/projects/technology.biscuit/governance).

## Sync’d releases

Since the release review process is time-consuming and introduces latency, we should try to bundle release reviews in a single one.

We can assume that the following lifecycles are coupled:

- biscuit-parser (this repo)
- biscuit-quote (this repo)
- biscuit-auth (this repo)
- biscuit-capi (this repo)
- [biscuit-cli](https://github.com/eclipse-biscuit/biscuit-cli)
- [biscuit-component-wasm](https://github.com/eclipse-biscuit/biscuit-component-wasm)
- [biscuit-web-components](https://github.com/eclipse-biscuit/biscuit-web-components)

## Actually releasing stuff

Depending on the actual changes, only a subset of the crates may need to be released.

- update the versions in the `Cargo.toml` files;
- update the corresponding `CHANGELOG.md` files (ideally, try to update them in each PRs, in an _unreleased_ section to make things easier);
- merge the PR
- tag the new `main` commit with one tag per updated crate
  - `biscuit-parser-x.y.z`
  - `biscuit-quote-x.y.z`
  - `biscuit-auth-x.y.z`
  - `biscuit-capi-x.y.z` (this one will trigger an automated biscuit-capi release)
- publish the crates on crates.io, in this order:
  - `biscuit-parser`
  - `biscuit-quote`
  - `biscuit-auth`
