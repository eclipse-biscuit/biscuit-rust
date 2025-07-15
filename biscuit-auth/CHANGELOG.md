# `6.0.0`

- support for `pem` / `der` private and public keys (#212 and #265)
- [biscuit-datalog 3.3](https://www.biscuitsec.org/blog/biscuit-3-3/) support (#217 and #271)
- Support for P256 signatures (#108)
- `query_exactly_once()` (#260) (Baran Yildirim)

## Breaking changes

- Syntax updates related to [biscuit-datalog 3.3](https://www.biscuitsec.org/blog/biscuit-3-3/) support (#217) (sets are now denoted with `{}`, `==` is now lenient equals).
- Separate `AuthorizerBuilder` from `Authorizer` (#250, #255, #274)
- include algorithm prefix in public/private key strings (#261, #276)
- `UnverifiedBiscuit.external_public_keys()` now returns `PublicKey`s, not byte vecs (#263)

# `5.0.0`

- fix [GHSA-rgqv-mwc3-c78m](https://github.com/biscuit-auth/biscuit/security/advisories/GHSA-rgqv-mwc3-c78m)

# `4.1.1`

- remove PKCS8 file loading functions (#208)

# `4.1.0` (yanked)

**This release was yanked because PKCS8 file loading functions, activated by the `pem` feature, could not compile. Those functions are removed in #208. PKCS8 parsing from buffers is still available**

- fix: typo in documentation (#190) (Rémi Duraffort)
- fix: include all authorizer facts and rules when using `Display` (#195) (Clément Delafargue)
- Add optional support for PEM/DER parsing (#204) (Baran Yildirim)

# `4.0.0`

- macros for individual statements: `fact!`, `check!`, `policy!` (#175, #176) (Clément Delafargue)
- fix: parse empty strings (#177) (Clément Delafargue)
- breaking: update ed25519-dalek to 2.0, rand_core to 0.6 and rand to 0.8 (#136) (Geoffroy Couprie)
- Optional support for Biscuit Web Key representation (#173) (Clément Delafargue)
- expose authorizer runtime values (#174) (Clément Delafargue)

# `3.2.0`

- Support for chained method calls (#153) (Geoffroy Couprie)
- Prevent facts from carrying variables (#154) (Clément Delafargue)
- Make the authorizer text representation stable (#155) (Clément Delafargue)
- Improve samples (#156, #158, #160, #161) (Clément Delafargue, Geoffroy Couprie)
- Fix rule symbol translation in snapshots (#159) (Geoffroy Couprie)
- Make the TTL check helper more compact (#162) (Clément Delafargue)
- Root key provider improvements (#164, #168) (Tristan Germain)
- Allow reading a token root key id (#167) (Clément Delafargue)

# `3.1.0`

- Add missing support for equality on booleans (#149) (Geoffroy Couprie)
- `ThirdPartyBlock` can be cloned (#145) (Clément Delafargue)

# `3.0.0`

- Fix rendering of set terms (#140) (Clément Delafargue)
- handle expression execution failure (#135) (Geoffroy Couprie)
- support for authorizer snapshots (#127, #133, #137) (Geoffroy Couprie, Clément Delafargue)
- Add support for != in datalog (#128) (Clément Delafargue)
- Improved `Authorizer::print_world()` (#126, #129) (Geoffroy Couprie)

# `3.0.0-alpha4`

- Support for bitwise operators on ints (#122) (Nathan Walsh)
- Fix operators precedence (#121) (Clément Delafargue)
- Fix public key display in `UnverifiedBiscuit` (#119) (Clément Delafargue)
- Add `Display` implementation for `Biscuit` (Bastien Vigneron)

# `3.0.0-alpha3`

- Support for `check all` (#107) (Geoffroy Couprie)
- Add `Debug` implementation for third-party requests (#116) (Pierre Tondereau)
- Add the current block to the default rule scope (#115) (Clément Delafargue, Geffroy Couprie)
- Macro overhaul (#109) (Till Höppner)
- Support for using UUIDs as terms (#110) (Till Höppner)
- Make the `Convert` trait public (#106) (Akanoa)

# `3.0.0-alpha2`

- Fix clippy warnings (#82) (Matthias Vogelgesang)
- Remove panics from parser (#102) (Pierre Tondereau)
- Use rule scopes in authorizer query (#100) (Clément Delafargue)
- API updates (#98, #99) (Geoffroy Couprie, Clément Delafargue)
- 3rd party requests API updates (#96) (Geoffroy Couprie)

# `3.0.0-alpha1`

- Third-party blocks (#79, #92, #93, #94) (Geoffroy Couprie, Clément Delafargue)
- API cleanup (#86, #88, #89) (Geoffroy Couprie, Clément Delafargue)
- Improved macro errors (#77) (Clément Delafargue)


# `2.2.0`

- Datalog macros (#76) (Clément Delafargue)
- Add `Authorizer::dump_code` (Clément Delafargue)
- Parameter interpolation (#69, #71) (Clément Delafargue)
- Fix deprecation warnings (#73) (Pierre Tondereau)
- Remove symbols leftovers (#68) (Clément Delafargue)
- Biscuit sealing improvements (#64, #65) (Clément Delafargue)
