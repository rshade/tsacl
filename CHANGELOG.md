# Changelog

## [0.2.0](https://github.com/rshade/tsacl/compare/v0.1.0...v0.2.0) (2026-11-10)


### ⚠ BREAKING CHANGES

* add --dry-run and an upload approval gate ([#63](https://github.com/rshade/tsacl/issues/63))
* run on the ax-go CLI runtime ([#62](https://github.com/rshade/tsacl/issues/62))

### Features

* add --dry-run and an upload approval gate ([#63](https://github.com/rshade/tsacl/issues/63)) ([9651ef5](https://github.com/rshade/tsacl/commit/9651ef5b7197a9f294247aae59f0145f096cd85d))
* run on the ax-go CLI runtime ([#62](https://github.com/rshade/tsacl/issues/62)) ([b26e911](https://github.com/rshade/tsacl/commit/b26e91155a2e48bc1cb98c7542bdae7a630022ed))
* serve the command tree over MCP and document the runtime ([#64](https://github.com/rshade/tsacl/issues/64)) ([3936662](https://github.com/rshade/tsacl/commit/39366627d7a36c7471340aae0e9b43ae1d9e39bd)), closes [#37](https://github.com/rshade/tsacl/issues/37)


### Bug Fixes

* **deps:** update module golang.org/x/term to v0.48.0 ([#71](https://github.com/rshade/tsacl/issues/71)) ([3108fc0](https://github.com/rshade/tsacl/commit/3108fc0cb442b2c3432125bab6f9d18a49c48966))
* report the module version for go install builds ([#60](https://github.com/rshade/tsacl/issues/60)) ([9402812](https://github.com/rshade/tsacl/commit/9402812dea7b77edb086db4197c8d29a7db2ff52))

## 0.1.0 (2026-11-07)


### ⚠ BREAKING CHANGES

* the `hujson-merge` and `acl-upload` binaries are no longer built.

### Features

* start the tsacl release line at 0.1.0 ([#49](https://github.com/rshade/tsacl/issues/49)) ([d94b8ca](https://github.com/rshade/tsacl/commit/d94b8caaa69b7359bf763bc6d3ef187f7cfbf1de))


### Bug Fixes

* **deps:** update module github.com/spf13/pflag to v1.1.0 ([#53](https://github.com/rshade/tsacl/issues/53)) ([baa9cb2](https://github.com/rshade/tsacl/commit/baa9cb2e30e023dfb123daaf23ec8153248921e8))
* harden against tailnet and identity leaks ([#55](https://github.com/rshade/tsacl/issues/55)) ([f02197d](https://github.com/rshade/tsacl/commit/f02197d68f3135190ffe8ac6ca30b7eca676eed7))
* stop the vocabulary probe at the client's ; suffix ([#50](https://github.com/rshade/tsacl/issues/50)) ([751e41f](https://github.com/rshade/tsacl/commit/751e41f010b2e70e270d75e79dc8f66cf3767d39))


### Code Refactoring

* fold hujson-merge and acl-upload into tsacl ([#54](https://github.com/rshade/tsacl/issues/54)) ([428eace](https://github.com/rshade/tsacl/commit/428eacecc0943da2c650c91e0705abdb5ea337d9))

## Changelog
