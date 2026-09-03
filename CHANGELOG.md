# Changelog

## [0.3.0](https://github.com/forkwright/hamma/compare/v0.2.0...v0.3.0) (2026-09-03)


### Features

* **phase-a:** derive public gate authority ([#123](https://github.com/forkwright/hamma/issues/123)) ([9aa9a56](https://github.com/forkwright/hamma/commit/9aa9a56223afdd47d7723104cd16a5c07d5fc722))


### Bug Fixes

* **ci:** attest release provenance only on public repos ([#134](https://github.com/forkwright/hamma/issues/134)) ([9a2b090](https://github.com/forkwright/hamma/commit/9a2b090f10426f9e7f3ae3b42a4933a30145b5cf))
* **ci:** make the dependabot auto-merge guard refuse instead of merging ([#90](https://github.com/forkwright/hamma/issues/90)) ([37d3f1b](https://github.com/forkwright/hamma/commit/37d3f1b09da9bbaaa7c7846caf3d2aafc21c1580)), closes [#89](https://github.com/forkwright/hamma/issues/89)
* **ci:** name the sha's real version on every action pin ([#119](https://github.com/forkwright/hamma/issues/119)) ([254f210](https://github.com/forkwright/hamma/commit/254f2104cc2e4eec891dc7799abef27d914968bc))
* **ci:** run CI on a pull request whose base is not main ([#92](https://github.com/forkwright/hamma/issues/92)) ([4358b47](https://github.com/forkwright/hamma/commit/4358b47d20d7b53a1aac28acffb5162955bb0e48))
* **control:** validate registration responses into an exhaustive state machine ([#95](https://github.com/forkwright/hamma/issues/95)) ([35f1b1f](https://github.com/forkwright/hamma/commit/35f1b1feaff81541f96a134514a2f1b5bfa734eb))
* **deps:** pin koinon to v0.1.0 and clear the mechanical lint-baseline entries ([#73](https://github.com/forkwright/hamma/issues/73)) ([8850220](https://github.com/forkwright/hamma/commit/8850220ca7c6c7f0beb0492c56f1496bdb96dad3)), closes [#57](https://github.com/forkwright/hamma/issues/57) [#61](https://github.com/forkwright/hamma/issues/61)
* **deps:** regenerate Cargo.lock so koinon matches the v0.2.0 the manifest already declares ([#124](https://github.com/forkwright/hamma/issues/124)) ([6622e4c](https://github.com/forkwright/hamma/commit/6622e4c4096b8600f3c9064d7a9b2d4e357fac02))
* **dictyon:** bound control-connection establishment with a deadline ([#76](https://github.com/forkwright/hamma/issues/76)) ([62596f7](https://github.com/forkwright/hamma/commit/62596f74da5dcff803a54b47122ffc1ad5d3354a)), closes [#52](https://github.com/forkwright/hamma/issues/52)
* **dictyon:** index peer removals and refuse to frame an unframable payload ([#78](https://github.com/forkwright/hamma/issues/78)) ([3f6011b](https://github.com/forkwright/hamma/commit/3f6011b98147a14bdcb41c67c33ac138bc8252c7)), closes [#55](https://github.com/forkwright/hamma/issues/55)
* **dictyon:** reject an over-limit key response before buffering it ([#79](https://github.com/forkwright/hamma/issues/79)) ([3ecf9ce](https://github.com/forkwright/hamma/commit/3ecf9ceb35c188ee4f87d16734f54e443839c603)), closes [#55](https://github.com/forkwright/hamma/issues/55)
* **dictyon:** validate server-supplied key-hex and routing-data fields at netmap ingestion ([#97](https://github.com/forkwright/hamma/issues/97)) ([2f0bd71](https://github.com/forkwright/hamma/commit/2f0bd7171d40e49fa4cc9a5968bc529838050238))
* **gate-attestation:** pin hybrid-gate.yml call to a SHA, closing the lint-debt gap ([#91](https://github.com/forkwright/hamma/issues/91)) ([32d4488](https://github.com/forkwright/hamma/commit/32d4488cf09b51ff8dc6fcaeef10976c4cbbe1be))
* **hamma-core:** decode a Node with no Addresses instead of failing the map update ([#72](https://github.com/forkwright/hamma/issues/72)) ([f8ef9b2](https://github.com/forkwright/hamma/commit/f8ef9b2e224504bae64b14e7f8057ff0169e0d89))
* **hamma-core:** drop a dead allow suppressing a lint that never fires ([#80](https://github.com/forkwright/hamma/issues/80)) ([fa1ddfb](https://github.com/forkwright/hamma/commit/fa1ddfb1c9f2c0d9e797fe8c9cd9ae50fa82bbe1)), closes [#57](https://github.com/forkwright/hamma/issues/57)
* **hamma-core:** enforce the documented config ranges at the deserialize boundary ([#77](https://github.com/forkwright/hamma/issues/77)) ([f3b2335](https://github.com/forkwright/hamma/commit/f3b23355386907f6deca1ff0f739f324261c4f47))
* **hamma-core:** redact the pre-auth key from AuthInfo debug output ([#74](https://github.com/forkwright/hamma/issues/74)) ([9b0b747](https://github.com/forkwright/hamma/commit/9b0b747b010b0ca6fa21290cb482b4f0a77b9824)), closes [#57](https://github.com/forkwright/hamma/issues/57)
* **handshake:** chunked AsyncRead header reader ([#81](https://github.com/forkwright/hamma/issues/81)) ([00c38b9](https://github.com/forkwright/hamma/commit/00c38b9078f2f0ec1c3a9570047abb4f46fbfd8c)), closes [#55](https://github.com/forkwright/hamma/issues/55)
* **lint:** burn down the kanon-lint debt baseline and delete it ([#86](https://github.com/forkwright/hamma/issues/86)) ([8c420f3](https://github.com/forkwright/hamma/commit/8c420f3df2e89dbae061f9c4b5081b1275e7345b)), closes [#57](https://github.com/forkwright/hamma/issues/57)
* **llms:** classify dictyon as a library, not a CLI, in the discovery corpus ([#87](https://github.com/forkwright/hamma/issues/87)) ([c1f7815](https://github.com/forkwright/hamma/commit/c1f781556cf909d1ac52a77b984c5f001d7a1b17)), closes [#85](https://github.com/forkwright/hamma/issues/85)
* **mitos:** zeroize AuthInfo::auth_key on drop ([#93](https://github.com/forkwright/hamma/issues/93)) ([a39bca4](https://github.com/forkwright/hamma/commit/a39bca4b040e613991983554444c0745259caf30))
* **noise:** add FrameTooLarge error taxonomy ([#83](https://github.com/forkwright/hamma/issues/83)) ([e023a1a](https://github.com/forkwright/hamma/commit/e023a1aa5f8a1b8462ea464472c6db0c86518464)), closes [#55](https://github.com/forkwright/hamma/issues/55)
* **noise:** validate hex length before allocation ([#82](https://github.com/forkwright/hamma/issues/82)) ([8b8bad6](https://github.com/forkwright/hamma/commit/8b8bad62b30e3df1149ecafc6ac737acd0c2482c)), closes [#55](https://github.com/forkwright/hamma/issues/55)
* **release:** derive the path-dep version pin release-please patches ([#75](https://github.com/forkwright/hamma/issues/75)) ([043cb5a](https://github.com/forkwright/hamma/commit/043cb5a8dc6b576cf3fbc284419c82b38fbe76ae))
* **release:** drop the component/package-name fields that wedge release-please ([#121](https://github.com/forkwright/hamma/issues/121)) ([6b7380f](https://github.com/forkwright/hamma/commit/6b7380f05a511ad2df879238c7768d89c2f7d8c8))


### Documentation

* refresh the _llm state corpus and README status against the tree ([#120](https://github.com/forkwright/hamma/issues/120)) ([20a7195](https://github.com/forkwright/hamma/commit/20a719576289eb1949facc56623428bebdb4dbb6))

## [0.2.0](https://github.com/forkwright/hamma/compare/v0.1.0...v0.2.0) (2026-07-28)


### Features

* **_llm:** add T0 corpus per [#667](https://github.com/forkwright/hamma/issues/667) / [#673](https://github.com/forkwright/hamma/issues/673) fleet rollout ([#10](https://github.com/forkwright/hamma/issues/10)) ([0568f51](https://github.com/forkwright/hamma/commit/0568f515368244f21fa5745974df0bf3a715f299))
* **control:** instrument async control client entry points ([#37](https://github.com/forkwright/hamma/issues/37)) ([e80622f](https://github.com/forkwright/hamma/commit/e80622f38c80da66ba37131a0264280882313afb)), closes [#20](https://github.com/forkwright/hamma/issues/20)
* **control:** support zstd map responses ([dd5ab90](https://github.com/forkwright/hamma/commit/dd5ab904a26bc09810a4410c666b3b5e29d1b756))
* **dictyon:** add TCP/TLS connection, registration, and map streaming ([a311d8a](https://github.com/forkwright/hamma/commit/a311d8a85e3b9d14977030063ee6d13a442ea32f))
* **dictyon:** control protocol types and map response parser ([dfc25c7](https://github.com/forkwright/hamma/commit/dfc25c7d63b30935619e94504bf777c59926da8f))
* **dictyon:** migrate tracing init to koinon ([e5a4260](https://github.com/forkwright/hamma/commit/e5a4260ee47d4d2208cf8ac23ed9f34277fdf569))
* **dictyon:** Noise IK handshake, key types, HTTP transport skeleton ([aafea4f](https://github.com/forkwright/hamma/commit/aafea4f90e83f5ae25f17a49fedac9545df3edb3))
* **dictyon:** trace wire noise transport phases ([#38](https://github.com/forkwright/hamma/issues/38)) ([2d80231](https://github.com/forkwright/hamma/commit/2d802316c6cdb86ec4dcc6cd8ccb47657c030499)), closes [#20](https://github.com/forkwright/hamma/issues/20)


### Bug Fixes

* **cargo:** track lockfile for pinned rust toolchain ([#30](https://github.com/forkwright/hamma/issues/30)) ([e6a2f01](https://github.com/forkwright/hamma/commit/e6a2f0134fbd249103c9aed0a54af0f5ea05b308)), closes [#29](https://github.com/forkwright/hamma/issues/29)
* **ci:** resolve cargo-deny + MSRV + binary smoke failures ([#13](https://github.com/forkwright/hamma/issues/13)) ([9bb4533](https://github.com/forkwright/hamma/commit/9bb4533aa609058d2516a067492604b03a4fb610))
* **ci:** waive gate attestation by PR author, not by github.actor ([#69](https://github.com/forkwright/hamma/issues/69)) ([764422e](https://github.com/forkwright/hamma/commit/764422e3e7d0403f3cb3c4582cb93757a63d580d)), closes [#68](https://github.com/forkwright/hamma/issues/68)
* **control:** accept node id peer removals ([7debc6b](https://github.com/forkwright/hamma/commit/7debc6b9cb485c8841cc567dc408b9ec339102d6))
* **control:** apply peer patch map deltas ([#33](https://github.com/forkwright/hamma/issues/33)) ([dfc3731](https://github.com/forkwright/hamma/commit/dfc37310b18482fe4b857d75c9a0f8af0db4ace6))
* **core:** parse peer patch map fields ([0686a66](https://github.com/forkwright/hamma/commit/0686a660a0e0c6a602c0b0db794fdbda8b1af7b5))
* **deps:** clear RUSTSEC-2026-0190 via anyhow lockfile bump ([#56](https://github.com/forkwright/hamma/issues/56)) ([2423485](https://github.com/forkwright/hamma/commit/2423485c5c48fd363624ba23ce7ff36bf7f70062))
* **lint:** add non_exhaustive to public error enums, mark public-key fields ([0355297](https://github.com/forkwright/hamma/commit/035529789281986e18ba65ccc9ee9513e552c911))
* **lint:** mechanical wins — allow→expect, indexing/slicing, casts, http→https ([9e339db](https://github.com/forkwright/hamma/commit/9e339db293a936ca048937346c4249446de1220a))
* **lint:** resolve clippy warnings in hamma-core and wire integration test ([#42](https://github.com/forkwright/hamma/issues/42)) ([079ad5e](https://github.com/forkwright/hamma/commit/079ad5ee0fa0f1af0a94553168f15957d51c44b2))
* **lint:** suppress pub-visibility for library API surface ([6d54674](https://github.com/forkwright/hamma/commit/6d54674a4a25f549fdf40775f6c06ea6fbf69266))
* **lint:** unblock kanon gate ([f93ff63](https://github.com/forkwright/hamma/commit/f93ff634f22724a1ccb19cdc0725d1e806f85f3e))
* **release:** bump the internal hamma-core pin and Cargo.lock with the release ([#71](https://github.com/forkwright/hamma/issues/71)) ([dfdfc35](https://github.com/forkwright/hamma/commit/dfdfc356ff333a74d3d5be801f731197ad6630d9)), closes [#70](https://github.com/forkwright/hamma/issues/70)
* resolve 1 lint violations via local ([#8](https://github.com/forkwright/hamma/issues/8)) ([0d4aa84](https://github.com/forkwright/hamma/commit/0d4aa84fb3a44bee7e2267c68b742f79af96eaad))


### Refactoring

* **dictyon:** replace expect with ? and rename test helper ([#9](https://github.com/forkwright/hamma/issues/9)) ([655b783](https://github.com/forkwright/hamma/commit/655b783b3094b2153429db9f4c63ae2dbf865f59))
* **lint:** split oversized modules; add hamma-core integration tests ([fa8f54f](https://github.com/forkwright/hamma/commit/fa8f54fb0a8c4739ab68a3127b230d5d2643b47c))
* rename plegma→hamma, plegma-core→hamma-core ([a67f792](https://github.com/forkwright/hamma/commit/a67f7922095bff0c899d7dad169c68a0f38a3e44))


### Documentation

* add CLAUDE.md precedence preamble (forge[#153](https://github.com/forkwright/hamma/issues/153)) ([e91ebea](https://github.com/forkwright/hamma/commit/e91ebeae74dcd712e3c1d384560f77ae01365fe6))
* add CONTRIBUTING.md for 05e cutover ([#1](https://github.com/forkwright/hamma/issues/1)) ([9dd5f87](https://github.com/forkwright/hamma/commit/9dd5f87e9d2eb0c48d25a1241afcfda391be1501))
* add llms.txt per kanon doc standards (refs [#10](https://github.com/forkwright/hamma/issues/10)) ([#11](https://github.com/forkwright/hamma/issues/11)) ([e869fe1](https://github.com/forkwright/hamma/commit/e869fe15cc4f9c681c668aa06552e244e622de3b))
* **agents:** add AGENTS.md per fleet repo-structure standard ([#40](https://github.com/forkwright/hamma/issues/40)) ([0382da1](https://github.com/forkwright/hamma/commit/0382da1df3a1d61398594c62fcc583c87aec0dd1))
* **hamma:** align pre-alpha status ([#6](https://github.com/forkwright/hamma/issues/6)) ([873a6c3](https://github.com/forkwright/hamma/commit/873a6c30bc4d892df723f90d5507ea447af440bd))
* **hamma:** replace standards copy with kanon pointer ([#8](https://github.com/forkwright/hamma/issues/8)) ([324ff18](https://github.com/forkwright/hamma/commit/324ff18b2fd4e0b5f9d07be88476b238d8633067))
* sanitize local bootstrap docs ([4c57d40](https://github.com/forkwright/hamma/commit/4c57d4033ea56ceb745f4e8fc84e66c6eb1ee0c6))
* **standards:** add canonical standards from kanon ([#1](https://github.com/forkwright/hamma/issues/1)) ([81e5007](https://github.com/forkwright/hamma/commit/81e5007805c21e2a5892313ddaa8d30628ece3a6))

## Changelog
