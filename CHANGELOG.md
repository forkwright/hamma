# Changelog

## [0.1.1](https://github.com/forkwright/hamma/compare/v0.1.0...v0.1.1) (2026-07-16)


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
* **control:** accept node id peer removals ([7debc6b](https://github.com/forkwright/hamma/commit/7debc6b9cb485c8841cc567dc408b9ec339102d6))
* **control:** apply peer patch map deltas ([#33](https://github.com/forkwright/hamma/issues/33)) ([dfc3731](https://github.com/forkwright/hamma/commit/dfc37310b18482fe4b857d75c9a0f8af0db4ace6))
* **core:** parse peer patch map fields ([0686a66](https://github.com/forkwright/hamma/commit/0686a660a0e0c6a602c0b0db794fdbda8b1af7b5))
* **deps:** clear RUSTSEC-2026-0190 via anyhow lockfile bump ([#56](https://github.com/forkwright/hamma/issues/56)) ([2423485](https://github.com/forkwright/hamma/commit/2423485c5c48fd363624ba23ce7ff36bf7f70062))
* **lint:** add non_exhaustive to public error enums, mark public-key fields ([0355297](https://github.com/forkwright/hamma/commit/035529789281986e18ba65ccc9ee9513e552c911))
* **lint:** mechanical wins — allow→expect, indexing/slicing, casts, http→https ([9e339db](https://github.com/forkwright/hamma/commit/9e339db293a936ca048937346c4249446de1220a))
* **lint:** resolve clippy warnings in hamma-core and wire integration test ([#42](https://github.com/forkwright/hamma/issues/42)) ([079ad5e](https://github.com/forkwright/hamma/commit/079ad5ee0fa0f1af0a94553168f15957d51c44b2))
* **lint:** suppress pub-visibility for library API surface ([6d54674](https://github.com/forkwright/hamma/commit/6d54674a4a25f549fdf40775f6c06ea6fbf69266))
* **lint:** unblock kanon gate ([f93ff63](https://github.com/forkwright/hamma/commit/f93ff634f22724a1ccb19cdc0725d1e806f85f3e))
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
