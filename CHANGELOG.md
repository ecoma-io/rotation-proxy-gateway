# Changelog

## [0.5.0](https://github.com/ecoma-io/rotation-proxy-gateway/compare/v0.4.0...v0.5.0) (2026-09-25)


### Features

* **routing:** scope CONNECT targets to candidate route sets ([#74](https://github.com/ecoma-io/rotation-proxy-gateway/issues/74)) ([e33c92e](https://github.com/ecoma-io/rotation-proxy-gateway/commit/e33c92e423bd9562023525b25bfb9ad6f62c22cd))


### Bug Fixes

* **cmd:** harden graceful shutdown for stuck-dial session ([#66](https://github.com/ecoma-io/rotation-proxy-gateway/issues/66)) ([#71](https://github.com/ecoma-io/rotation-proxy-gateway/issues/71)) ([c2fd7d2](https://github.com/ecoma-io/rotation-proxy-gateway/commit/c2fd7d27cac888b5391089262ebac0ef0275c64a))
* **routing:** harden tunnel opacity and hostname matching ([#76](https://github.com/ecoma-io/rotation-proxy-gateway/issues/76)) ([c0cf2d6](https://github.com/ecoma-io/rotation-proxy-gateway/commit/c0cf2d676235f0dd24c953120691e11070ecffec))

## [0.4.0](https://github.com/ecoma-io/rotation-proxy-gateway/compare/v0.3.1...v0.4.0) (2026-09-23)


### Features

* **rotation:** per-route rotationCount and ipRevisitCount in /status ([#63](https://github.com/ecoma-io/rotation-proxy-gateway/issues/63)) ([71b3366](https://github.com/ecoma-io/rotation-proxy-gateway/commit/71b3366bee6ca2c8af23ebdd9e025fdf34cff9b8))


### Bug Fixes

* **proxyserver:** release the in-flight hold of a failed attempt immediately ([#65](https://github.com/ecoma-io/rotation-proxy-gateway/issues/65)) ([7ecedf9](https://github.com/ecoma-io/rotation-proxy-gateway/commit/7ecedf916e0549fe83c501eff0b8a6a77af7aa1d))
* **rotation:** commit a rotation only into the live pool generation ([#70](https://github.com/ecoma-io/rotation-proxy-gateway/issues/70)) ([dbb8c48](https://github.com/ecoma-io/rotation-proxy-gateway/commit/dbb8c489fde8a0a97c9ce6a8534fb6521795e46f)), closes [#67](https://github.com/ecoma-io/rotation-proxy-gateway/issues/67) [#68](https://github.com/ecoma-io/rotation-proxy-gateway/issues/68) [#69](https://github.com/ecoma-io/rotation-proxy-gateway/issues/69)

## [0.3.1](https://github.com/ecoma-io/rotation-proxy-gateway/compare/v0.3.0...v0.3.1) (2026-09-21)


### Bug Fixes

* **ci:** keep .env and node_modules out of the Docker build context ([6efb6a7](https://github.com/ecoma-io/rotation-proxy-gateway/commit/6efb6a7c13e9781d28637487f8491f49e388b0d4)), closes [#41](https://github.com/ecoma-io/rotation-proxy-gateway/issues/41)
* **ci:** keep .env out of the Docker build context ([#49](https://github.com/ecoma-io/rotation-proxy-gateway/issues/49)) ([6efb6a7](https://github.com/ecoma-io/rotation-proxy-gateway/commit/6efb6a7c13e9781d28637487f8491f49e388b0d4))
* **ci:** keep merge-queue CodeQL upload tied to its candidate ([#60](https://github.com/ecoma-io/rotation-proxy-gateway/issues/60)) ([fc046e1](https://github.com/ecoma-io/rotation-proxy-gateway/commit/fc046e12795699e01280c3167f55270d9fcad7e6))
* **cmd:** catch and ignore SIGHUP instead of dying without drain ([2e9b322](https://github.com/ecoma-io/rotation-proxy-gateway/commit/2e9b322c72225c1eed46c23f86ef9cbd9f72323d))
* **cmd:** ignore SIGHUP instead of terminating without drain ([#57](https://github.com/ecoma-io/rotation-proxy-gateway/issues/57)) ([2e9b322](https://github.com/ecoma-io/rotation-proxy-gateway/commit/2e9b322c72225c1eed46c23f86ef9cbd9f72323d))
* **config:** reject provider URLs without a host and unknown argv ([#50](https://github.com/ecoma-io/rotation-proxy-gateway/issues/50)) ([9eb0bf6](https://github.com/ecoma-io/rotation-proxy-gateway/commit/9eb0bf6df7eebed822535ce7e32c34f8d069fe48)), closes [#44](https://github.com/ecoma-io/rotation-proxy-gateway/issues/44)
* **pool:** clear pair cooldowns when a rotation succeeds ([#54](https://github.com/ecoma-io/rotation-proxy-gateway/issues/54)) ([8f0e20a](https://github.com/ecoma-io/rotation-proxy-gateway/commit/8f0e20a6ce4bad98ee4a100364190ef332224345))
* **proxyserver:** compare RFC 1929 credentials constant-time across the pair ([#48](https://github.com/ecoma-io/rotation-proxy-gateway/issues/48)) ([eaa8743](https://github.com/ecoma-io/rotation-proxy-gateway/commit/eaa87434cdb97a6f9726c29f6aaa0f930935a2f3))
* **proxyserver:** log retry-cap exhaustion as a distinct error kind ([#58](https://github.com/ecoma-io/rotation-proxy-gateway/issues/58)) ([a6d17a7](https://github.com/ecoma-io/rotation-proxy-gateway/commit/a6d17a75af4db17831c3c3328388ab943590adec))
* **proxyserver:** reset wrapped client conns and honor client half-close ([#55](https://github.com/ecoma-io/rotation-proxy-gateway/issues/55)) ([ded0388](https://github.com/ecoma-io/rotation-proxy-gateway/commit/ded0388384bb208a0d5b6a5e4aed275a7439b5ce)), closes [#37](https://github.com/ecoma-io/rotation-proxy-gateway/issues/37) [#38](https://github.com/ecoma-io/rotation-proxy-gateway/issues/38)
* **rotation:** make the new-IP commit race-free and add the post-API removal checkpoint ([#56](https://github.com/ecoma-io/rotation-proxy-gateway/issues/56)) ([051fdcb](https://github.com/ecoma-io/rotation-proxy-gateway/commit/051fdcbee289454ed26f2705c5b50880be33c778))


### Documentation

* configuration.md "Reload behavior" now states the caught-and- ([2e9b322](https://github.com/ecoma-io/rotation-proxy-gateway/commit/2e9b322c72225c1eed46c23f86ef9cbd9f72323d)), closes [#42](https://github.com/ecoma-io/rotation-proxy-gateway/issues/42)
* rotation.md procedure step 4 and failure-and-health.md's pair ([8f0e20a](https://github.com/ecoma-io/rotation-proxy-gateway/commit/8f0e20a6ce4bad98ee4a100364190ef332224345)), closes [#45](https://github.com/ecoma-io/rotation-proxy-gateway/issues/45)
* split the behavior contract into docs/ pages behind a landing README ([#36](https://github.com/ecoma-io/rotation-proxy-gateway/issues/36)) ([d001bfb](https://github.com/ecoma-io/rotation-proxy-gateway/commit/d001bfbe60190407a4209d0cd4643796df0eb9ec))

## [0.3.0](https://github.com/ecoma-io/rotation-proxy-gateway/compare/v0.2.0...v0.3.0) (2026-09-21)


### ⚠ BREAKING CHANGES

* prefix all bootstrap environment variables with RPGW_ ([#30](https://github.com/ecoma-io/rotation-proxy-gateway/issues/30))

### Features

* prefix all bootstrap environment variables with RPGW_ ([#30](https://github.com/ecoma-io/rotation-proxy-gateway/issues/30)) ([b853530](https://github.com/ecoma-io/rotation-proxy-gateway/commit/b8535307afa1358d31dd8ff39e370c07e76ef6c7)), closes [#29](https://github.com/ecoma-io/rotation-proxy-gateway/issues/29)
* **proxyserver:** require inbound RFC 1929 auth when RPGW_ACCOUNT is set ([#33](https://github.com/ecoma-io/rotation-proxy-gateway/issues/33)) ([43c206d](https://github.com/ecoma-io/rotation-proxy-gateway/commit/43c206d7fc07a78aaba923c873d94e463dac5abc))

## [0.2.0](https://github.com/ecoma-io/rotation-proxy-gateway/compare/v0.1.0...v0.2.0) (2026-09-21)


### ⚠ BREAKING CHANGES

* a config containing a route weight key or a balance block fails validation (UnmarshalExact rejects the now-unknown keys) — the last-known-good config keeps serving and first boot refuses to start, mirroring the removed global block. /status pool entries lose weight and the top-level balance key is gone.
* socks5:// and socks5h:// route proxy lines are no longer accepted; use the bare forms.

### Features

* drop weighted selection and the balance family split ([#28](https://github.com/ecoma-io/rotation-proxy-gateway/issues/28)) ([e95c65d](https://github.com/ecoma-io/rotation-proxy-gateway/commit/e95c65d7dba91f2be2a127abbf2ba741119edf41))
* preserve the inbound CONNECT address type and drop route-line schemes ([#19](https://github.com/ecoma-io/rotation-proxy-gateway/issues/19)) ([fbab6dd](https://github.com/ecoma-io/rotation-proxy-gateway/commit/fbab6dd496d56dafa022c1600b35e0e2aa567fad))
* warm upstream connection pool (background + borrow-or-cold serving path) ([#26](https://github.com/ecoma-io/rotation-proxy-gateway/issues/26)) ([a535f08](https://github.com/ecoma-io/rotation-proxy-gateway/commit/a535f08a182db0d3979518a0e052058ac36b1bf6)), closes [#23](https://github.com/ecoma-io/rotation-proxy-gateway/issues/23)


### Bug Fixes

* **config:** make the poller-baseline test replace content atomically ([#21](https://github.com/ecoma-io/rotation-proxy-gateway/issues/21)) ([3ea0e80](https://github.com/ecoma-io/rotation-proxy-gateway/commit/3ea0e807521ac001a123b49d3e01d5f29f8866c8))

## 0.1.0 (2026-09-21)


### ⚠ BREAKING CHANGES

* replace slog with zerolog JSON logging on stdout
* replace HTTP inbound with SOCKS5-only listeners

### Features

* add the manual-route rotation engine ([d2757f0](https://github.com/ecoma-io/rotation-proxy-gateway/commit/d2757f03941dac29efce3e8b10f8869606cb9726))
* add YAML runtime config and egress listeners ([1546d51](https://github.com/ecoma-io/rotation-proxy-gateway/commit/1546d514e3bec8fa48e15262c723f3e6a54fbdd4))
* bound graceful shutdown with a shared configurable SHUTDOWN_GRACE ([e0fdbbb](https://github.com/ecoma-io/rotation-proxy-gateway/commit/e0fdbbbbd2c9a0b770f7561361884562b3dca793))
* **config,cmd:** debug the reload signal and log shutdown milestones ([1ee2221](https://github.com/ecoma-io/rotation-proxy-gateway/commit/1ee222115634b06f0978bfc2b919fbd6f5e3ffd0))
* improve proxy request logging ([c1418d8](https://github.com/ecoma-io/rotation-proxy-gateway/commit/c1418d820e8663ebe8dcb24bca24f063bf77254e))
* log tunnel close records, reset broken tunnels, flush streamed responses ([c33929c](https://github.com/ecoma-io/rotation-proxy-gateway/commit/c33929c9254c80fdd56ec3912a6b7fbac5c61b81))
* make the directory watch the only reload path ([4b46a85](https://github.com/ecoma-io/rotation-proxy-gateway/commit/4b46a8559a1e4ccdd18f48e1d55cb9060b59be57))
* optional egress-family balance split for the mixed listener ([80ee8d5](https://github.com/ecoma-io/rotation-proxy-gateway/commit/80ee8d5e9791c493281cb14a88437ec0202b02eb))
* parse manual rotation routes and rotation settings ([fe8825b](https://github.com/ecoma-io/rotation-proxy-gateway/commit/fe8825b2bccb83ce511971fa7f305a65aa1e9fae))
* **proxyserver:** debug-trace route picks, cooldown fallback, and drains ([6a2fa1b](https://github.com/ecoma-io/rotation-proxy-gateway/commit/6a2fa1b4d01cbab55f4b3441324b3b74f0cf6e3a))
* replace HTTP inbound with SOCKS5-only listeners ([e57070a](https://github.com/ecoma-io/rotation-proxy-gateway/commit/e57070aaf777820c7c76f349ffcde9bbdfc58b13))
* replace inotify watching with a content-hash config poller ([89a301c](https://github.com/ecoma-io/rotation-proxy-gateway/commit/89a301c925396b3ccc1a030a922918447d728b54))
* replace slog with zerolog JSON logging on stdout ([e475c75](https://github.com/ecoma-io/rotation-proxy-gateway/commit/e475c75f5bf04c92243d2b9cc21f2e951fedad10))
* report real rotations and rename the fallback counter to failovers ([203702d](https://github.com/ecoma-io/rotation-proxy-gateway/commit/203702deb749eb660ab6269b441e69c745e66aad))
* **rotation:** debug-trace phases, probes, and scheduler skips ([d9a4155](https://github.com/ecoma-io/rotation-proxy-gateway/commit/d9a4155451ac8e3b3293053db10c2202ec02955c))
* route outbound traffic through SOCKS5 only ([cc1e487](https://github.com/ecoma-io/rotation-proxy-gateway/commit/cc1e48769b8dcd5f5d1c9fa3793b914d0dd9b751))
* scope post-handshake (connect-target) cooldowns per (route, target) ([#6](https://github.com/ecoma-io/rotation-proxy-gateway/issues/6)) ([89fa337](https://github.com/ecoma-io/rotation-proxy-gateway/commit/89fa337f7510025e3632571b945652788d1b407b))
* track in-flight work and rotation state in the pool ([7d6f9b3](https://github.com/ecoma-io/rotation-proxy-gateway/commit/7d6f9b33dfc1d777fe0bb6df8c83a5550100867d))
* treat SOCKS handshake failures as retryable route health failures ([edb67d0](https://github.com/ecoma-io/rotation-proxy-gateway/commit/edb67d0de1e9405917238cab6fcbdf1a50d44a90))
* weighted per-route selection via a stride recency clock ([e964d48](https://github.com/ecoma-io/rotation-proxy-gateway/commit/e964d48ee10299a88da4cfa0606a380193db95a6))


### Bug Fixes

* abort rotation procedures for routes removed by a reload ([e1ac133](https://github.com/ecoma-io/rotation-proxy-gateway/commit/e1ac13397cf902bdefbab8ae306239b68ffc5b2d))
* allow single-family proxy pools ([1cd1857](https://github.com/ecoma-io/rotation-proxy-gateway/commit/1cd185787d4ed4716d0ee31fa557ff060ad23254))
* bound rotation probe connections by their probe timeout ([2ad178d](https://github.com/ecoma-io/rotation-proxy-gateway/commit/2ad178d19f2874d13d146b710b527c7a9631186f))
* **ci:** make first public workflow run green ([eac7d90](https://github.com/ecoma-io/rotation-proxy-gateway/commit/eac7d9004d4fd487dfe470a53f6c3f1d5c62381c))
* close route-identity and tunnel-log credential gaps, pin with unit tests ([d831a38](https://github.com/ecoma-io/rotation-proxy-gateway/commit/d831a38e807292a7993a9415d3fb5a9cd98acbd9))
* **cmd:** check healthcheck cleanup errors ([dbbdb59](https://github.com/ecoma-io/rotation-proxy-gateway/commit/dbbdb595d5c5eb8e13d940ee2a58869d776c0dc4))
* **config:** read failures keep the poller baseline and ports compare numerically ([6ec719d](https://github.com/ecoma-io/rotation-proxy-gateway/commit/6ec719da5ce9058f0e06ec30f44de21c5ef1ee4e))
* harden forwarding and tunnel cancellation ([c3c8ec7](https://github.com/ecoma-io/rotation-proxy-gateway/commit/c3c8ec78f0691b018928267e44ad3dd4da380292))
* harden pool health state ([29ba389](https://github.com/ecoma-io/rotation-proxy-gateway/commit/29ba3898319a95a8d2e1ec064145bd34cbc8ed90))
* never follow redirects from the rotate API ([ec90b58](https://github.com/ecoma-io/rotation-proxy-gateway/commit/ec90b58e2ab4cdf640c56beb21a8f872110bfc4e))
* **pool:** anchor cooldown deadlines to the monotonic clock ([9a67682](https://github.com/ecoma-io/rotation-proxy-gateway/commit/9a6768247ae0f7d9860e7a76f250f290dcfe5555))
* **pool:** dedicated picks no longer advance the family clocks ([7bc454e](https://github.com/ecoma-io/rotation-proxy-gateway/commit/7bc454e7f9b9b651277edbc1c331ce9610b28df3))
* **pool:** write cooldown and failure streak as one critical section ([8673c4e](https://github.com/ecoma-io/rotation-proxy-gateway/commit/8673c4e0c860b722cd612fe1c6aa4099d261ffbb))
* **proxyserver:** bound shutdown and make session admission race-free ([fa7c46b](https://github.com/ecoma-io/rotation-proxy-gateway/commit/fa7c46b35c4caa836eef24ceac288ed0cac7e56a))
* **proxyserver:** handle ignored errors and embed-selector findings ([8c3b3dc](https://github.com/ecoma-io/rotation-proxy-gateway/commit/8c3b3dc07beb42e74ad74c822e392e3e47d0e0a6))
* **proxyserver:** honest failover counting and deadline-guarded retries ([fc25947](https://github.com/ecoma-io/rotation-proxy-gateway/commit/fc259477137a23cf736cff384849f4ebdc27d685))
* redact route diagnostics ([390be3b](https://github.com/ecoma-io/rotation-proxy-gateway/commit/390be3be68e425a5439b22162d717c122e14c539))
* redact the bare user:pass@host spelling too ([7923357](https://github.com/ecoma-io/rotation-proxy-gateway/commit/7923357b5b7f5acbf81678a608f6b5544c89ac2a))
* **release:** seed the manifest at 0.0.0 so the first release is 0.1.0 ([b738bec](https://github.com/ecoma-io/rotation-proxy-gateway/commit/b738bec71d2ba6e8738db829e1494b3726ddabff))
* **rotation:** check probe cleanup errors ([1a0cc9e](https://github.com/ecoma-io/rotation-proxy-gateway/commit/1a0cc9e34d7ec60b5a467d099f895f8c60404624))
* **rotation:** clamp Retry-After, validate probe IPs, and guard rotation state races ([8961c44](https://github.com/ecoma-io/rotation-proxy-gateway/commit/8961c44929c69931a36483587cb9daa67c99dd6a))
* **rotation:** dial the rotate API directly, never an ambient proxy ([50bbc1c](https://github.com/ecoma-io/rotation-proxy-gateway/commit/50bbc1c1130bf78b0107c2dbd08df2527d1c801b))
* **rotation:** guard finishProcedure against stale replacements ([9e9207f](https://github.com/ecoma-io/rotation-proxy-gateway/commit/9e9207fcd6bcd5d6b7e94f8bf953a10ae2268bb0))
* **socksdial:** check handshake cleanup errors ([485c1f7](https://github.com/ecoma-io/rotation-proxy-gateway/commit/485c1f7634f472753cd7d6ba4a52e306e0c95441))
* **socksdial:** report buffered-prefix read failures ([4e61b0f](https://github.com/ecoma-io/rotation-proxy-gateway/commit/4e61b0f1b576a0a9c2df27a7697883dd73b6f49d))
* validate SOCKS route configuration ([6bbb2f4](https://github.com/ecoma-io/rotation-proxy-gateway/commit/6bbb2f47bc249978140d97c20dafc9785cc1cb1a))


### Documentation

* **ci:** correct lint baseline tracking note ([c2e6e34](https://github.com/ecoma-io/rotation-proxy-gateway/commit/c2e6e34d78ba60413aa82011dfd85981bb133f8e))
* **ci:** mark the tracked lint debt cleared ([c46ecd1](https://github.com/ecoma-io/rotation-proxy-gateway/commit/c46ecd1944382a9d4a000d1722a0e93664084d98))
* correct the drain-expiry comment in the rotation procedure ([09de137](https://github.com/ecoma-io/rotation-proxy-gateway/commit/09de137c98696355ada9b34f196da9e4e1e23a9e))
* **e2e:** point gateway-internal claims at the in-process benches ([2b2e0c3](https://github.com/ecoma-io/rotation-proxy-gateway/commit/2b2e0c3ac9f408256ae2d095fe44b4a64765dadc))
* specify manual rotation routes and the counters split ([ea5e835](https://github.com/ecoma-io/rotation-proxy-gateway/commit/ea5e8359bf23b74cc7cb2c8630df8cad4aa4f648))
