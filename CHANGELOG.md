# Changelog

## [0.2.0](https://github.com/ecoma-io/rotation-proxy-gateway/compare/v0.1.0...v0.2.0) (2026-09-19)


### Features

* add the manual-route rotation engine ([d2757f0](https://github.com/ecoma-io/rotation-proxy-gateway/commit/d2757f03941dac29efce3e8b10f8869606cb9726))
* add YAML runtime config and egress listeners ([1546d51](https://github.com/ecoma-io/rotation-proxy-gateway/commit/1546d514e3bec8fa48e15262c723f3e6a54fbdd4))
* bound graceful shutdown with a shared configurable SHUTDOWN_GRACE ([e0fdbbb](https://github.com/ecoma-io/rotation-proxy-gateway/commit/e0fdbbbbd2c9a0b770f7561361884562b3dca793))
* improve proxy request logging ([c1418d8](https://github.com/ecoma-io/rotation-proxy-gateway/commit/c1418d820e8663ebe8dcb24bca24f063bf77254e))
* log tunnel close records, reset broken tunnels, flush streamed responses ([c33929c](https://github.com/ecoma-io/rotation-proxy-gateway/commit/c33929c9254c80fdd56ec3912a6b7fbac5c61b81))
* make the directory watch the only reload path ([4b46a85](https://github.com/ecoma-io/rotation-proxy-gateway/commit/4b46a8559a1e4ccdd18f48e1d55cb9060b59be57))
* optional egress-family balance split for the mixed listener ([80ee8d5](https://github.com/ecoma-io/rotation-proxy-gateway/commit/80ee8d5e9791c493281cb14a88437ec0202b02eb))
* parse manual rotation routes and rotation settings ([fe8825b](https://github.com/ecoma-io/rotation-proxy-gateway/commit/fe8825b2bccb83ce511971fa7f305a65aa1e9fae))
* replace inotify watching with a content-hash config poller ([89a301c](https://github.com/ecoma-io/rotation-proxy-gateway/commit/89a301c925396b3ccc1a030a922918447d728b54))
* report real rotations and rename the fallback counter to failovers ([203702d](https://github.com/ecoma-io/rotation-proxy-gateway/commit/203702deb749eb660ab6269b441e69c745e66aad))
* route outbound traffic through SOCKS5 only ([cc1e487](https://github.com/ecoma-io/rotation-proxy-gateway/commit/cc1e48769b8dcd5f5d1c9fa3793b914d0dd9b751))
* track in-flight work and rotation state in the pool ([7d6f9b3](https://github.com/ecoma-io/rotation-proxy-gateway/commit/7d6f9b33dfc1d777fe0bb6df8c83a5550100867d))
* treat SOCKS handshake failures as retryable route health failures ([edb67d0](https://github.com/ecoma-io/rotation-proxy-gateway/commit/edb67d0de1e9405917238cab6fcbdf1a50d44a90))
* weighted per-route selection via a stride recency clock ([e964d48](https://github.com/ecoma-io/rotation-proxy-gateway/commit/e964d48ee10299a88da4cfa0606a380193db95a6))


### Bug Fixes

* abort rotation procedures for routes removed by a reload ([e1ac133](https://github.com/ecoma-io/rotation-proxy-gateway/commit/e1ac13397cf902bdefbab8ae306239b68ffc5b2d))
* allow single-family proxy pools ([1cd1857](https://github.com/ecoma-io/rotation-proxy-gateway/commit/1cd185787d4ed4716d0ee31fa557ff060ad23254))
* bound rotation probe connections by their probe timeout ([2ad178d](https://github.com/ecoma-io/rotation-proxy-gateway/commit/2ad178d19f2874d13d146b710b527c7a9631186f))
* **ci:** make first public workflow run green ([25784e8](https://github.com/ecoma-io/rotation-proxy-gateway/commit/25784e80b17a55f707df9e940a09529f99ee6a92))
* close route-identity and tunnel-log credential gaps, pin with unit tests ([d831a38](https://github.com/ecoma-io/rotation-proxy-gateway/commit/d831a38e807292a7993a9415d3fb5a9cd98acbd9))
* **cmd:** check healthcheck cleanup errors ([7f3c344](https://github.com/ecoma-io/rotation-proxy-gateway/commit/7f3c34440fb43b8bc247d7985133eeb3fd0bb453))
* harden forwarding and tunnel cancellation ([c3c8ec7](https://github.com/ecoma-io/rotation-proxy-gateway/commit/c3c8ec78f0691b018928267e44ad3dd4da380292))
* harden pool health state ([29ba389](https://github.com/ecoma-io/rotation-proxy-gateway/commit/29ba3898319a95a8d2e1ec064145bd34cbc8ed90))
* never follow redirects from the rotate API ([ec90b58](https://github.com/ecoma-io/rotation-proxy-gateway/commit/ec90b58e2ab4cdf640c56beb21a8f872110bfc4e))
* **proxyserver:** handle ignored errors and embed-selector findings ([097d9b0](https://github.com/ecoma-io/rotation-proxy-gateway/commit/097d9b07c6292333ca48789c730aa3b476a96f80))
* redact route diagnostics ([390be3b](https://github.com/ecoma-io/rotation-proxy-gateway/commit/390be3be68e425a5439b22162d717c122e14c539))
* **rotation:** check probe cleanup errors ([a8717ce](https://github.com/ecoma-io/rotation-proxy-gateway/commit/a8717ce6d16e8842aa6e585229eab82c1c13c07a))
* **socksdial:** check handshake cleanup errors ([effb0fa](https://github.com/ecoma-io/rotation-proxy-gateway/commit/effb0faae85b2a39b188eb8e09dfcf2d2d9fa142))
* **socksdial:** report buffered-prefix read failures ([7da88dd](https://github.com/ecoma-io/rotation-proxy-gateway/commit/7da88dd5b6c0837060370d84661664270213967b))
* validate SOCKS route configuration ([6bbb2f4](https://github.com/ecoma-io/rotation-proxy-gateway/commit/6bbb2f47bc249978140d97c20dafc9785cc1cb1a))


### Documentation

* **ci:** correct lint baseline tracking note ([3375828](https://github.com/ecoma-io/rotation-proxy-gateway/commit/3375828df99a5b286467ff579b1f2b10e5428cd7))
* **ci:** mark the tracked lint debt cleared ([70ec929](https://github.com/ecoma-io/rotation-proxy-gateway/commit/70ec9292dfe85ada76a95d060d001e7abc5e5e91))
* correct the drain-expiry comment in the rotation procedure ([09de137](https://github.com/ecoma-io/rotation-proxy-gateway/commit/09de137c98696355ada9b34f196da9e4e1e23a9e))
* specify manual rotation routes and the counters split ([ea5e835](https://github.com/ecoma-io/rotation-proxy-gateway/commit/ea5e8359bf23b74cc7cb2c8630df8cad4aa4f648))
