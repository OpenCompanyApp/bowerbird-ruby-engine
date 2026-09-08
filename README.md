# Shared Ruby engine

Status: implementation in progress; not a production-qualified sandbox.

An application-neutral mruby guest for OpenCompany and future Bowerbird hosts.
The local protocol does not implement Bowerbird durable replay or Program Locks.
The engine implementation is Apache-2.0; mruby retains its upstream MIT notices.

Build prerequisites: Rust, C compiler, Ruby and rake. Provision the exact source:

```sh
git clone --branch 4.0.0 https://github.com/mruby/mruby.git vendor/mruby
cargo build --release
cargo test
```

The build verifies the source commit in `engine.lock.json`. Capability libraries
are explicitly selected in `build_config.rb`. The runner accepts a bounded JSON
request, spawns a fresh guest, forwards framed callback messages, and enforces
deadlines. Its input is source, never externally supplied mruby bytecode.

Supervisor pipes are bounded and nonblocking. Partial frames, output backpressure
and waiting host callbacks cannot suspend the watchdog. Closing host stdin
cancels and reaps the guest. Abrupt supervisor loss kills the guest through
Linux's parent-death signal or a macOS kernel process watch. These guarantees do
not cancel an external request already dispatched by the PHP host.

The focused supervision tests cover these lifetime cases and repeated startup.
CI also runs a fixed ASan corpus against the contained guest and short,
coverage-guided fuzzing of framing and request/value admission. These bounded
checks do not replace sustained sanitizer/fuzz, release-artifact or deployment
qualification.

## CI evidence

The `engine qualification` workflow builds the pinned mruby source, runs Clippy,
the Rust test suite, and the seven-scenario PHP 8.4 smoke test on Linux AMD64,
Linux ARM64, and macOS ARM64 GitHub-hosted runners. The Linux ARM64 label is a
GitHub public-preview runner label. A workflow definition or a green result is
test evidence for that source revision only; it is not a production release,
signing attestation, or sandbox qualification. See [GitHub's hosted runner
reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
for current runner availability.

## Release-candidate artifacts

The manually dispatched `engine release-candidate artifacts` workflow tests each
native target before uploading review-only artifacts; it never creates a tag or
GitHub Release. Download the archive and its matching `SHA256SUMS`, then verify
the exact archive before configuring its absolute binary path in the PHP client:

```sh
shasum -a 256 bowerbird-ruby-engine-<candidate>-<platform>.tar.gz
grep ' bowerbird-ruby-engine-<candidate>-<platform>.tar.gz$' SHA256SUMS
```

The separate PHP adapter archive contains only `composer.json`, `php/src`, and
notices: it intentionally excludes Rust build output and the mutable mruby
checkout. GitHub provenance/SBOM attestations exist only after a successful RC
job and can be independently checked with `gh attestation verify`; they are not
maintainer signatures or a production qualification statement.

OpenCompany owns permissions, credentials, approval and effect delivery. The
engine cannot establish those facts and never claims a killed provider call was
rolled back. See the OpenCompany mruby migration plan for release gates.
