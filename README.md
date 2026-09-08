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
They do not replace sanitizer/fuzz, release-artifact or deployment qualification.

OpenCompany owns permissions, credentials, approval and effect delivery. The
engine cannot establish those facts and never claims a killed provider call was
rolled back. See the OpenCompany mruby migration plan for release gates.
