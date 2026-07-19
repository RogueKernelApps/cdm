# CDM patch to hudsucker 0.25.0

This directory is the crates.io `hudsucker` 0.25.0 source (registry checksum
`3a1d7c1c828ff6db12ddafb16768ecbac920df6301778d0eb78e95da0e44d94b`), with
one narrow security patch. The upstream MIT and Apache-2.0 license files are
preserved beside this note.

Upstream falls back to an opaque TCP tunnel when the bytes following CONNECT
are neither HTTP nor a TLS ClientHello, even after the handler requested
interception. CDM cannot permit an uninspectable channel while secret mappings
exist. The patch:

1. adds `HttpHandler::should_tunnel_unknown_connect`, defaulting to `true` so
   upstream behavior remains unchanged for other handlers; and
2. asks that hook before the existing unknown-protocol tunnel fallback.

CDM's handler returns `false` whenever mappings exist. The regression
`proxy::tests::unknown_connect_protocol_never_falls_back_to_a_tunnel_with_secrets`
proves that the connection closes without reaching the requested upstream.

Only `src/lib.rs` and `src/proxy/internal.rs` differ from the published source.
Remove this patch when an equivalent fail-closed hook is available in an
upstream hudsucker release.
