# Reality transport preview

This experimental VLESS TCP Reality adapter follows the public XTLS REALITY
protocol and the SagerNet sing-box client reference:
https://github.com/SagerNet/sing-box/blob/testing/common/tls/reality_client.go
The adapted authentication logic is GPL-3.0-or-later. It uses metacubex/uTLS
v1.8.7 (BSD-style upstream TLS implementation) and the existing protected Android
physical-network dialer. It does not embed the sing-box application/core.

The client validates the X25519 public key, derives the REALITY authentication
key, encrypts the short ID/timestamp in ClientHello and requires the authenticated
Ed25519 certificate signature. A conventional TLS certificate is not enough.
No unauthenticated fallback HTTP request is issued. Authentication keys and
credentials are not logged.

Supported preview: VLESS TCP Reality, empty flow, chrome/firefox ClientHello.
Unsupported: XTLS Vision, Reality over WS/gRPC, ML-DSA certificate authentication,
other client fingerprints and provider-specific min/max client-version policies.
The client identifies protocol version 0.1.0, not an upstream application version.

Tests use an independent synthetic reference peer that decrypts wire ClientHello
session IDs and authenticates encrypted TLS echo traffic. Wrong public keys,
short IDs and conventional TLS certificates are rejected. These are not proof
of interoperability with every official REALITY version or Flybit endpoint.
Physical-device traffic, background behavior and network switching need testing.
