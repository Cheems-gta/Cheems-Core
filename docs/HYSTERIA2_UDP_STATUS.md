## Scope update

The loopback SOCKS5 server now accepts UDP ASSOCIATE only when the authenticated
HY2 server advertised UDP. It binds a loopback UDP socket, validates the client
endpoint and SOCKS5 packet framing, creates one Hysteria UDP association, routes
replies to the originating SOCKS client, and cleans up when its TCP control
connection closes.

Single-datagram Hysteria framing and SOCKS address parsing have unit coverage
for IPv4, IPv6, domains, malformed packets, oversize payloads and fragmentation
rejection. Go race tests and vet pass.

Still pending: a true QUIC datagram echo interoperability test, SOCKS UDP
association integration test, fragmentation/reassembly, reliable DNS behavior,
Android TUN/VPN UDP flow integration, Flybit device test and sustained stability
test. This checkpoint is not yet an end-to-end UDP support claim.
