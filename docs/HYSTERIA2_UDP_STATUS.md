## Hysteria 2 UDP milestone

Implement the Hysteria 2 UDP datagram envelope, bounded address and payload
validation, nonzero per-session identifiers, packet IDs, and explicit rejection
of fragmented packets until fragmentation/reassembly is implemented.

After authentication, read the Hysteria-UDP response header. The client only
sends or receives datagrams when the server advertises UDP support. TCP
interoperability remains covered separately by the local HTTP/3 reference peer.

This milestone does not yet expose UDP ASSOCIATE through the loopback SOCKS
listener, pass Android TUN UDP flows into the adapter, or verify datagram
interoperability against a public/provider server. Do not mark end-to-end UDP or
Android VPN as complete. Hysteria 2's protocol specification defines a 32-bit
session ID, 16-bit packet ID, fragment ID/count, address and payload in each
QUIC datagram. Current adapter supports single-fragment packets only.
