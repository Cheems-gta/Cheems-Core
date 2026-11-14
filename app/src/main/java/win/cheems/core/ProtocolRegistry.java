package win.cheems.core;

/**
 * User-facing capability metadata.
 * IMPLEMENTED means a protocol dialer exists; it does not imply provider
 * interoperability, Android VPN support or completed device verification.
 */
public final class ProtocolRegistry {
    public enum Status { IMPLEMENTED, EXPERIMENTAL, PLANNED }
    public static final class Capability {
        public final String name;
        public final Status status;
        Capability(String name, Status status) {
            this.name = name;
            this.status = status;
        }
    }
    private ProtocolRegistry() {}
    public static final Capability[] CAPABILITIES = {
        new Capability("HTTP CONNECT (loopback)", Status.EXPERIMENTAL),
        new Capability("HTTP upstream CONNECT", Status.IMPLEMENTED),
        new Capability("HTTPS upstream CONNECT", Status.IMPLEMENTED),
        new Capability("SOCKS5 TCP CONNECT", Status.IMPLEMENTED),
        new Capability("Shadowsocks AEAD TCP", Status.IMPLEMENTED),
        new Capability("Trojan TCP/TLS", Status.IMPLEMENTED),
        new Capability("VMess", Status.PLANNED),
        new Capability("VLESS", Status.PLANNED),
        new Capability("Hysteria2", Status.PLANNED),
        new Capability("TUIC", Status.PLANNED),
        new Capability("AnyTLS", Status.PLANNED),
        new Capability("WireGuard", Status.PLANNED),
        new Capability("SSH Tunnel", Status.PLANNED),
        new Capability("NaiveProxy", Status.PLANNED)
    };
    public static boolean isImplemented(String protocol) {
        for (Capability c : CAPABILITIES) {
            if (c.name.equals(protocol)) return c.status != Status.PLANNED;
        }
        return false;
    }
}
