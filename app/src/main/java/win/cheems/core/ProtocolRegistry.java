package win.cheems.core;

/**
 * Protocol capability registry. Declared targets are not implemented protocols.
 * Use this to prevent the UI from reporting a parsed subscription as connected.
 */
public final class ProtocolRegistry {
    public enum Status { EXPERIMENTAL, PLANNED }
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
        new Capability("HTTPS Proxy", Status.PLANNED),
        new Capability("SOCKS5", Status.PLANNED),
        new Capability("Shadowsocks", Status.PLANNED),
        new Capability("VMess", Status.PLANNED),
        new Capability("VLESS", Status.PLANNED),
        new Capability("Trojan", Status.PLANNED),
        new Capability("Hysteria2", Status.PLANNED),
        new Capability("TUIC", Status.PLANNED),
        new Capability("AnyTLS", Status.PLANNED),
        new Capability("WireGuard", Status.PLANNED),
        new Capability("SSH Tunnel", Status.PLANNED),
        new Capability("NaiveProxy", Status.PLANNED)
    };
    public static boolean isImplemented(String protocol) {
        return "HTTP CONNECT (loopback)".equals(protocol);
    }
}
