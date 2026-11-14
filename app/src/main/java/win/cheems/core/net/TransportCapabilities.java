package win.cheems.core.net;

import java.util.Locale;

/**
 * Capability registry reflects actual Dialer implementations, not parsed subscription formats.
 * Import support and transport support are deliberately separate.
 */
public final class TransportCapabilities {
  private TransportCapabilities() {}

  public enum Status { TCP_READY, PARSE_ONLY, NOT_IMPLEMENTED }

  public static Status status(String protocol) {
    if (protocol == null) return Status.NOT_IMPLEMENTED;
    switch (protocol.toLowerCase(Locale.ROOT)) {
      case "ss":
      case "trojan":
      case "socks5":
      case "http":
        return Status.TCP_READY;
      case "hysteria2":
      case "hy2":
      case "anytls":
        return Status.PARSE_ONLY;
      default:
        return Status.NOT_IMPLEMENTED;
    }
  }

  public static boolean canDialTcp(String protocol) {
    return status(protocol) == Status.TCP_READY;
  }

  public static boolean canDialUdp(String protocol) {
    // Current Dialer supports only TCP; do not advertise UDP prematurely.
    return false;
  }

  public static boolean requiresQuic(String protocol) {
    return protocol != null &&
        (protocol.equalsIgnoreCase("hysteria2") || protocol.equalsIgnoreCase("hy2") ||
         protocol.equalsIgnoreCase("tuic"));
  }
}
