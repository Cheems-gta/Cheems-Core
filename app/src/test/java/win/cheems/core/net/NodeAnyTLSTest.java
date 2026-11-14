package win.cheems.core.net;

import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import static org.junit.Assert.*;

public class NodeAnyTLSTest {
  private Node node(Object... entries) {
    Map<String, Object> config = new HashMap<>();
    config.put("type", "anytls");
    config.put("server", "node.example");
    config.put("port", 443);
    config.put("password", "secret");
    for (int i = 0; i < entries.length; i += 2) config.put((String) entries[i], entries[i + 1]);
    return new Node(config);
  }

  @Test public void standardTlsAnyTlsNodeIsSelectable() {
    Node n = node();
    assertTrue(n.unsupported, n.supported());
    assertTrue(n.tls());
    assertEquals(TransportCapabilities.Status.TCP_READY, TransportCapabilities.status(n.type));
  }

  @Test public void skipCertificateHintRequiresExplicitOneTimeChoice() {
    Node n = node("skip-cert-verify", true);
    assertTrue(n.unsupported, n.supported());
    assertTrue(n.hasInsecureTlsFlag());
  }

  @Test public void missingPasswordAndUnsupportedFingerprintFailClosed() {
    assertFalse(node("password", "").supported());
    assertTrue(node("client-fingerprint", "chrome").unsupported.contains("指纹"));
  }
}
