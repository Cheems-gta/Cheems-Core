package win.cheems.core.net;

import org.junit.Test;
import static org.junit.Assert.*;

public class TransportCapabilitiesTest {
  @Test public void supportedTcpTransportsAreAdvertised() {
    for (String p : new String[]{"ss","trojan","socks5","http"}) {
      assertTrue(p, TransportCapabilities.canDialTcp(p));
    }
  }
  @Test public void importedProtocolsMustNotClaimWorkingConnections() {
    for (String p : new String[]{"hysteria2","hy2"}) {
      assertEquals(TransportCapabilities.Status.PARSE_ONLY,TransportCapabilities.status(p));
      assertFalse(p,TransportCapabilities.canDialTcp(p));
    }
    assertEquals(TransportCapabilities.Status.TCP_READY,TransportCapabilities.status("anytls"));
    assertTrue(TransportCapabilities.canDialTcp("anytls"));
    assertEquals(TransportCapabilities.Status.TCP_READY,TransportCapabilities.status("vless"));
    assertTrue(TransportCapabilities.canDialTcp("vless"));
  }
  @Test public void quicRequirementsAreExplicit() {
    assertTrue(TransportCapabilities.requiresQuic("hysteria2"));
    assertTrue(TransportCapabilities.requiresQuic("hy2"));
    assertTrue(TransportCapabilities.requiresQuic("tuic"));
    assertFalse(TransportCapabilities.requiresQuic("anytls"));
  }
  @Test public void noUdpDialerExistsYet() {
    for(String p:new String[]{"ss","hysteria2","anytls","tuic"})
      assertFalse(TransportCapabilities.canDialUdp(p));
  }
}

