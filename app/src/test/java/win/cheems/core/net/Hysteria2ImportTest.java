package win.cheems.core.net;
import org.junit.Test;
import java.util.List;
import static org.junit.Assert.*;

/** Node import tests verify supported configuration; they do not prove real QUIC connectivity. */
public class Hysteria2ImportTest {
 @Test public void parsesHy2ShareLink() throws Exception {
  List<Node> nodes=Subscription.parse("hy2://secret@example.com:443?sni=edge.example.com#Flybit");
  assertEquals(1,nodes.size());
  Node n=nodes.get(0);
  assertEquals("hysteria2",n.type);
  assertEquals("example.com",n.host);
  assertEquals(443,n.port);
  assertEquals("secret",n.password);
  assertEquals("edge.example.com",n.sni);
  assertTrue(n.supported());
 }
 @Test public void parsesYamlNode() throws Exception {
  List<Node> nodes=Subscription.parse("proxies:\n  - name: HY2 test\n    type: hysteria2\n    server: example.com\n    port: 443\n    password: secret\n");
  assertEquals("hysteria2",nodes.get(0).type);
  assertTrue(nodes.get(0).supported());
 }
 @Test public void rejectsMissingCredentials() throws Exception {
  Node n=Subscription.parse("hy2://example.com:443#Missing").get(0);
  assertTrue(n.unsupported.contains("密码"));
 }
 @Test public void rejectsInsecureTlsConfig() throws Exception {
  Node n=Subscription.parse("hy2://secret@example.com:443?insecure=1").get(0);
  assertTrue(n.unsupported.contains("证书"));
 }
}
