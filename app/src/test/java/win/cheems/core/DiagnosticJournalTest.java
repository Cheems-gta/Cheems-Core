package win.cheems.core;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.HashMap;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import win.cheems.core.net.Node;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = {28, 35})
public class DiagnosticJournalTest {
  @Test public void restartRetainsBoundedRedactedErrors() {
    SharedPreferences prefs = RuntimeEnvironment.getApplication().getSharedPreferences("journal-test", Context.MODE_PRIVATE);
    prefs.edit().clear().commit();
    DiagnosticJournal log = new DiagnosticJournal(prefs);
    HashMap<String,Object> map = new HashMap<>();
    map.put("type", "anytls"); map.put("server", "private.example"); map.put("port", 443);
    map.put("password", "private-password"); map.put("name", "private-node");
    Node node = new Node(map);
    for (int i=0; i<45; i++) log.append("stage-" + i, node);
    log.append("TLS failed private.example private-password https://subscription.example/?token=hidden local-secret", node, "local-secret");
    String restored = new DiagnosticJournal(prefs).snapshot();
    assertEquals(log.snapshot(), restored);
    assertEquals(40, restored.split("\n").length);
    assertTrue(restored.contains("TLS failed"));
    assertFalse(restored.contains("private.example"));
    assertFalse(restored.contains("private-password"));
    assertFalse(restored.contains("subscription.example"));
    assertFalse(restored.contains("local-secret"));
  }
}
