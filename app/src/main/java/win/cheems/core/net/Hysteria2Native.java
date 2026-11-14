package win.cheems.core.net;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Optional gomobile Hysteria 2 bridge. The default Java-only APK does not
 * contain the native AAR; only a build that packages it can start this engine.
 * Calls must be made on a background thread.
 */
public final class Hysteria2Native {
  private static final String BINDING = "go.mobilebridge.Mobilebridge";
  public static final int LOCAL_SOCKS_PORT = 10990;
  private Hysteria2Native() {}

  private static Class<?> binding() throws ClassNotFoundException {
    return Class.forName(BINDING);
  }

  public static boolean isPackaged() {
    try { binding().getMethod("start", String.class, int.class, String.class, String.class, int.class); return true; }
    catch (ReflectiveOperationException | LinkageError e) { return false; }
  }

  public static void start(Node node, int localPort) throws Exception {
    if (!"hysteria2".equals(node.type)) throw new IllegalArgumentException("Hysteria 2 node required");
    if (node.password.isEmpty()) throw new IllegalArgumentException("Missing Hysteria 2 password");
    if (localPort < 1 || localPort > 65535) throw new IllegalArgumentException("Invalid local port");
    try {
      Method start = binding().getMethod("start", String.class, int.class, String.class, String.class, int.class);
      start.invoke(null, node.host, node.port, node.sni, node.password, localPort);
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException("Hysteria 2 native AAR is not packaged in this APK", e);
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause();
      throw new IllegalStateException("Hysteria 2 native start failed", cause);
    }
  }

  public static void stop() throws Exception {
    binding().getMethod("stop").invoke(null);
  }

  public static boolean isRunning() {
    try { return (Boolean) binding().getMethod("isRunning").invoke(null); }
    catch (ReflectiveOperationException | LinkageError e) { return false; }
  }
}
