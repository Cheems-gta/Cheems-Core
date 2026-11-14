package win.cheems.core.net;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Optional gomobile Hysteria 2 bridge. The default Java-only APK does not
 * contain the native AAR; only a build that packages it can start this engine.
 * Calls must be made on a background thread.
 */
public final class Hysteria2Native {
  private static final String BINDING = "go.mobilebridge.Mobilebridge";
  public static final int LOCAL_SOCKS_PORT = 10990;
  private static final AtomicReference<String> localToken = new AtomicReference<>();
  private Hysteria2Native() {}

  public static String localSocksToken() {
    String token = localToken.get();
    return token == null ? "" : token;
  }

  private static Class<?> binding() throws ClassNotFoundException {
    return Class.forName(BINDING);
  }

  public static boolean isPackaged() {
    try { binding().getMethod("start", String.class, long.class, String.class, String.class, long.class, String.class, boolean.class, String.class, String.class); return true; }
    catch (ReflectiveOperationException | LinkageError e) { return false; }
  }

  public static void start(Node node, int localPort, boolean allowUnverifiedTLS, String customCAPEM) throws Exception {
    if (!"hysteria2".equals(node.type)) throw new IllegalArgumentException("Hysteria 2 node required");
    if (node.password.isEmpty()) throw new IllegalArgumentException("Missing Hysteria 2 password");
    if (localPort < 1 || localPort > 65535) throw new IllegalArgumentException("Invalid local port");
    if (allowUnverifiedTLS && !node.hasInsecureTlsFlag())
      throw new IllegalArgumentException("Unverified TLS requires an explicit insecure provider flag");
    String trustedCAPEM = customCAPEM == null || customCAPEM.isBlank()
        ? node.trustedCAPEM() : customCAPEM;
    if (trustedCAPEM.length() > 64 * 1024)
      throw new IllegalArgumentException("Custom CA certificate exceeds 64 KiB");
    String platformAndCustomCAPEM = PlatformTrust.withCustomCA(trustedCAPEM);
    byte[] nonce = new byte[32];
    new SecureRandom().nextBytes(nonce);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
    localToken.set(token);
    try {
      Method start = binding().getMethod("start", String.class, long.class, String.class, String.class, long.class, String.class, boolean.class, String.class, String.class);
      start.invoke(null, node.host, (long) node.port, node.sni, node.password, (long) localPort, token, allowUnverifiedTLS, platformAndCustomCAPEM, node.certificateSHA256());
    } catch (ClassNotFoundException e) {
      localToken.compareAndSet(token, null);
      throw new IllegalStateException("Hysteria 2 native AAR is not packaged in this APK", e);
    } catch (InvocationTargetException e) {
      localToken.compareAndSet(token, null);
      Throwable cause = e.getCause();
      String detail = cause == null ? "未知错误" : cause.getMessage();
      if (detail == null || detail.isBlank()) detail = "未知错误";
      throw new IllegalStateException("Hysteria 2 建连失败：" + detail, cause);
    } catch (ReflectiveOperationException | LinkageError e) {
      localToken.compareAndSet(token, null);
      throw new IllegalStateException("Hysteria 2 Android 原生桥接异常", e);
    }
  }

  public static void stop() throws Exception {
    localToken.set(null);
    binding().getMethod("stop").invoke(null);
  }

  public static boolean isRunning() {
    try { return (Boolean) binding().getMethod("isRunning").invoke(null); }
    catch (ReflectiveOperationException | LinkageError e) { return false; }
  }
}

