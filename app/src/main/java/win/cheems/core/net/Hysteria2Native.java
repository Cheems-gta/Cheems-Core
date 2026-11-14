package win.cheems.core.net;

import win.cheems.core.CoreService;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.lang.reflect.InvocationHandler;
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
    try {
      Class<?> network = Class.forName("go.mobilebridge.Network");
      binding().getMethod("startWithNetwork", String.class, long.class, String.class, String.class,
          long.class, String.class, boolean.class, String.class, String.class, network);
      binding().getMethod("startAnyTLSWithNetwork", String.class, long.class, String.class, String.class,
          long.class, String.class, boolean.class, String.class, String.class, network);
      binding().getMethod("startVLESSWithNetwork", String.class, long.class, String.class, String.class,
          long.class, String.class, boolean.class, String.class, String.class, network);
      binding().getMethod("startTunnel", long.class);
      binding().getMethod("stopTunnel");
      return true;
    }
    catch (ReflectiveOperationException | LinkageError e) { return false; }
  }

  public static void start(Node node, int localPort, boolean allowUnverifiedTLS, String customCAPEM,
      CoreService vpnService) throws Exception {
    boolean hy2 = "hysteria2".equals(node.type);
    boolean anytls = "anytls".equals(node.type);
    boolean vless = "vless".equals(node.type);
    if (!hy2 && !anytls && !vless) throw new IllegalArgumentException("Native node protocol required");
    if ((vless && node.uuid.isEmpty()) || (!vless && node.password.isEmpty())) throw new IllegalArgumentException("Missing node credentials");
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
      Class<?> networkType=Class.forName("go.mobilebridge.Network");
      Object network=Proxy.newProxyInstance(networkType.getClassLoader(),new Class<?>[]{networkType},
          (proxy,method,args)->{
            if(method.getName().equals("protect")) return vpnService.protectAndBind((Long)args[0]);
            if(method.getName().equals("resolve")) return vpnService.resolveOnPhysical((String)args[0]);
            if(method.getName().equals("toString")) return "CheemsPhysicalNetwork";
            throw new UnsupportedOperationException(method.getName());
          });
      String methodName = hy2 ? "startWithNetwork" : anytls ? "startAnyTLSWithNetwork" : "startVLESSWithNetwork";
      Method start = binding().getMethod(methodName, String.class, long.class, String.class,
          String.class, long.class, String.class, boolean.class, String.class, String.class, networkType);
      start.invoke(null, node.host, (long) node.port, node.sni, vless ? node.uuid : node.password, (long) localPort,
          token, allowUnverifiedTLS, platformAndCustomCAPEM, node.certificateSHA256(),network);
    } catch (ClassNotFoundException e) {
      localToken.compareAndSet(token, null);
      throw new IllegalStateException("Native protocol AAR is not packaged in this APK", e);
    } catch (InvocationTargetException e) {
      localToken.compareAndSet(token, null);
      Throwable cause = e.getCause();
      String detail = cause == null ? "未知错误" : cause.getMessage();
      if (detail == null || detail.isBlank()) detail = "未知错误";
      throw new IllegalStateException("节点建连失败：" + detail, cause);
    } catch (ReflectiveOperationException | LinkageError e) {
      localToken.compareAndSet(token, null);
      throw new IllegalStateException("Android 原生协议桥接异常", e);
    }
  }

  public static void startTunnel(long fd) throws Exception {
    try {binding().getMethod("startTunnel",long.class).invoke(null,fd);}
    catch(InvocationTargetException e){Throwable c=e.getCause();throw new IllegalStateException(c==null?"TUN启动失败":c.getMessage(),c);}
  }

  public static void stopTunnel() throws Exception {
    try {binding().getMethod("stopTunnel").invoke(null);}
    catch(InvocationTargetException e){Throwable c=e.getCause();throw new IllegalStateException(c==null?"TUN关闭失败":c.getMessage(),c);}
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

