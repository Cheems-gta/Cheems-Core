package win.cheems.core;

import android.app.*;
import android.content.*;
import android.os.IBinder;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import java.net.InetAddress;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.security.SecureRandom;
import win.cheems.core.net.Hysteria2Native;
import win.cheems.core.net.Node;
import win.cheems.core.net.LocalProxyProbe;

public final class CoreService extends VpnService {
  static volatile Node selected;
  static volatile ProxyCore core;
  static volatile boolean connecting;
  static volatile boolean tunnelEstablished;
  static volatile boolean forwardingVerified;
  static volatile String lastFailure;
  static volatile String localHttpPassword;
  private String ownedHttpPassword;
  private ProxyCore ownedCore;
  private volatile Thread connectionMonitor;
  private static final ArrayDeque<String> events = new ArrayDeque<>();
  private final AtomicBoolean launching = new AtomicBoolean();
  private volatile boolean destroyed;
  private ParcelFileDescriptor vpnInterface;
  private android.net.Network physicalNetwork;

  static synchronized void log(String s) {
    if (events.size() >= 40) events.removeFirst();
    events.addLast(s);
  }

  static synchronized String logs() {
    return String.join("\n", events);
  }

  private void updateConnecting(boolean value) {
    // A canceled service must not overwrite the state of its successor.
    if (core == ownedCore) connecting = value;
  }

  private void watchNativeConnection(int startId) {
    Thread watcher = new Thread(
        () -> {
          String previousDiagnostic = "";
          while (!destroyed && core == ownedCore) {
            try {
              Thread.sleep(2000);
            } catch (InterruptedException interrupted) {
              return;
            }
            if (destroyed || core != ownedCore) return;
            String diagnostic = Hysteria2Native.tunnelLastError();
            if (!diagnostic.isEmpty() && !diagnostic.equals(previousDiagnostic)) {
              previousDiagnostic = diagnostic;
              log("隧道诊断：" + diagnostic);
            }
            if (!Hysteria2Native.isRunning()) {
              log("原生节点连接已中断，正在关闭失效代理");
              stopSelfResult(startId);
              return;
            }
          }
        },
        "cheems-hy2-watch");
    watcher.setDaemon(true);
    connectionMonitor = watcher;
    watcher.start();
  }

  @Override
  public void onCreate() {
    super.onCreate();
    destroyed = false;
    tunnelEstablished = false;
    forwardingVerified = false;
    byte[] secret = new byte[32];
    new SecureRandom().nextBytes(secret);
    ownedHttpPassword = Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
    localHttpPassword = ownedHttpPassword;
    ownedCore = new ProxyCore(CoreService::log, ownedHttpPassword);
    core = ownedCore;
  }

  @Override
  public int onStartCommand(Intent intent, int flags, int id) {
    NotificationManager nm = getSystemService(NotificationManager.class);
    nm.createNotificationChannel(
        new NotificationChannel("core", "Cheems Core VPN", NotificationManager.IMPORTANCE_LOW));
    PendingIntent open =
        PendingIntent.getActivity(
            this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
    Notification n =
        new Notification.Builder(this, "core")
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("Cheems Core · VPN")
            .setContentText("VPN服务启动中，节点转发待验证")
            .setContentIntent(open)
            .setOngoing(true)
            .build();
    startForeground(1, n);
    if (!launching.compareAndSet(false, true)) return START_NOT_STICKY;
    connecting = true;
    lastFailure = null;

    final boolean allowUnverifiedTLS =
        intent != null && intent.getBooleanExtra("hy2.allowUnverifiedTls", false);
    final String customCAPEM =
        intent == null ? null : intent.getStringExtra("hy2.trustedCaPem");
    final Node node = selected;
    new Thread(
            () -> {
              try {
                if (node == null || !node.supported()) {
                  throw new IllegalStateException("请选择有效且受支持的节点");
                }
                if (destroyed) return;
                boolean nativeNode = "hysteria2".equals(node.type) || "anytls".equals(node.type) || "vless".equals(node.type) || "vmess".equals(node.type) || "ss2022".equals(node.type) || "tuic".equals(node.type)
                    || ("socks5".equals(node.type) && Hysteria2Native.isPackaged());
                if (nativeNode) {
                  if (!Hysteria2Native.isPackaged()) {
                    throw new IllegalStateException("当前 APK 未打包原生协议内核");
                  }
                  log("正在连接 " + node.type.toUpperCase(java.util.Locale.ROOT) + " 节点…");
                  if (allowUnverifiedTLS)
                    log("安全提示：本次连接按用户确认跳过常规 TLS 校验；配置的证书指纹仍会检查");
                  else if (customCAPEM != null && !customCAPEM.isBlank())
                    log("本次节点连接使用自定义 CA，并继续校验服务器名称");
                  Hysteria2Native.start(node, Hysteria2Native.LOCAL_SOCKS_PORT,
                      allowUnverifiedTLS, customCAPEM, this);
                  establishVPNTunnel();
                }
                if (destroyed) {
                  if (nativeNode) Hysteria2Native.stop();
                  return;
                }
                ownedCore.start(node);
                log("本地 HTTP 代理已启动；正在自动检查节点 TCP 转发");
                try {
                  LocalProxyProbe.Result result = LocalProxyProbe.check(ownedHttpPassword);
                  if (destroyed || core != ownedCore) return;
                  forwardingVerified = true;
                  lastFailure = null;
                  log("节点 TCP 转发验证通过 · " + result.elapsedMs + " ms · " + result.responseStatus);
                  if (nativeNode) log("VPN 接口已建立；全局流量仍以应用访问和隧道计数为准");
                } catch (IOException probeFailure) {
                  if (destroyed || core != ownedCore) return;
                  forwardingVerified = false;
                  lastFailure = "测试目标转发未通过；查看运行记录";
                  log("自动转发检查失败：" + probeFailure.getMessage());
                }
                updateConnecting(false);
                if (nativeNode && !destroyed) {
                  if (!Hysteria2Native.isRunning()) {
                    log("原生节点连接已丢失，代理将停止");
                    stopSelfResult(id);
                    return;
                  }
                  watchNativeConnection(id);
                }
                if (destroyed) {
                  ownedCore.stop();
                  if (nativeNode) Hysteria2Native.stop();
                }
              } catch (Exception | LinkageError e) {
                updateConnecting(false);
                String message = e.getMessage();
                String detail = message == null ? e.getClass().getSimpleName() : message;
                String lower = detail.toLowerCase(java.util.Locale.ROOT);
                if (lower.contains("unknown authority"))
                  lastFailure = "证书不受信任；请核对 SNI，使用可信 CA 或服务商证书指纹";
                else if (lower.contains("no recent network activity") || lower.contains("timeout"))
                  lastFailure = "节点连接超时；请检查网络、协议端口和地址";
                else if (lower.contains("fingerprint mismatch"))
                  lastFailure = "服务器证书指纹不匹配，已拒绝连接";
                else lastFailure = "节点连接失败；查看运行记录";
                log("代理启动失败：" + detail);
                stopSelfResult(id);
              }
            },
            "cheems-connect")
        .start();
    return START_NOT_STICKY;
  }

  private android.net.Network choosePhysicalNetwork() {
    ConnectivityManager cm=getSystemService(ConnectivityManager.class);
    android.net.Network active=cm.getActiveNetwork();
    NetworkCapabilities activeCaps=active==null?null:cm.getNetworkCapabilities(active);
    if(activeCaps!=null && activeCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        && !activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return active;
    for(android.net.Network candidate:cm.getAllNetworks()) {
      NetworkCapabilities caps=cm.getNetworkCapabilities(candidate);
      if(caps!=null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
          && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return candidate;
    }
    return null;
  }

  public boolean protectAndBind(long rawFd) {
    if(rawFd<0 || rawFd>Integer.MAX_VALUE || !protect((int)rawFd)) return false;
    android.net.Network current=choosePhysicalNetwork();
    if(current==null) return false;
    try (ParcelFileDescriptor descriptor=ParcelFileDescriptor.fromFd((int)rawFd)) {
      current.bindSocket(descriptor.getFileDescriptor());
      physicalNetwork=current;
      setUnderlyingNetworks(new android.net.Network[]{current});
      return true;
    }
    catch(IOException e) { return false; }
  }

  public String resolveOnPhysical(String host) throws Exception {
    android.net.Network current=choosePhysicalNetwork();
    if(current==null) throw new IOException("No physical network available");
    InetAddress[] answers=current.getAllByName(host);
    if(answers.length==0) throw new IOException("Physical DNS returned no addresses");
    return answers[0].getHostAddress();
  }

  private void establishVPNTunnel() throws Exception {
    physicalNetwork=choosePhysicalNetwork();
    if(physicalNetwork==null) throw new IOException("No physical internet network available");
    Builder builder=new Builder().setSession("Cheems Core")
        .setMtu(1500)
        .addAddress("10.77.0.1",30)
        .addAddress("fd77:77::1",126)
        .addRoute("0.0.0.0",0)
        .addRoute("::",0)
        .addDnsServer("10.77.0.2")
        .addDnsServer("fd77:77::2")
        .addDisallowedApplication(getPackageName());
    vpnInterface=builder.establish();
    if(vpnInterface==null) throw new IOException("Android denied VPN interface establishment");
    setUnderlyingNetworks(new android.net.Network[]{physicalNetwork});
    Hysteria2Native.startTunnel(vpnInterface.getFd());
    if (!destroyed && core == ownedCore) tunnelEstablished = true;
    log("Android全局VPN和IPv4/IPv6隧道已启动");
  }

  @Override
  public void onDestroy() {
    destroyed = true;
    Thread watcher = connectionMonitor;
    if (watcher != null) watcher.interrupt();
    updateConnecting(false);
    if (ownedCore != null) ownedCore.stop();
    try { if(Hysteria2Native.isPackaged()) Hysteria2Native.stopTunnel(); }
    catch(Exception e) { log("TUN关闭异常"); }
    if(vpnInterface!=null) {try{vpnInterface.close();}catch(IOException ignored){} vpnInterface=null;}
    if (core == ownedCore) {
      tunnelEstablished = false;
      forwardingVerified = false;
      core = null;
    }
    if (ownedHttpPassword != null && ownedHttpPassword.equals(localHttpPassword))
      localHttpPassword = null;
    // Stop synchronously so an old asynchronous shutdown cannot destroy
    // a newly selected node's native session. Go Stop cancels pending startup.
    try {
      if (Hysteria2Native.isPackaged()) Hysteria2Native.stop();
    } catch (Exception e) {
      log("原生连接关闭异常");
    }
    stopForeground(STOP_FOREGROUND_REMOVE);
    super.onDestroy();
  }

  @Override
  public void onRevoke() {
    log("Android VPN 权限已撤销，正在关闭节点和隧道");
    stopSelf();
    super.onRevoke();
  }

  @Override
  public IBinder onBind(Intent i) {
    return super.onBind(i);
  }
}

