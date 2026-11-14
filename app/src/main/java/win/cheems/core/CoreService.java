package win.cheems.core;

import android.app.*;
import android.content.*;
import android.os.IBinder;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.security.SecureRandom;
import win.cheems.core.net.Hysteria2Native;
import win.cheems.core.net.Node;

public final class CoreService extends Service {
  static volatile Node selected;
  static volatile ProxyCore core;
  static volatile boolean connecting;
  static volatile String localHttpPassword;
  private String ownedHttpPassword;
  private ProxyCore ownedCore;
  private volatile Thread connectionMonitor;
  private static final ArrayDeque<String> events = new ArrayDeque<>();
  private final AtomicBoolean launching = new AtomicBoolean();
  private volatile boolean destroyed;

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
          while (!destroyed && core == ownedCore) {
            try {
              Thread.sleep(2000);
            } catch (InterruptedException interrupted) {
              return;
            }
            if (destroyed || core != ownedCore) return;
            if (!Hysteria2Native.isRunning()) {
              log("Hysteria 2 远端连接已中断，正在关闭失效的本地代理");
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
        new NotificationChannel("core", "本地代理服务", NotificationManager.IMPORTANCE_LOW));
    PendingIntent open =
        PendingIntent.getActivity(
            this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
    Notification n =
        new Notification.Builder(this, "core")
            .setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("Cheems Core · 本地代理")
            .setContentText("127.0.0.1:8899 · 仅代理显式配置的应用")
            .setContentIntent(open)
            .setOngoing(true)
            .build();
    startForeground(1, n);
    if (!launching.compareAndSet(false, true)) return START_NOT_STICKY;
    connecting = true;

    final Node node = selected;
    new Thread(
            () -> {
              try {
                if (node == null || !node.supported()) {
                  throw new IllegalStateException("请选择有效且受支持的节点");
                }
                if (destroyed) return;
                if ("hysteria2".equals(node.type)) {
                  if (!Hysteria2Native.isPackaged()) {
                    throw new IllegalStateException("当前 APK 未打包 Hysteria 2 原生内核");
                  }
                  log("正在通过 QUIC 连接 Hysteria 2 服务端…");
                  Hysteria2Native.start(node, Hysteria2Native.LOCAL_SOCKS_PORT);
                }
                if (destroyed) {
                  if ("hysteria2".equals(node.type)) Hysteria2Native.stop();
                  return;
                }
                ownedCore.start(node);
                updateConnecting(false);
                if ("hysteria2".equals(node.type) && !destroyed) {
                  if (!Hysteria2Native.isRunning()) {
                    log("Hysteria 2 连接已丢失，本地代理将停止");
                    stopSelfResult(id);
                    return;
                  }
                  watchNativeConnection(id);
                }
                if (destroyed) {
                  ownedCore.stop();
                  if ("hysteria2".equals(node.type)) Hysteria2Native.stop();
                }
              } catch (Exception | LinkageError e) {
                updateConnecting(false);
                String message = e.getMessage();
                log("代理启动失败：" + (message == null ? e.getClass().getSimpleName() : message));
                stopSelfResult(id);
              }
            },
            "cheems-connect")
        .start();
    return START_NOT_STICKY;
  }

  @Override
  public void onDestroy() {
    destroyed = true;
    Thread watcher = connectionMonitor;
    if (watcher != null) watcher.interrupt();
    updateConnecting(false);
    if (ownedCore != null) ownedCore.stop();
    if (core == ownedCore) core = null;
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
  public IBinder onBind(Intent i) {
    return null;
  }
}
