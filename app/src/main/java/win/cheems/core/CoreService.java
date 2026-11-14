package win.cheems.core;

import android.app.*;
import android.content.*;
import android.os.IBinder;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import win.cheems.core.net.Hysteria2Native;
import win.cheems.core.net.Node;

public final class CoreService extends Service {
  static volatile Node selected;
  static volatile ProxyCore core;
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

  @Override
  public void onCreate() {
    super.onCreate();
    destroyed = false;
    core = new ProxyCore(CoreService::log);
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
                core.start(node);
                if (destroyed) {
                  core.stop();
                  if ("hysteria2".equals(node.type)) Hysteria2Native.stop();
                }
              } catch (Exception | LinkageError e) {
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
    if (core != null) core.stop();
    // Go startup may still be waiting for QUIC: do not block Android's main thread.
    new Thread(
            () -> {
              try {
                if (Hysteria2Native.isPackaged()) Hysteria2Native.stop();
              } catch (Exception e) {
                log("原生连接关闭异常");
              }
            },
            "cheems-shutdown")
        .start();
    stopForeground(STOP_FOREGROUND_REMOVE);
    super.onDestroy();
  }

  @Override
  public IBinder onBind(Intent i) {
    return null;
  }
}
