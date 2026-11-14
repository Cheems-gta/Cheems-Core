package win.cheems.core;

import android.app.*;
import android.content.*;
import android.os.IBinder;
import java.util.*;
import win.cheems.core.net.Node;

public final class CoreService extends Service {
  static volatile Node selected;
  static volatile ProxyCore core;
  private static final ArrayDeque<String> events = new ArrayDeque<>();

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
    try {
      core.start(selected);
    } catch (Exception e) {
      log("无法启动：请检查节点选择或端口占用");
      stopSelf();
    }
    return START_NOT_STICKY;
  }

  @Override
  public void onDestroy() {
    if (core != null) core.stop();
    stopForeground(STOP_FOREGROUND_REMOVE);
    super.onDestroy();
  }

  @Override
  public IBinder onBind(Intent i) {
    return null;
  }
}
