package win.cheems.core;

import android.app.*;
import android.content.*;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.os.*;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.HttpsURLConnection;
import win.cheems.core.net.*;

public final class MainActivity extends Activity {
  private final int ink = Color.rgb(235, 232, 245),
      muted = Color.rgb(164, 157, 182),
      purple = Color.rgb(173, 133, 255);
  private final ExecutorService io = Executors.newSingleThreadExecutor();
  private final Handler handler = new Handler(Looper.getMainLooper());
  private List<Node> nodes = new ArrayList<>();
  private int selected = -1;
  private TextView status, metrics, logs, summary;
  private Spinner spinner;
  private boolean busy;
  private final Runnable tick =
      new Runnable() {
        public void run() {
          refresh();
          handler.postDelayed(this, 1000);
        }
      };

  @Override
  public void onCreate(Bundle b) {
    super.onCreate(b);
    getWindow().setStatusBarColor(Color.rgb(18, 15, 26));
    getWindow().setNavigationBarColor(Color.rgb(18, 15, 26));
    ScrollView scroll = new ScrollView(this);
    LinearLayout root = new LinearLayout(this);
    root.setOrientation(LinearLayout.VERTICAL);
    root.setPadding(dp(22), dp(28), dp(22), dp(32));
    root.setBackgroundColor(Color.rgb(18, 15, 26));
    scroll.addView(root);
    setContentView(scroll);
    root.setOnApplyWindowInsetsListener(
        (v, insets) -> {
          v.setPadding(
              dp(22),
              insets.getSystemWindowInsetTop() + dp(16),
              dp(22),
              insets.getSystemWindowInsetBottom() + dp(20));
          return insets;
        });
    root.requestApplyInsets();
    root.addView(label("CHEEMS CORE", 28, purple));
    root.addView(label("V0.2  /  独立节点代理实验版", 13, muted));
    LinearLayout state = card(root);
    status = label("● 未启动", 23, ink);
    state.addView(status);
    metrics = label("连接 0   ↑ 0 B   ↓ 0 B", 14, muted);
    state.addView(metrics);
    LinearLayout imports = card(root);
    imports.addView(label("01  节点", 17, ink));
    summary = label("导入 Flybit 的 Clash 订阅或分享链接", 13, muted);
    imports.addView(summary);
    button(imports, "导入订阅 / 粘贴节点", this::importDialog);
    spinner = new Spinner(this);
    imports.addView(spinner);
    spinner.setOnItemSelectedListener(
        new android.widget.AdapterView.OnItemSelectedListener() {
          public void onItemSelected(android.widget.AdapterView<?> a, View v, int p, long id) {
            if (selected != p && CoreService.core != null && CoreService.core.running()) {
              stopService(new Intent(MainActivity.this, CoreService.class));
              CoreService.log("节点已切换，请重新启动代理");
            }
            selected = p;
            getPreferences(0).edit().putInt("selected", p).apply();
          }

          public void onNothingSelected(android.widget.AdapterView<?> a) {}
        });
    button(imports, "验证所选节点的转发", this::probe);
    LinearLayout actions = card(root);
    actions.addView(label("02  本地代理", 17, ink));
    button(
        actions,
        "启动代理",
        () -> {
          Node n = current();
          if (n == null) return;
          if (Build.VERSION.SDK_INT >= 33
              && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)
                  != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[] {android.Manifest.permission.POST_NOTIFICATIONS}, 1);
          CoreService.selected = n;
          startForegroundService(new Intent(this, CoreService.class));
        });
    button(actions, "停止并关闭连接", () -> stopService(new Intent(this, CoreService.class)));
    actions.addView(
        label("监听 127.0.0.1:8899（HTTP CONNECT）。需要应用显式使用此代理；本版尚未接入 Android 全局 VPN。", 13, muted));
    LinearLayout events = card(root);
    events.addView(label("03  运行记录", 17, ink));
    logs = label("等待导入节点", 12, muted);
    events.addView(logs);
    root.addView(
        label(
            "已实现：SS AEAD · Trojan TCP/TLS · SOCKS5 · HTTP(S)\n"
                + "暂不支持：VMess、VLESS、HY2、SS 2022、插件、UDP。\n"
                + "节点凭据仅加密保存在本机，不上传到项目仓库。",
            12,
            muted));
    io.execute(
        () -> {
          try {
            String saved = Vault.load(this);
            if (!saved.isEmpty()) {
              List<Node> parsed = Subscription.parse(saved);
              runOnUiThread(() -> setNodes(parsed));
            }
          } catch (Exception e) {
            runOnUiThread(() -> message("本地配置无法读取，请重新导入"));
          }
        });
  }

  private TextView label(String text, int size, int color) {
    TextView t = new TextView(this);
    t.setText(text);
    t.setTextSize(size);
    t.setTextColor(color);
    t.setPadding(0, dp(5), 0, dp(8));
    return t;
  }

  private LinearLayout card(LinearLayout root) {
    LinearLayout l = new LinearLayout(this);
    l.setOrientation(LinearLayout.VERTICAL);
    l.setPadding(dp(16), dp(12), dp(16), dp(14));
    GradientDrawable bg = new GradientDrawable();
    bg.setColor(Color.rgb(31, 26, 44));
    bg.setCornerRadius(dp(18));
    l.setBackground(bg);
    LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, -2);
    p.topMargin = dp(18);
    root.addView(l, p);
    return l;
  }

  private void button(LinearLayout box, String text, Runnable action) {
    Button b = new Button(this);
    b.setText(text);
    b.setAllCaps(false);
    b.setTextColor(ink);
    b.setBackgroundTintList(android.content.res.ColorStateList.valueOf(Color.rgb(71, 48, 106)));
    box.addView(b, new LinearLayout.LayoutParams(-1, dp(54)));
    b.setOnClickListener(v -> action.run());
  }

  private int dp(int n) {
    return (int) (n * getResources().getDisplayMetrics().density);
  }

  private void message(String s) {
    if (!isFinishing())
      new AlertDialog.Builder(this).setMessage(s).setPositiveButton("知道了", null).show();
  }

  private Node current() {
    if (selected < 0 || selected >= nodes.size()) {
      message("请先导入并选择节点");
      return null;
    }
    Node n = nodes.get(selected);
    if (!n.supported()) {
      message(n.unsupported);
      return null;
    }
    return n;
  }

  private void setNodes(List<Node> list) {
    nodes = list;
    ArrayAdapter<Node> adapter =
        new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, nodes);
    spinner.setAdapter(adapter);
    selected = Math.min(getPreferences(0).getInt("selected", 0), nodes.size() - 1);
    spinner.setSelection(Math.max(0, selected));
    int supported = 0;
    Map<String, Integer> types = new TreeMap<>();
    for (Node n : nodes) {
      if (n.supported()) supported++;
      types.put(n.type, types.getOrDefault(n.type, 0) + 1);
    }
    summary.setText(
        "共 " + nodes.size() + " 个 · 可用协议配置 " + supported + " 个\n" + types + "\n实际连通性需验证");
  }

  private void importDialog() {
    if (busy) return;
    EditText input = new EditText(this);
    input.setTextColor(ink);
    input.setHintTextColor(muted);
    input.setHint("https://订阅地址 或 节点链接 / Clash YAML");
    input.setMinLines(3);
    input.setMaxLines(8);
    input.setInputType(
        android.text.InputType.TYPE_CLASS_TEXT
            | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
            | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
    new AlertDialog.Builder(this)
        .setTitle("导入节点")
        .setMessage("订阅会在手机上直接下载。使用 Flybit 的 Clash 订阅格式兼容性更好。")
        .setView(input)
        .setNegativeButton("取消", null)
        .setPositiveButton("导入", (d, w) -> importText(input.getText().toString().trim()))
        .show();
  }

  private void importText(String raw) {
    busy = true;
    summary.setText("正在读取订阅…");
    io.execute(
        () -> {
          try {
            String data = raw;
            if (raw.matches("(?is)^https?://\\S+$")) data = download(raw);
            List<Node> parsed = Subscription.parse(data);
            Vault.save(this, data);
            runOnUiThread(
                () -> {
                  stopService(new Intent(this, CoreService.class));
                  setNodes(parsed);
                  CoreService.log("导入完成：" + parsed.size() + " 个节点；未建立连接");
                });
          } catch (Exception e) {
            runOnUiThread(
                () -> {
                  summary.setText("导入失败");
                  String reason = e.getMessage();
                  message(
                      "导入失败："
                          + (reason == null || reason.isBlank()
                              ? e.getClass().getSimpleName()
                              : reason));
                });
          } finally {
            runOnUiThread(() -> busy = false);
          }
        });
  }

  private String download(String link) throws Exception {
    URL u = new URL(link);
    for (int redirect = 0; redirect < 8; redirect++) {
      if (!u.getProtocol().equalsIgnoreCase("https"))
        throw new IOException("订阅跳转到了 HTTP 明文地址，已阻止下载。请在 Flybit 重新复制 HTTPS 订阅链接。");
      HttpsURLConnection c = (HttpsURLConnection) u.openConnection();
      c.setInstanceFollowRedirects(false);
      c.setConnectTimeout(15000);
      c.setReadTimeout(20000);
      c.setRequestProperty("User-Agent", "clash.meta/1.19.20");
      c.setRequestProperty("Accept", "application/yaml, text/yaml, text/plain, */*");
      c.setRequestProperty("Accept-Encoding", "identity");
      try {
        int code = c.getResponseCode();
        if (code >= 300 && code < 400) {
          String target = c.getHeaderField("Location");
          if (target == null) throw new IOException("订阅服务器返回跳转，但没有提供跳转地址。");
          u = new URL(u, target);
          continue;
        }
        if (code != 200) {
          String reason;
          if (code == 401 || code == 403)
            reason = "服务器拒绝订阅请求（HTTP " + code + "）。请确认订阅状态，或在 Flybit 重新复制 Clash 订阅链接。";
          else if (code == 404) reason = "订阅地址不存在（HTTP 404）。请在 Flybit 后台重新复制完整的 Clash 订阅链接。";
          else if (code == 429) reason = "订阅请求过于频繁（HTTP 429），请稍后再试。";
          else reason = "订阅服务器返回 HTTP " + code + "。请检查订阅状态或稍后重试。";
          throw new IOException(reason);
        }
        try (InputStream in = c.getInputStream();
            ByteArrayOutputStream out = new ByteArrayOutputStream()) {
          byte[] b = new byte[8192];
          int n;
          while ((n = in.read(b)) != -1) {
            if (out.size() + n > Subscription.MAX_BYTES) throw new IOException("Too large");
            out.write(b, 0, n);
          }
          String body =
              new String(out.toByteArray(), StandardCharsets.UTF_8).replace("\uFEFF", "").trim();
          if (body.isEmpty()) throw new IOException("订阅服务器返回空内容。请确认后台复制的是 Clash 订阅。");
          String contentType = c.getContentType();
          if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("text/html"))
            throw new IOException("订阅地址返回了网页而不是节点配置。请使用 Flybit 后台的 Clash 订阅链接，不要用登录或购买页面地址。");
          return body;
        }
      } finally {
        c.disconnect();
      }
    }
    throw new IOException("订阅服务器连续跳转超过 8 次。请在 Flybit 后台重新复制订阅链接。");
  }

  private void probe() {
    Node n = current();
    if (n == null || busy) return;
    busy = true;
    CoreService.log("正在验证节点的 HTTP 转发…");
    io.execute(
        () -> {
          long start = System.nanoTime();
          try (Dialer.Tunnel t = Dialer.connect(n, "example.com", 80, s -> {})) {
            t.socket.setSoTimeout(15000);
            t.out.write(
                "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
                    .getBytes(StandardCharsets.US_ASCII));
            t.out.flush();
            String response = Dialer.header(t.in).split("\r\n")[0];
            if (!response.matches("HTTP/1\\.[01] [23][0-9][0-9].*"))
              throw new IOException("Unexpected response");
            CoreService.log(
                "转发验证成功 · " + ((System.nanoTime() - start) / 1000000) + " ms · " + response);
          } catch (Exception e) {
            CoreService.log("转发验证失败 · " + e.getClass().getSimpleName() + "（未回退直连）");
          } finally {
            runOnUiThread(() -> busy = false);
          }
        });
  }

  private void refresh() {
    if (status == null) return;
    ProxyCore c = CoreService.core;
    status.setText(c != null && c.running() ? "● 本地代理运行中" : "● 未启动");
    metrics.setText(
        c == null
            ? "连接 0   ↑ 0 B   ↓ 0 B"
            : "连接 " + c.active() + "   ↑ " + c.uploaded() + " B   ↓ " + c.downloaded() + " B");
    logs.setText(CoreService.logs());
  }

  @Override
  public void onResume() {
    super.onResume();
    handler.post(tick);
  }

  @Override
  public void onPause() {
    handler.removeCallbacks(tick);
    super.onPause();
  }

  @Override
  public void onDestroy() {
    handler.removeCallbacks(tick);
    io.shutdownNow();
    super.onDestroy();
  }
}
