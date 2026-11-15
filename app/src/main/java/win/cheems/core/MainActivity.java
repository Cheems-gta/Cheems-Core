package win.cheems.core;

import android.app.*;
import android.net.VpnService;
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
  private static final int VPN_PERMISSION_REQUEST=7134;
  private Node pendingVpnNode;
  private boolean pendingAllowUnverifiedTLS;
  private String pendingTrustedCAPEM;
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
    root.addView(label("V" + packageVersion() + " / 独立节点代理实验版", 13, muted));
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
            if (selected >= 0 && selected != p && CoreService.core != null) {
              stopService(new Intent(MainActivity.this, CoreService.class));
              CoreService.log("节点已切换，请重新启动代理");
            }
            selected = p;
            getPreferences(0).edit().putInt("selected", p).apply();
          }

          public void onNothingSelected(android.widget.AdapterView<?> a) {}
        });
    button(imports, "验证完整代理转发（需先启动）", this::probe);
    LinearLayout actions = card(root);
    actions.addView(label("02  本地代理", 17, ink));
    button(
        actions,
        "启动代理",
        () -> {
          Node n = current();
          if (n == null) return;
          if (n.hasInsecureTlsFlag()) {
            TlsChoiceDialog.show(this,
                () -> startProxy(n, false, ""),
                () -> askTrustedCA(n),
                () -> confirmUnverifiedTLS(n));
          } else {
            startProxy(n, false, "");
          }
        });
    button(actions, "停止并关闭连接", () -> stopService(new Intent(this, CoreService.class)));
    button(actions, "复制本地代理账号 / 密码", () -> {
      String secret = CoreService.localHttpPassword;
      if (secret == null || secret.isEmpty()) {
        message("请先启动本地代理，再获取本次会话的认证信息。");
        return;
      }
      ClipboardManager clipboard =
          (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
      ClipData clip = ClipData.newPlainText(
          "Cheems Core HTTP Proxy", "用户名：cheems\n密码：" + secret);
      if (Build.VERSION.SDK_INT >= 33) {
        android.os.PersistableBundle extras = new android.os.PersistableBundle();
        extras.putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true);
        clip.getDescription().setExtras(extras);
      }
      clipboard.setPrimaryClip(clip);
      message("已复制本次会话的代理用户名和密码。请仅在你信任的应用中配置代理。");
    });
    actions.addView(
        label("HY2、AnyTLS、VLESS、VMess、SS2022 与 TUIC v5 可建立实验性全局 VPN。VMess UDP 需节点支持；SS2022 UDP 为实验功能。VMess/VLESS WebSocket 和标准 gRPC 已接入；VLESS TCP Reality 已接入。", 13, muted));
    LinearLayout events = card(root);
    events.addView(label("03  运行记录", 17, ink));
    logs = label("等待导入节点", 12, muted);
    events.addView(logs);
    android.content.SharedPreferences startup = getSharedPreferences("vpn_startup", MODE_PRIVATE);
    if (startup.getBoolean("pending", false)) {
      String interrupted = startup.getString("last_stage", "未知阶段");
      CoreService.connecting = false;
      CoreService.lastFailure = "上次 VPN 启动可能异常中断；查看运行记录";
      CoreService.log("上次 VPN 进程可能在【" + interrupted + "】阶段异常退出；请复制运行记录。");
      startup.edit().putBoolean("pending", false).apply();
    }
    if (startup.getBoolean("crash_pending", false)) {
      // Only exception category and code location are stored. Never credentials.
      String kind = startup.getString("crash_type", "UnknownError");
      String site = startup.getString("crash_site", "unknown");
      String thread = startup.getString("crash_thread", "unknown");
      String phase = startup.getString("last_stage", "未知阶段");
      CoreService.lastFailure = "检测到上次异常退出，请查看运行记录";
      CoreService.log("检测到上次应用异常退出：类型=" + kind
          + "；线程=" + thread + "；位置=" + site
          + "；VPN 阶段=" + phase);
      startup.edit().remove("crash_pending").remove("crash_type")
          .remove("crash_site").remove("crash_thread").apply();
    }
    button(events, "复制诊断运行记录", () -> {
      String entries = CoreService.logs();
      if (entries.isBlank()) {
        message("暂时没有可复制的运行记录。");
        return;
      }
      ClipboardManager clipboard =
          (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
      clipboard.setPrimaryClip(ClipData.newPlainText("Cheems Core diagnostic", entries));
      message("已复制运行记录。发送之前请检查并删去任何不希望分享的信息。");
    });
    root.addView(
        label(
            "已实现：SS AEAD · Trojan TCP/TLS · SOCKS5 · HTTP(S)\n"
                + "HY2：实验性 VPN，UDP 取决于节点。AnyTLS/VLESS TCP+TLS：实验性 VPN。SOCKS5：实验性 TCP/UDP VPN。\n"
                + "暂不支持：XTLS Vision、Reality WS/gRPC、gRPC TunMulti、协议插件和 AnyTLS UDP。\n"
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

  private String packageVersion() {
    try {
      return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
    } catch (Exception e) {
      return "unknown";
    }
  }

  private void askTrustedCA(Node node) {
    EditText pem = new EditText(this);
    pem.setHint("-----BEGIN CERTIFICATE-----");
    pem.setMinLines(5);
    pem.setMaxLines(10);
    pem.setInputType(android.text.InputType.TYPE_CLASS_TEXT
        | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
        | android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
    new AlertDialog.Builder(this)
        .setTitle("粘贴服务商提供的可信 CA 证书")
        .setMessage("仅接受 PEM 格式证书，不接受文件路径。证书只用于本次连接。"
            + " 不要粘贴私钥或订阅密码。")
        .setView(pem)
        .setNegativeButton("取消", null)
        .setPositiveButton("验证 CA 并连接", (dialog, which) -> {
          String value = pem.getText().toString().trim();
          if (!value.contains("-----BEGIN CERTIFICATE-----")
              || !value.contains("-----END CERTIFICATE-----") || value.length() > 64 * 1024) {
            message("请粘贴完整 PEM 格式 CA 证书（不超过 64 KiB）。");
            return;
          }
          startProxy(node, false, value);
        })
        .show();
  }

  private void confirmUnverifiedTLS(Node node) {
    new AlertDialog.Builder(this)
        .setTitle("高风险：跳过节点证书验证")
        .setMessage("如果没有预先可信的证书指纹，攻击者可能冒充代理服务器，"
            + "甚至窃取连接凭据。这不会永久修改设置，也不会影响其他节点。"
            + "只在你确认信任当前网络和节点服务商时使用。")
        .setNegativeButton("返回", null)
        .setPositiveButton("已知风险，仅本次尝试", (dialog, which) ->
            startProxy(node, true, ""))
        .show();
  }

  private void startProxy(Node node, boolean allowUnverifiedTLS, String trustedCAPEM) {
    if (nativeProtocol(node)) {
      Intent prepare=VpnService.prepare(this);
      if(prepare!=null) {
        pendingVpnNode=node;
        pendingAllowUnverifiedTLS=allowUnverifiedTLS;
        pendingTrustedCAPEM=trustedCAPEM;
        startActivityForResult(prepare,VPN_PERMISSION_REQUEST);
        return;
      }
    }
    launchVpnService(node,allowUnverifiedTLS,trustedCAPEM);
  }

  @Override protected void onActivityResult(int requestCode,int resultCode,Intent data) {
    super.onActivityResult(requestCode,resultCode,data);
    if(requestCode!=VPN_PERMISSION_REQUEST)return;
    Node node=pendingVpnNode;boolean insecure=pendingAllowUnverifiedTLS;String ca=pendingTrustedCAPEM;
    pendingVpnNode=null;pendingTrustedCAPEM=null;pendingAllowUnverifiedTLS=false;
    if(resultCode==RESULT_OK && node!=null)launchVpnService(node,insecure,ca);
    else {CoreService.connecting=false;CoreService.lastFailure="VPN权限未授予";CoreService.log("Android VPN权限请求已取消");refresh();}
  }

  private void launchVpnService(Node node, boolean allowUnverifiedTLS, String trustedCAPEM) {
    if (CoreService.connecting || (CoreService.core != null && CoreService.core.running())) {
      message("当前服务正在连接或运行，请先停止再重试。");
      return;
    }
    if (Build.VERSION.SDK_INT >= 33
        && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)
            != android.content.pm.PackageManager.PERMISSION_GRANTED) {
      requestPermissions(new String[] {android.Manifest.permission.POST_NOTIFICATIONS}, 1);
    }
    CoreService.selected = node;
    CoreService.lastFailure = null;
    CoreService.connecting = true;
    CoreService.log("正在准备节点连接（证书策略仅对此次连接有效）");
    Intent service = new Intent(this, CoreService.class);
    service.putExtra("hy2.allowUnverifiedTls", allowUnverifiedTLS);
    service.putExtra("hy2.trustedCaPem", trustedCAPEM);
    try {
      startForegroundService(service);
    } catch (RuntimeException e) {
      CoreService.connecting = false;
      CoreService.lastFailure = "本地服务启动失败";
      CoreService.log("启动前台服务失败：" + e.getClass().getSimpleName());
    }
    refresh();
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
    if (nativeProtocol(n) && !Hysteria2Native.isPackaged()) {
      message("当前 APK 未集成原生协议内核，请使用带 Native AAR 的构建版。");
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
      if (n.supported() && (!nativeProtocol(n) || Hysteria2Native.isPackaged())) supported++;
      types.put(n.type, types.getOrDefault(n.type, 0) + 1);
    }
    summary.setText(
        "共 " + nodes.size() + " 个 · 可尝试的协议配置 " + supported + " 个\n" + types + "\n证书、认证和真实连通性尚未验证");
  }

  private static boolean nativeProtocol(Node n) {
    return "hysteria2".equals(n.type) || "anytls".equals(n.type) || "vless".equals(n.type) || "vmess".equals(n.type) || "ss2022".equals(n.type) || "tuic".equals(n.type)
        || ("socks5".equals(n.type) && Hysteria2Native.isPackaged());
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
    Node node = current();
    if (node == null || busy) return;
    ProxyCore activeCore = CoreService.core;
    if (activeCore == null || !activeCore.running() || CoreService.selected != node) {
      message("请先启动当前所选节点的代理，再验证完整的 HTTP CONNECT 转发。");
      return;
    }
    if (nativeProtocol(node) && !Hysteria2Native.isRunning()) {
      message("本地代理虽然可能正在运行，但原生节点会话已中断。");
      return;
    }
    String secret = CoreService.localHttpPassword;
    if (secret == null || secret.isEmpty()) {
      message("本地代理认证信息不可用，请停止后重新启动。");
      return;
    }
    busy = true;
    CoreService.log("完整转发诊断：本地 HTTP → 节点 → example.com:80");
    io.execute(
        () -> {
          try {
            LocalProxyProbe.Result result = LocalProxyProbe.check(secret);
            if (CoreService.core == activeCore) {
              CoreService.forwardingVerified = true;
              CoreService.lastFailure = null;
            }
            CoreService.log(
                "完整转发验证成功 · " + result.elapsedMs + " ms · " + result.responseStatus);
          } catch (Exception e) {
            // Never print provider credentials or temporary proxy auth tokens.
            String detail = e.getMessage();
            if (CoreService.core == activeCore) {
              CoreService.forwardingVerified = false;
              CoreService.lastFailure = "测试目标转发未通过；查看运行记录";
            }
            CoreService.log("完整转发失败 · "
                + (detail == null || detail.isBlank()
                    ? e.getClass().getSimpleName() : detail)
                + "（没有回退直连）");
          } finally {
            runOnUiThread(() -> busy = false);
          }
        });
  }

  private void refresh() {
    if (status == null) return;
    ProxyCore c = CoreService.core;
    boolean localRunning = c != null && c.running();
    boolean nativeDisconnected = localRunning && CoreService.selected != null
        && nativeProtocol(CoreService.selected) && !Hysteria2Native.isRunning();
    status.setText(
        CoreService.connecting ? (CoreService.tunnelEstablished ? "● VPN已建立，正在验证节点转发…" : "● 正在连接节点…") :
        nativeDisconnected ? "● 原生节点已断开" :
        localRunning ? (CoreService.lastFailure != null ? "● " + CoreService.lastFailure
            : CoreService.tunnelEstablished
                ? (CoreService.forwardingVerified ? "● 节点TCP转发已验证，VPN已建立" : "● VPN已建立，转发待验证")
                : "● 本地代理运行中，未建立全局VPN") :
        CoreService.lastFailure != null ? "● " + CoreService.lastFailure : "● 未启动");
    if (localRunning && CoreService.tunnelEstablished) {
      metrics.setText("隧道连接 " + Hysteria2Native.tunnelConnections()
          + "   ↑ " + Hysteria2Native.tunnelUploaded() + " B   ↓ " + Hysteria2Native.tunnelDownloaded()
          + " B\nDNS 查询 " + Hysteria2Native.tunnelDNSQueries());
    } else {
      metrics.setText(c == null ? "连接 0   ↑ 0 B   ↓ 0 B"
          : "本地连接 " + c.active() + "   ↑ " + c.uploaded() + " B   ↓ " + c.downloaded() + " B");
    }
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

