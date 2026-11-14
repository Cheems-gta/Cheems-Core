package win.cheems.core.net;

import java.util.*;

/** Immutable imported endpoint. Credentials must never appear in logs. */
public final class Node {
  public final String name, type, host, password, username, cipher, sni, unsupported;
  public final int port;
  public final Map<String, Object> source;

  public Node(Map<String, Object> m) {
    source = Collections.unmodifiableMap(new LinkedHashMap<>(m));
    type = value(m, "type", "").toLowerCase(Locale.ROOT).equals("hy2") ? "hysteria2" : value(m, "type", "").toLowerCase(Locale.ROOT);
    host = value(m, "server", "");
    int p;
    try {
      p = Integer.parseInt(value(m, "port", "0"));
    } catch (Exception e) {
      p = 0;
    }
    port = p;
    name = value(m, "name", type + " · " + host);
    password = value(m, "password", "");
    username = value(m, "username", "");
    cipher = value(m, "cipher", "").toLowerCase(Locale.ROOT);
    sni = value(m, "sni", value(m, "servername", host));
    String reason = "";
    if (host.isEmpty() || port < 1 || port > 65535) reason = "地址或端口无效";
    else if (type.equals("hysteria2") && password.isEmpty()) reason = "Hysteria 2 缺少认证密码";
    else if (type.equals("hysteria2") && Boolean.parseBoolean(value(m, "skip-cert-verify", "false")))
      reason = "Hysteria 2 配置要求跳过证书验证；当前安全策略不允许";
    else if (type.equals("hysteria2") && (!value(m, "obfs", "").isEmpty() || !value(m, "obfs-password", "").isEmpty()))
      reason = "当前独立内核尚不支持 Hysteria 2 混淆（Salamander）";
    else if (type.equals("hysteria2") && m.containsKey("ports"))
      reason = "当前独立内核尚不支持 Hysteria 2 端口跳跃";
    else if (type.equals("anytls"))
      reason = "AnyTLS 节点已识别，但当前版本尚未实现会话协议；不可连接。请等待真实协议实现和互通测试";
    else if (!Arrays.asList("ss", "trojan", "socks5", "http", "hysteria2").contains(type))
      reason = "暂未实现 " + type + " 协议";
    else if (m.containsKey("plugin") && !value(m, "plugin", "").isEmpty()) reason = "暂不支持插件传输";
    else if (!Arrays.asList("tcp", "").contains(value(m, "network", "tcp")))
      reason = "暂不支持 " + value(m, "network", "") + " 传输";
    else if (m.containsKey("reality-opts") || m.containsKey("ws-opts"))
      reason = "暂不支持 Reality / WebSocket";
    else if (type.equals("ss")
        && !Arrays.asList("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305").contains(cipher))
      reason = "暂不支持加密方式 " + cipher;
    else if ((type.equals("ss") || type.equals("trojan")) && password.isEmpty()) reason = "缺少密码";
    else if (Boolean.parseBoolean(value(m, "skip-cert-verify", "false")))
      reason = "此配置要求跳过证书验证；请使用有效证书";
    unsupported = reason;
  }

  public boolean supported() {
    return unsupported.isEmpty();
  }

  public boolean tls() {
    return type.equals("trojan") || Boolean.parseBoolean(value(source, "tls", "false"));
  }

  public static String value(Map<?, ?> m, String key, String fallback) {
    Object v = m.get(key);
    return v == null ? fallback : String.valueOf(v);
  }

  @Override
  public String toString() {
    return name + " · " + type.toUpperCase(Locale.ROOT) + (supported() ? "" : " · " + unsupported);
  }
}
