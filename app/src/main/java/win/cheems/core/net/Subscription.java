package win.cheems.core.net;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/** Parses data only: YAML tags cannot instantiate Java classes. */
public final class Subscription {
  public static final int MAX_BYTES = 2 * 1024 * 1024, MAX_NODES = 2000;

  public static List<Node> parse(String text) throws Exception {
    if (text.length() > MAX_BYTES) throw new IllegalArgumentException("订阅超过 2 MB");
    text = text.trim();
    if (!text.contains("://") && !text.contains("proxies") && !text.startsWith("[")) {
      try {
        text = decode(text).trim();
      } catch (Exception ignored) {
      }
    }
    List<Node> result = new ArrayList<>();
    if (text.startsWith("proxies:")
        || text.contains("\nproxies:")
        || text.startsWith("{")
        || text.startsWith("[")) {
      LoaderOptions opts = new LoaderOptions();
      opts.setMaxAliasesForCollections(0);
      opts.setCodePointLimit(MAX_BYTES);
      opts.setNestingDepthLimit(24);
      opts.setAllowDuplicateKeys(false);
      Object data = new Yaml(new SafeConstructor(opts)).load(text);
      Object list = data instanceof Map ? ((Map<?, ?>) data).get("proxies") : data;
      if (!(list instanceof List)) throw new IllegalArgumentException("没有找到 proxies 节点列表");
      for (Object entry : (List<?>) list) {
        if (!(entry instanceof Map)) continue;
        Map<String, Object> map = new LinkedHashMap<>();
        ((Map<?, ?>) entry).forEach((k, v) -> map.put(String.valueOf(k), v));
        result.add(new Node(map));
        if (result.size() > MAX_NODES) throw new IllegalArgumentException("节点数量超过 2000");
      }
    } else {
      for (String line : text.split("\\r?\\n")) {
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) continue;
        result.add(parseUri(line));
        if (result.size() > MAX_NODES) throw new IllegalArgumentException("节点数量超过 2000");
      }
    }
    if (result.isEmpty()) throw new IllegalArgumentException("未识别到节点，请使用 Clash 订阅或节点分享链接");
    return result;
  }

  private static Node parseUri(String link) throws Exception {
    String scheme = link.substring(0, link.indexOf("://")).toLowerCase(Locale.ROOT);
    if (!Arrays.asList("ss", "trojan", "socks5", "socks", "http", "https").contains(scheme)) {
      Map<String, Object> unsupported = new LinkedHashMap<>();
      unsupported.put("type", scheme);
      unsupported.put("server", "unsupported");
      unsupported.put("port", 1);
      unsupported.put("name", scheme + " 节点（暂不支持）");
      return new Node(unsupported);
    }
    if (scheme.equals("ss")) {
      String body = link.substring(5), fragment = "";
      int hash = body.indexOf('#');
      if (hash >= 0) {
        fragment = body.substring(hash);
        body = body.substring(0, hash);
      }
      if (!body.contains("@")) body = decode(body);
      link = "ss://" + body + fragment;
    }
    URI u = new URI(link);
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("type", scheme.equals("https") ? "http" : scheme.equals("socks") ? "socks5" : scheme);
    if (scheme.equals("https")) m.put("tls", true);
    m.put("server", u.getHost() == null ? "" : u.getHost().replace("[", "").replace("]", ""));
    m.put(
        "port",
        u.getPort() > 0
            ? u.getPort()
            : scheme.equals("https") ? 443 : scheme.equals("http") ? 80 : 0);
    m.put(
        "name",
        u.getRawFragment() == null ? scheme + " · " + u.getHost() : urlDecode(u.getRawFragment()));
    String user = u.getRawUserInfo() == null ? "" : urlDecode(u.getRawUserInfo());
    if (scheme.equals("ss")) {
      if (!user.contains(":")) user = decode(user);
      int sep = user.indexOf(':');
      if (sep < 0) throw new IllegalArgumentException("SS 链接缺少加密方式");
      m.put("cipher", user.substring(0, sep));
      m.put("password", user.substring(sep + 1));
    } else if (scheme.equals("trojan")) m.put("password", user);
    else {
      String[] pair = user.split(":", 2);
      m.put("username", pair[0]);
      m.put("password", pair.length > 1 ? pair[1] : "");
    }
    if (u.getRawQuery() != null)
      for (String part : u.getRawQuery().split("&")) {
        String[] kv = part.split("=", 2);
        String key = urlDecode(kv[0]), v = kv.length == 2 ? urlDecode(kv[1]) : "";
        if (key.equals("sni") || key.equals("peer")) m.put("sni", v);
        if (key.equals("type")) m.put("network", v);
        if (key.equals("plugin")) m.put("plugin", v);
        if ((key.equals("allowInsecure") || key.equals("insecure"))
            && (v.equals("1") || v.equals("true"))) m.put("skip-cert-verify", true);
      }
    return new Node(m);
  }

  private static String urlDecode(String s) throws Exception {
    return URLDecoder.decode(s.replace("+", "%2B"), "UTF-8");
  }

  private static String decode(String s) {
    s = s.replaceAll("\\s", "");
    try {
      return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException e) {
      return new String(Base64.getUrlDecoder().decode(s), StandardCharsets.UTF_8);
    }
  }
}
