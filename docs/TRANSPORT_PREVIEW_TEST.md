# Cheems Core 0.4.1 transport preview — 真机测试

这是需要手机验收的测试版，尚未证明 Flybit 实际可用或长期稳定。

支持本批测试的组合：
- VMess / VLESS：普通 TLS WebSocket，Host + Path，未支持早期数据与任意自定义请求头。
- VMess / VLESS：TLS gRPC 标准 Tun，需明确服务名称；未支持 TunMulti、压缩与 h2c。
- VLESS TCP Reality：空 flow，chrome/firefox，X25519 公钥与 short ID。

不支持 XTLS Vision、Reality WS/gRPC、ML-DSA Reality 认证。配置会明确拒绝这些组合。
原有 HY2/AnyTLS/TUIC/SS2022/SOCKS5 的实验路径仍保留。

测试步骤：
1. 下载并解压构建附件，安装其中的 APK。测试包用调试签名；若旧包签名冲突，先自行备份订阅，再卸载旧包。
2. 停止其他 VPN，导入你自己有权使用的订阅。不要把订阅地址或节点密码发到公开日志。
3. 先选一个已有 HY2/AnyTLS 节点验证基本启动，再选本批传输组合分别验证。
4. 点启动并授权 Android VPN，打开网页，再运行应用内的完整转发检查。
5. 测试停止后网络恢复，以及 Wi-Fi/移动网络切换。自动重连、后台长期运行仍需验证。
6. 反馈节点协议/传输类型、失败步骤和脱敏后的错误日志。无需提供密码、公钥以外的认证材料或订阅地址。

源码归档与 SHA256 校验文件随 APK 同时提供。源码 CI 和签名检查不等于真机通过。

## 0.4.1 证书选项弹窗修复

说明文字和连接按钮改为同一个可滚动布局，避免 Android 原生对话框隐藏选项列表。应显示严格验证、粘贴可信 CA 和本次跳过验证三个独立按钮；跳过验证仍需再次确认。Android 9/15 的 UI 回归检查覆盖按钮可见性与点击分派。
