# 在原 Python MTProxy 上新增 WEB 模式

这版以你提供的 `mtprotoproxy.py`、`config.py`、`requirements.txt` 为基础。

- 启动文件仍是 **mtprotoproxy.py**。
- 原来的 **classic / secure / tls** 模式保留；默认仍然是原来的 tls 模式。
- 新增 **web** 模式，配置中只增加 `MODES["web"]` 和 **WEB_DOMAIN**。
- 端口、用户和密钥继续使用原来的 **PORT、USERS**，其它设置使用默认值。
- **requirements.txt 原样保留**。新增 WEB 模块只使用 Python 标准库和原依赖中的 cryptography。
- 不使用前一版启动器，不下载或编译 Go 程序，不需要 Docker、Nginx/Caddy 或 Tunnel。

## 上传和启用

停止旧进程，把下面四个文件放到同一目录：

```text
mtprotoproxy.py
webproxy.py
config.py
requirements.txt
```

WEB 作为独立模式运行。在 `config.py` 中设置：

```python
MODES = {
    "classic": False,
    "secure": False,
    "tls": False,
    "web": True,
}

WEB_DOMAIN = "mtp.tincg.de5.net"
```

原有的 `PORT` 仍填写面板分配的监听端口。你的实例使用 **24887**，因此应将原有的 `PORT = 443` 改为：

```python
PORT = 24887
```

`USERS` 继续填自己的密钥。WEB 支持 **32 位十六进制**，以及 **`dd`＋32 位十六进制（共 34 位）**。例如，使用随机填充模式时，在原来的 32 位密钥前加上 `dd`，同时更新配置和客户端链接：

```python
USERS = {
    "tg": "dd000102030405060708090a0b0c0d0e0f",  # 格式示例，请换成自己的密钥
}
```

`dd` 会保留在 WEB 链接和桥接验证计算里；实际 MTProxy AES 握手使用后面的 16 字节密钥。不能只在客户端链接里加 dd、服务器配置不改。旧的 classic / secure / tls 模式仍使用原来 32 位密钥的配置方式。

附带配置保留了原文件的示例值，正式使用时请换成自己的密钥。

面板启动文件选择 **mtprotoproxy.py**，或使用原来的 `python mtprotoproxy.py` 启动方式。无需交互；启动时读取 config.py，控制台会打印各用户的 `tg://webproxy` 和 `https://t.me/webproxy` 链接。

要使用旧模式，把 `web` 改回 `False`，再按原来的方式开启 classic、secure 或 tls。WEB 与旧模式不能同时开启；配置冲突时会明确报错。WEB 配置修改后需重启进程。

## 继续沿用已经打通的 Cloudflare 配置

- 域名开启橙云。
- SSL/TLS 使用 **Full / 完全**。
- 源站规则使用 **主机名等于 `mtp.tincg.de5.net`**，回源端口 **24887**。
- 保持 WebSockets 开启，桥接页面和 API 不缓存，也不要对这个子域名插入挑战页或修改脚本。

程序在 `PORT` 上接收真正的 HTTPS，并自动生成回源用的自签证书，保存在 `.webproxy/`。默认自签证书适用于 Cloudflare **Full**，不适用于 **Full (strict)**。`.webproxy/` 中没有需要手填的配置。

实际传输是：

```text
Telegram 客户端
    ↓ HTTPS / WSS
Cloudflare 的 443
    ↓ HTTPS / WSS，回源 24887
Python WEB 模块
    ↓ 本机内部连接
你原来的 Python MTProxy 转发逻辑
    ↓
Telegram 服务器
```

只有 `PORT` 需要对外开放。本机内部连接自动分配回环端口，不需要向面板另申请公网端口。自动证书用于回源，直接绕过 Cloudflare 用浏览器访问源站会出现自签证书提示。

## 实现范围

WEB 部分实现在 `webproxy.py`，默认使用官方 WEB v1 中的 `websocket` 传输方式。支持域名＋用户密钥派生的桥接入口、HTTPS 会话建立、WebSocket 多路连接、窗口流量控制、关闭及超时清理，以及原生 WebView / 系统浏览器 MessagePort 桥接。

公网入口复用原有 PORT；用户密钥和数据统计继续由原 MTProxy 逻辑处理。没有引入额外参数文件或运行时下载。无凭据访问显示一个简单的 Welcome 页面，不提供工作目录的文件访问。

这是根据[官方 WEB 协议](https://github.com/telegramdesktop/tproxy-server/blob/master/PROTOCOL.md)新增的 Python 实现，固定使用 websocket carrier；没有移植四种 carrier 的全部服务器实现。用户无需选择 carrier。

## 验证状态

交付前完成了：

- 26 项 Python 测试：原有模式的有效默认值、官方 capability 测试向量、dd 前缀校验/链接/安全握手往返、以 dd 开头的普通 16 字节密钥、TLS 证书及 MemoryBIO 加密往返、HTTP bootstrap、WebSocket 分片/多路复用、流控、关闭清理、原 MTProxy 加密握手及数据往返等。
- JavaScript 模拟测试：原生 WebView 初始化、HELLO/WELCOME、浏览器请求设置、帧拆分、MessagePort 来源检查与失败关闭。
- 原始 Downloads 文件没有修改；输出包中的 requirements.txt 与原文件一致。

**网络传输测试使用内存字节流模拟，TLS 使用 MemoryBIO 验证；未完成真实端口、Cloudflare 和 Telegram 客户端的端到端实测。** 本地回环网络被沙箱拦截，运行网络测试的自动审批服务又返回 404（审批模型不受支持），因此没有把模拟测试说成真实连接验证。

新模式仍需在你的面板上确认 Telegram 可以连接、收发消息和加载媒体。建议保留原文件备份，以便随时回到原来的 tls 模式。
