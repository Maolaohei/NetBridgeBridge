# NetBridge Bridge

NetBridge Bridge 是 v2rayN NetBridge v2 架构中的独立 Go 程序，负责将 ProxyBridgeCore（C）捕获的流量通过 NetBridge 协议转发到 Bray Core（Xray/sing-box）。

## 架构

```
进程 (chrome.exe / game.exe / ...)
    │ 原始 TCP / UDP
    ▼
WinDivert.sys (内核驱动)
    │ 捕获，用户态回调
    ▼
ProxyBridgeCore.dll (C)
    │ 解析原始目标，PID→进程名
    │ TCP → NetBridge Header → 127.0.0.1:35000
    │ UDP → NetBridge Header → 127.0.0.1:35001
    ▼
NetBridge Bridge (本程序)
    │ 解析 Header，验证 Token
    │ SOCKS5 CONNECT → Core
    ▼
Bray Core (127.0.0.1:10808)
    │ sniffing + 路由
    ▼
远端服务器
```

## 前置条件

- Windows 10/11 x64
- Go 1.23+
- WinDivert 2.2.2-A SDK（编译 ProxyBridgeCore.dll 用）
- Visual Studio 2019+ 或 MinGW-w64（编译 C 侧用）

## 编译

### Go Bridge

```bash
cd NetBridgeBridge
go build -o netbridge-bridge.exe ./cmd/bridge
```

### ProxyBridgeCore.dll（C 侧）

```bash
cd ProxyBridge/Windows
# 修改 WinDivert 路径（如果不在 C:\WinDivert-2.2.2-A）
.\compile.ps1
```

编译产物在 `ProxyBridge/Windows/output/` 目录。

## 配置

### 启动参数

```
netbridge-bridge.exe [选项]

选项：
  -tcp-listen string    TCP 监听地址 (默认 "127.0.0.1:35000")
  -udp-listen string    UDP 监听地址 (默认 "127.0.0.1:35001")
  -core-socks string    Core SOCKS5 地址 (默认 "127.0.0.1:10808")
```

### 端口说明

| 端口 | 协议 | 方向 | 用途 |
|------|------|------|------|
| 35000 | TCP | ProxyBridgeCore → Bridge | NetBridge TCP Header + 原始数据流 |
| 35001 | UDP | ProxyBridgeCore → Bridge | NetBridge UDP Header + Payload |
| 10808 | TCP/UDP | Bridge → Core | SOCKS5 代理（Core mixed inbound）|

### Token 机制

Bridge 启动时通过 Windows Named Shared Memory `Local\BrayNBToken` 读取 32-bit 鉴权 Token。该 Token 由 v2rayN（通过 Core）生成，ProxyBridgeCore 在每个 NetBridge Header 中携带此 Token，Bridge 验证后才转发流量。

## 运行

### 1. 启动 Bray Core（v2rayN 自动管理）

### 2. 启动 NetBridge Bridge

```bash
netbridge-bridge.exe -core-socks 127.0.0.1:10808
```

### 3. 在 v2rayN 中启用 NetBridge

设置 → NetBridge → 启用 → 添加进程规则

### 4. 验证

```bash
# 检查 Bridge 日志
# 应看到：
# [NetBridge] Token loaded: 0xXXXXXXXX
# [NetBridge] TCP listening on 127.0.0.1:35000
# [NetBridge] UDP listening on 127.0.0.1:35001

# 测试 TCP 代理
curl.exe https://example.com

# 测试 DNS
nslookup google.com
```

## 故障排查

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| `Cannot read token after 10s` | Core 未启动或 Token Shared Memory 不存在 | 先启动 Core，再启动 Bridge |
| `invalid magic` | 旧版 ProxyBridgeCore 连接 | 重新编译 ProxyBridgeCore.dll（NB_USE_NETBRIDGE=1）|
| `invalid token` | Token 不匹配 | 重启 v2rayN 让 Core 重新生成 Token |
| TCP 连接超时 | Core mixed inbound 未启动 | 检查 Core 是否运行在 10808 端口 |
| UDP 无响应 | Bridge 未启动或 Core UDP 未配置 | 确认 Bridge 启动日志和 Core 配置 |

## 文件结构

```
NetBridgeBridge/
├── go.mod                          # Go 模块定义
├── README.md                       # 本文档
├── cmd/bridge/main.go              # 入口
└── internal/
    ├── protocol/
    │   ├── tcp.go                  # TCP Header 解析
    │   └── udp.go                  # UDP Header 解析
    ├── security/
    │   └── token.go                # Token 读取（Named Shared Memory）
    ├── tcpproxy/
    │   └── proxy.go                # TCP 代理 + SOCKS5 客户端 + 连接池
    └── udpproxy/
        └── proxy.go                # UDP 代理 + Session 管理
```
