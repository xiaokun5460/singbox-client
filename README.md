# SingBox Manager

一个基于 [sing-box](https://github.com/SagerNet/sing-box) 的代理管理工具，提供简洁的 Web 界面，支持 Clash 订阅导入、智能分流、DNS 防泄漏。

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-blue.svg)
![sing-box](https://img.shields.io/badge/sing--box-1.12%2B-green.svg)

## 功能特性

- **一键部署** - 单脚本完成安装、配置、启动
- **Web 管理界面** - 简洁美观，支持移动端
- **Clash 订阅** - 自动解析 Clash YAML 格式订阅
- **智能分流** - 国内直连、国外代理，基于 BGP IP 列表和 GeoSite 规则
- **DNS 防泄漏** - DoH 加密查询 + FakeIP + 代理 DNS 解析
- **多协议支持** - Shadowsocks、VMess、VLESS、Trojan、Hysteria2
- **自定义规则** - 支持域名、IP、GeoSite、GeoIP 规则
- **实时日志** - SSE 实时查看日志，支持分类过滤
- **连接管理** - 实时查看活跃连接，支持单独断开

## 系统要求

- **操作系统**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- **架构**: x86_64 (amd64), ARM64, ARMv7
- **权限**: 需要 root 权限 (TUN 模式)
- **依赖**: Go 1.21+ (仅编译时需要)

## 快速开始

### 一键安装

```bash
# 克隆仓库
git clone https://github.com/xiaokun/singbox-client.git
cd singbox-client

# 运行安装脚本
sudo ./scripts/install.sh install
```

安装完成后：
1. 打开浏览器访问 `http://localhost:3333`
2. 添加 Clash 订阅链接
3. 选择节点，点击"启动服务"

### 手动安装

```bash
# 1. 安装 sing-box
bash <(curl -fsSL https://sing-box.app/deb-install.sh)

# 2. 编译 singbox-client
git clone https://github.com/xiaokun/singbox-client.git
cd singbox-client
go build -o singbox-client .

# 3. 运行
sudo ./singbox-client
```

## 使用说明

### 管理命令

```bash
# 服务管理
sudo systemctl start singbox-client    # 启动管理服务
sudo systemctl stop singbox-client     # 停止管理服务
sudo systemctl restart singbox-client  # 重启管理服务
sudo systemctl status singbox-client   # 查看状态

# 查看日志
sudo journalctl -u singbox-client -f

# 脚本命令
sudo ./scripts/install.sh status       # 查看完整状态
sudo ./scripts/install.sh update       # 更新升级
sudo ./scripts/install.sh uninstall    # 卸载
```

### Web 界面

| 页面 | 功能 |
|------|------|
| 仪表盘 | 服务状态、快捷操作、代理模式切换 |
| 节点管理 | 查看节点列表、切换节点、延迟测试 |
| 订阅管理 | 添加/删除订阅、手动刷新 |
| 规则设置 | 自定义分流规则 |
| 系统设置 | DNS、TUN、缓存管理等配置 |
| 日志查看 | 实时日志，支持分类过滤 |
| 连接管理 | 查看活跃连接、流量统计 |

### 代理模式

| 模式 | 说明 |
|------|------|
| 规则模式 | 根据 BGP IP/GeoSite 规则智能分流 (推荐) |
| 全局模式 | 所有流量走代理 |
| 直连模式 | 所有流量直连 |

## 配置说明

### 目录结构

```
/var/lib/singbox-client/          # 数据目录
├── config.yaml                   # 应用配置
├── state.yaml                    # 运行状态
├── subscriptions/                # 订阅缓存
└── singbox/
    ├── config.json               # sing-box 配置 (自动生成)
    └── cache.db                  # DNS/规则缓存 (持久化)
```

### 配置文件

`/var/lib/singbox-client/config.yaml`:

```yaml
server:
  host: "127.0.0.1"
  port: 3333

singbox:
  binary_path: "/usr/local/bin/sing-box"
  config_path: "/var/lib/singbox-client/singbox/config.json"
  log_level: "info"

dns:
  domestic_servers:
    - "223.5.5.5"      # 阿里 DNS
    - "119.29.29.29"   # 腾讯 DNS
  proxy_servers:
    - "8.8.8.8"        # Google DNS
    - "1.1.1.1"        # Cloudflare DNS

proxy:
  tun_address: "172.19.0.1/30"
  tun_stack: "system"
  auto_route: true
  strict_route: true

subscription:
  auto_update: true
  update_interval: 60  # 分钟
```

## 技术架构

```
┌─────────────────────────────────────────────────┐
│              Web UI (Alpine.js + Tailwind)      │
├─────────────────────────────────────────────────┤
│              Go HTTP Server (net/http)          │
│  ┌──────────┬──────────┬──────────┬──────────┐  │
│  │ 订阅管理 │ 配置生成 │ 进程控制 │  API     │  │
│  └──────────┴──────────┴──────────┴──────────┘  │
├─────────────────────────────────────────────────┤
│              sing-box 核心                       │
│     (TUN / 代理协议 / 路由 / DNS)               │
└─────────────────────────────────────────────────┘
```

### 分流规则

默认规则 (自动生成):

1. **DNS 劫持** - 接管系统 DNS 请求
2. **域名解析** - resolve action 获取真实 IP
3. **私有网络直连** - 10.x, 192.168.x, 172.16.x
4. **中国域名直连** - geosite:cn + dnsmasq-china-list
5. **中国 IP 直连** - BGP 路由表 (比 MaxMind GeoIP 更准确)
6. **广告拦截** - geosite:category-ads-all
7. **其他流量代理** - 默认走代理

### DNS 防泄漏策略

```
┌─────────────────────────────────────────────────────────────┐
│                       DNS 查询流程                           │
├─────────────────────────────────────────────────────────────┤
│  已知中国域名 (geosite-cn + china-domains)                   │
│      → 国内 DNS (223.5.5.5) → 真实 IP → 直连                │
├─────────────────────────────────────────────────────────────┤
│  已知国外域名 (geosite-geolocation-!cn)                      │
│      → FakeIP (198.18.x.x) → 代理                           │
├─────────────────────────────────────────────────────────────┤
│  未知域名                                                    │
│      → 代理 DNS (Cloudflare DoH) → 真实 IP                  │
│      → BGP IP 列表匹配 → 中国 IP 直连，其他代理              │
└─────────────────────────────────────────────────────────────┘
```

**特点：**
- 国内域名使用国内 DNS，获取真实 IP，直连访问
- 国外域名使用 FakeIP，防止 DNS 泄漏
- 未知域名通过代理 DNS 解析，然后用 BGP IP 列表判断
- ISP 无法看到任何国外域名的 DNS 查询

### 规则集来源

| 规则集 | 来源 | 用途 |
|--------|------|------|
| chnroutes-bgp | [misakaio/chnroutes2](https://github.com/misakaio/chnroutes2) | BGP 中国 IP (更准确) |
| china-domains | [felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) | 中国域名加速列表 |
| geosite-cn | [SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite) | 中国域名规则 |
| geosite-geolocation-!cn | SagerNet/sing-geosite | 国外域名规则 |

## API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/status` | GET | 获取运行状态 |
| `/api/start` | POST | 启动代理 |
| `/api/stop` | POST | 停止代理 |
| `/api/restart` | POST | 重启代理 |
| `/api/nodes` | GET | 获取节点列表 |
| `/api/nodes/:name/select` | POST | 选择节点 |
| `/api/subscriptions` | GET/POST | 订阅管理 |
| `/api/subscriptions/refresh` | POST | 刷新订阅 |
| `/api/rules` | GET/PUT | 规则管理 |
| `/api/config` | GET/PUT | 配置管理 |
| `/api/logs` | GET | 获取日志 |
| `/api/logs/stream` | GET (SSE) | 实时日志流 |
| `/api/cache/clear` | POST | 清空 DNS 缓存 |

## 常见问题

### Q: 启动失败，提示权限不足？

sing-box 需要 root 权限创建 TUN 设备：
```bash
sudo setcap cap_net_admin,cap_net_bind_service=+ep /usr/local/bin/sing-box
```

### Q: 如何验证 DNS 没有泄漏？

访问 https://browserleaks.com/dns 或 https://ipleak.net，检查：
- DNS 服务器应该显示代理节点所在地区
- 不应该显示你的 ISP 或中国大陆的 DNS

### Q: 国内网站访问变慢？

检查是否正确分流：
```bash
# 应该返回真实 IP（非 198.18.x.x）
nslookup baidu.com
```

如果返回 FakeIP，检查 geosite 规则是否正确加载。

### Q: 如何添加自定义规则？

在 Web 界面 → 规则设置 → 添加自定义规则：
- **域名**: `example.com` → 直连/代理
- **域名后缀**: `.example.com` → 匹配所有子域名
- **GeoSite**: `google` → 使用预定义规则集
- **GeoIP**: `us` → 匹配美国 IP

### Q: 如何清空 DNS 缓存？

在 Web 界面 → 系统设置 → 缓存管理 → 清空 DNS 缓存

### Q: 如何更新 sing-box？

```bash
sudo ./scripts/install.sh update
```

## 开发

### 项目结构

```
singbox-client/
├── main.go                 # 入口
├── go.mod
├── internal/
│   ├── api/                # HTTP API
│   ├── config/             # 配置管理
│   ├── singbox/            # sing-box 配置生成与进程管理
│   ├── subscription/       # 订阅解析
│   └── rules/              # 规则管理
├── web/
│   ├── templates/          # HTML 模板
│   └── static/             # 静态资源
└── scripts/
    └── install.sh          # 安装脚本
```

### 本地开发

```bash
# 克隆
git clone https://github.com/xiaokun/singbox-client.git
cd singbox-client

# 运行
go run .

# 编译
go build -o singbox-client .
```

## 致谢

- [sing-box](https://github.com/SagerNet/sing-box) - 优秀的代理核心
- [Tailwind CSS](https://tailwindcss.com/) - CSS 框架
- [Alpine.js](https://alpinejs.dev/) - 轻量级 JS 框架
- [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) - 中国域名列表
- [chnroutes2](https://github.com/misakaio/chnroutes2) - BGP 中国 IP 列表

## 许可证

MIT License
