# MASQUE Speed · Go WebUI

原生 Go MASQUE 测速器。Windows x64 单文件程序，启动后打开浏览器；不依赖 Python、curl、usque 可执行文件、管理员权限或系统 TUN。WebUI 仅绑定 `127.0.0.1`，测试流量经过用户填写凭据建立的真实 WARP CONNECT-IP 隧道。

## Windows 使用

解压 `masque-speed-windows-amd64.zip`，双击 `masque-speed-windows-amd64.exe`。程序会显示并打开带临时会话令牌的本机地址；保持程序窗口运行，关闭窗口或 Ctrl+C 退出。浏览器标签页关闭不等于退出程序。

1. 导入 FOFA JSON/CSV/TXT 扫描结果，或粘贴结果文本。
2. 填写已注册 WARP MASQUE 设备私钥、服务端公钥和设备内网地址；也可以导入已有 usque `config.json`。
3. 选择 TCP、UDP 或两者。按国家、省份/地区或城市选择要测的地区。
4. 设置最大合格延迟（ms）、最小下载速度（Mbps）、下载字节数、采样数和超时。
5. 选择总合格数量，或每个所选地区分别达到相同数量，然后开始。手动停止会取消当前连接/下载。
6. 达到要求自动停止；候选耗尽但未满足配额时明确显示耗尽，不报成达标。可导出合格结果 CSV。

命令行选项：

```text
masque-speed-windows-amd64.exe -port 8080
masque-speed-windows-amd64.exe -no-browser
```

默认随机选择可用的本机端口。URL 中令牌仅用于当前程序会话；不要分享该地址。再次打开页面时使用终端显示的完整地址。

## TCP / UDP、指标与数量

- **TCP**：外层 TCP + TLS + HTTP/2 CONNECT-IP；**UDP**：外层 QUIC + HTTP/3 CONNECT-IP。两种方式都在隧道内通过 HTTPS 下载，不是向第三方开放端口发送 UDP 洪泛，也不是 UDP iperf 吞吐测试。
- 同时选择两者时，先测 TCP；若已满足延迟和速度要求，不再测试同一端点的 UDP。否则再测 UDP。任意一种合格，该端点就算一个合格项。
- 每次先建立隧道，再访问 `https://www.cloudflare.com/cdn-cgi/trace`；要求 HTTP 200、`warp=on` 或 `warp=plus` 及有效出口 IP。
- **延迟是隧道建立后，多次 HTTPS trace 请求的首字节时间中位数（TTFB）**，不是 ICMP RTT、QUIC RTT 或初始隧道握手耗时。包含隧道内 DNS、TCP/TLS 和服务响应成本。采样必须全部成功；超过延迟阈值就不执行下载。
- 下载地址为 `https://speed.cloudflare.com/__down?bytes=N`。接收完整指定字节数、HTTP 200 才产生有效速度。速度为下载字节 × 8 ÷ 整次下载请求秒数 ÷ 1,000,000，单位 Mbps。默认 10,000,000 字节，串行测速，避免任务互相抢带宽。小文件速度受建连时间影响较大。
- **延迟 ≤ 最大值，且速度 ≥ 最小值**才合格。最大延迟必须大于零；最小速度可为零。超时分别约束建立隧道、每次 trace 和下载，不是整个端点的总时限。
- 按规范化的 **IP + 端口**全局去重，TCP/UDP 不重复计数。同一 IP 的不同端口分别计数。
- 总配额：所有所选地区共累计 N 个合格端点即停。每地区配额：每个所选地区各累计 N 个，已满地区跳过，继续测未满地区。
- 地区元数据来自导入文件；没有地区信息归为“未知”，不联网补全地理位置。同名城市/省份按该字段值归为同一组。

## 公私钥与保存

所需私钥是**已在 WARP 注册的 ECDSA P-256 设备私钥**，公钥是**服务端用于固定校验的 ECDSA 公钥**，不是随意生成的一对，也不是 WireGuard 的 32 字节密钥。

界面支持手动填写或从已有 usque 配置导入 `private_key`、`endpoint_pub_key`、`ipv4`、`ipv6`。至少需要一个有效设备内网地址。程序不自动注册或上传凭据到除所选 MASQUE 端点外的服务；导入配置中的 API access token 不参与测速。

默认只在内存中使用凭据。用户主动点击保存并确认后，以明文凭据文件写入当前用户配置目录：

- Windows：`%AppData%\masque-speed\credentials.json`
- Linux：`$XDG_CONFIG_HOME/masque-speed/credentials.json`，通常 `~/.config/masque-speed/credentials.json`

可在界面加载或删除保存的凭据。文件不是加密保险箱，具有当前用户权限的软件可以读取；不要放到共享目录。Unix 目录/文件权限限制为 0700/0600；Windows 依赖当前用户配置目录的系统访问控制。启动不会自动加载项目目录的旧 `config.json`。

MASQUE 服务端公钥固定校验始终启用，隧道内 HTTPS 使用系统信任校验；不存在跳过校验或失败直连回退。外层连接固定到所选 IP/端口，不使用 HTTP_PROXY/HTTPS_PROXY 改道。

## 支持的 FOFA 导入

- API JSON：`{"assets":[{"ip":"1.2.3.4","port":443,"country":"中国","region":"北京市","city":"Beijing"}]}`。
- 资产对象数组：`[{"ip":"1.2.3.4","port":443,...}]`。
- 带字段表的 FOFA JSON：`{"fields":["ip","port","country","region","city"],"results":[["1.2.3.4",443,"中国","北京市","Beijing"]]}`。
- 有表头 CSV：`ip,port,country,region,city`；支持 `host` URL 回填地址和端口，以及“端口、国家、省份/地区、城市”等中文表头。UTF-8/BOM 和 GB18030 CSV 均可。
- TXT：每行 `IP:端口`，IPv6 写作 `[2001:db8::1]:443`。TXT 没有地区信息。

仅接受字面 IP 和 1–65535 端口。非法记录跳过并给出数量提示；重复地址合并，缺失地区值用后续记录补齐，冲突以第一个非空值为准。单次导入最大 32 MiB。程序不调用 FOFA API、不需要 FOFA API Key。

`examples/fofa-example.csv` 包含之前检索到的三个大陆候选地址。**证书关联不保证支持 MASQUE**；它们不是已验证可用列表。

## 从源码构建

要求 Go 1.26.3 或更高版本，依赖固定在 `go.mod` / `go.sum`。WebUI 静态文件通过 `go:embed` 编入程序，无前端构建工具。

```sh
go mod download
go test -race ./...
# Windows x64，Linux/macOS 交叉编译
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/masque-speed-windows-amd64.exe .
# 本机运行
go run .
```

Windows PowerShell 可使用 `./build-windows.ps1` 构建并打包。依赖许可见 `THIRD_PARTY_NOTICES.md` 与发布包中的许可文件。

## 本地安全边界

所有 API 都要求每次启动随机生成的会话令牌，拒绝非本机 Host 和跨站请求。凭据只在受保护的凭据接口返回，不出现在状态、CSV 或日志中。关闭程序会取消测速；导出只包含合格端点的可用传输与性能。

## 已执行的验证

- `go test -race ./...`：导入解析、配额边界、并发状态快照、凭据与本地 API 安全、测量判定、TCP/QUIC 取消及超时测试通过。
- Linux 原生构建在真实 Chromium 页面完成 FOFA CSV 导入、IPv6 文本粘贴、配置导入、总配额自动停止、地区筛选及每地区配额、合格 CSV 下载、凭据保存/读取/删除和手动取消。
- 参考端点 `162.159.198.2:443` 的真实 TCP/HTTP2 隧道通过 WARP trace 验证，完整下载 10,000,000 字节；该次浏览器实测为 106.82 Mbps，TTFB 中位数 25.36 ms。总配额为 1 时，仅测试首个合格候选便停止，第二候选未启动。此为当前机器当前网络结果，不是性能保证。
- 极低延迟阈值触发“延迟未达标”，下载未启动。UDP/QUIC 对 `162.159.198.1:443` 的实测在 10 秒连接期限内超时；停止按钮能取消未完成的 UDP 测试。当前环境未取得真实公网 UDP 成功吞吐结果。
- Windows x64 已交叉编译，并检查为 `PE32+ x86-64` 可执行文件；没有 Windows 运行时，尚未做 Windows 实机双击、系统证书和浏览器启动验证。IPv6 公网隧道未实测。

旧 Python 测速入口及 usque 安装脚本已由 Go 版替代并删除；原有设备 `config.json` 不作修改，可在 WebUI 中自行导入。
