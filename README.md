## MTU Watcher 工具

**用途**：在不使用 DLL 注入的前提下，参考 `kanan-new` 中 `AutoSetMTU` 的思路，  
通过抓包检测到“游戏流量”时临时降低网卡 MTU，闲置一段时间后再恢复 MTU，从而尽量模拟原有的效果。

本工具是一个独立的 Go 程序，不注入到游戏进程内部，只在本机：

- 使用 `pcap` 抓取网络数据包；
- 根据过滤条件判断是否出现“疑似游戏流量”；
- 通过 `netsh interface ipv4 set subinterface ... mtu=...` 修改指定网卡的 MTU；
- 在长时间检测不到新游戏包时，将 MTU 恢复为正常值。

---

### 1. 依赖与构建

#### 1.1 安装依赖

1. 安装 Go（建议 1.20+）。
2. 安装 WinPcap / Npcap（Wireshark 安装时一般会附带）。

在 `mtu-watcher` 目录下初始化 / 下载依赖（仅第一次需要）：

```bash
cd mtu-watcher
go mod init mtu-watcher
go get github.com/google/gopacket
go get github.com/google/gopacket/pcap
```

> 说明：如果你已经有统一的 `go.mod` 管理，可以把本文件加入到现有模块中，而不是新建模块。

#### 1.2 构建可执行文件

```bash
cd mtu-watcher
go build -o mtu-watcher.exe
```

构建成功后，当前目录会生成 `mtu-watcher.exe`。

---

### 2. 使用方式

#### 2.1 自动选择网卡（不填 `-nic`）

本工具已经集成了类似 `MabiTrade-core/internal/pcaputil/FindNic` 的逻辑：

- 如果你**不指定 `-nic`**，程序会：
  - 使用 `pcap.FindAllDevs()` 列出所有可用设备；
  - 对每个设备尝试抓包一小段时间（默认约 1 秒）；
  - 谁先收到数据包（符合过滤条件的优先），就自动选用谁。
- 也就是说，在大多数情况下，你可以**直接不填 `-nic`**，让程序自动选择你正在上网/玩游戏的那块网卡。

如果自动探测失败，程序会在日志中提示，并要求你手工指定 `-nic`。

#### 2.2 手动指定网卡 + 其他参数

```bash
mtu-watcher.exe ^
  -nic "<PCAP网卡名>" ^
  -iface "以太网" ^
  -low-mtu 386 ^
  -normal-mtu 1500 ^
  -idle-timeout 60 ^
  -filter "tcp and dst host 1.2.3.4 and dst port 11000" ^
  -verbose-packet=false
```

**参数说明：**

- `-nic`（可选）  
  - pcap 设备名，用于抓包。示例：`"\\Device\\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"`  
  - **留空时会自动探测**：程序会尝试对所有网卡短暂抓包，自动选取实际有流量的一块。  
  - 如果自动探测失败，可以通过 Wireshark、Npcap 自带工具或 `MabiTrade-core` 现有输出查到设备名后手动填写。

- `-iface`  
  - `netsh` 用到的接口显示名，例如 `"以太网"`、`"Ethernet"`。  
  - 可以在命令行运行 `netsh interface ipv4 show subinterfaces` 查看当前名称。

- `-low-mtu`  
  - 检测到游戏流量时要设置的“较小 MTU”，例如 386。

- `-normal-mtu`  
  - 恢复时的正常 MTU，一般是 1500 或你当前网卡的默认值。

- `-idle-timeout`  
  - 从**上一次检测到游戏包**开始，连续多少秒内没有新包，就自动恢复 MTU。  
  - 默认 60 秒，可以按习惯调大/调小。

- `-filter`  
  - BPF 过滤表达式，用于减少无关流量。  
  - **默认留空即可**：程序会尝试读取当前目录下的 `channels.json`，  
    把其中所有服务器频道的 `ip` / `port` 组合成一个过滤条件，例如：  
    `tcp and (host 211.147.76.31 and port 11020 or host 61.164.61.10 and port 11020 ...)`  
  - 如果你想只监听某一部分服务器/频道，可以自行写更精确的表达式覆盖默认值。

- `-verbose-packet`  
  - 是否打印每一个匹配的数据包的详细信息（时间、IP、端口、负载长度）。  
  - 调试抓包/过滤规则时可设为 `true`，正常使用可以关掉以减少日志。

#### 2.2 运行示例

假设：

- pcap 网卡名：`\\Device\\NPF_{ABCDEF12-3456-7890-ABCD-EF1234567890}`
- netsh 接口名：`以太网`
- 游戏服务器 IP：`203.0.113.10`
- 端口：`11000`

可以这样运行（在 PowerShell 中）：

```powershell
cd g:\github\auto-mabinogi-mtu\mtu-watcher
.\mtu-watcher.exe `
  -nic "\\Device\\NPF_{ABCDEF12-3456-7890-ABCD-EF1234567890}" `
  -iface "以太网" `
  -low-mtu 386 `
  -normal-mtu 1500 `
  -idle-timeout 60 `
  -filter "tcp and dst host 203.0.113.10 and dst port 11000" `
  -verbose-packet=false
```

程序启动后：

- 当检测到第一条符合过滤条件、且带有 TCP payload 的数据包时：
  - 日志会输出 `[STATE] Idle -> LowMTU ...`；
  - 调用 `netsh` 将接口 MTU 设置为 `-low-mtu`。
- 只要在 `idle-timeout` 时间内持续有游戏流量，都会维持在 LowMTU 状态，只更新最近活跃时间。
- 一旦超过 `idle-timeout` 时间没有新的游戏流量：
  - 日志会输出 `[STATE] LowMTU -> Idle ...`；
  - 调用 `netsh` 将 MTU 恢复为 `-normal-mtu`。
- 按 `Ctrl + C` 退出时：
  - 程序会捕获信号并尝试先恢复 MTU，再退出。

---

### 3. 实现细节说明

#### 3.1 和 `kanan AutoSetMTU` 的关系

- `kanan-new` 中的 `AutoSetMTU` 是通过 DLL 注入 + 函数 Hook：
  - 在“创建连接函数”被调用前后短暂修改 MTU；
  - 借此影响 TCP 握手时协商的 MSS，从而长期保持“小 MSS”。
- 本工具不再进入游戏进程，而是：
  - 在**外部进程**中监控网卡上的“游戏流量”（通过 pcap）；
  - 检测到有流量时降低 MTU，闲置一段时间后再恢复；
  - 效果上尽量接近“在连接/换线阶段保持较小 MTU”的行为。

#### 3.2 状态机设计

内部有两个简单状态：

- `Idle`：未检测到最近的游戏流量，MTU 应该是正常值；
- `LowMTU`：最近一段时间检测到游戏流量，MTU 维持在较小值。

状态转移：

- `Idle -> LowMTU`：解析到一条符合条件的 TCP 包（且有 Payload）时，调用 `setMTU(lowMTU)`；
- `LowMTU -> Idle`：当前时间与 `lastActive` 的差值 ≥ `idle-timeout`，调用 `setMTU(normalMTU)`。

所有关键操作（状态切换、netsh 调用、错误）都会通过 `log.Printf` 输出到标准输出，方便调试。

#### 3.3 抓包与过滤

- 使用 `pcap.OpenLive` 打开指定网卡，设置：
  - 抓包缓冲区大小（snaplen / bufsize）；
  - 混杂模式；
  - 读取超时。
- 若指定了 `-filter`，则调用 `handle.SetBPFFilter` 设置 BPF 表达式，减少无关数据。
- 使用 `gopacket.DecodingLayerParser` 根据不同 LinkType 选择合适的解析起点：
  - 以太网：`Ethernet -> IPv4 -> TCP -> Payload`
  - 回环 / Raw：直接从 `Loopback` 或 `IPv4` 层开始。
- “疑似游戏包”的判定当前非常宽松：
  - 只要是 TCP 且 Payload 长度 > 0；
  - 实际使用中建议依靠 `-filter` 进行更精确的过滤（按 IP / 端口）。

---

### 4. 调试建议

1. **先不改 MTU，只看抓包是否正确**
   - 暂时修改代码中 `setMTU` 的调用处，改为只打印命令而不真正执行；
   - 配合 `-verbose-packet=true`，确认过滤条件确实只在游戏登录/换线时触发。

2. **再打开 MTU 修改，观察游戏体验**
   - 注意在测试环境中进行，确认不会影响其他重要网络连接；
   - 可以尝试不同的 `-low-mtu` 数值和 `-idle-timeout`，找到合适的平衡。

3. **必要时打印更详细日志**
   - 可以在有需要的地方增加更多 `log.Printf`，例如记录最近一次状态切换的 stack/context。

---

### 5. 潜在改进方向

- 和 `MabiTrade-core` 现有的 `GameServerPacketReader` 进行集成：
  - 已经有成熟的网卡打开、日志、解析逻辑；
  - 可以在其基础上直接增加“连接/换线事件回调”，再在回调里调用 `setMTU`。
- 更精确地区分“登录”和“心跳”：
  - 通过具体 opcode 或消息格式识别真正的“握手/切线”行为；
  - 仅在这些关键事件前后调整 MTU，进一步接近原版 Hook 的行为。

当前版本的 `mtu-watcher` 已经可以作为一个可用的基础实现，你可以根据实际情况继续在此基础上迭代。  

