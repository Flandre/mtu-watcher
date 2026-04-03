package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	defaultPcapBufSize  = 32 * 1024 * 1024
	defaultPcapPromisc  = true
	defaultIdleTimeout  = 60 * time.Second // 多久没看到新包就恢复 MTU
	defaultSnapLen      = 65535
	defaultReadTimeout  = pcap.BlockForever
	defaultLogTimeLayout = "2006-01-02 15:04:05.000"
)

// 下面几个结构体用于解析 MabiTrade-core/internal/constants/channels.json。
type channelInfo struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type serverInfo struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	IPPrefix string        `json:"ipPrefix"`
	Channels []channelInfo `json:"channels"`
}

type channelsConfig struct {
	Servers []serverInfo `json:"servers"`
}

// buildDefaultFilter 尝试根据 MabiTrade-core 的 channels.json 自动构建一个 BPF 过滤表达式。
// 形如：
//   tcp and (host 211.147.76.31 and port 11020 or host 61.164.61.10 and port 11020 ...)
func buildDefaultFilter() (string, error) {
	// 优先使用 mtu-watcher 目录下的 channels.json，方便独立分发。
	localPath := filepath.Join("channels.json")
	if _, err := os.Stat(localPath); err != nil {
		return "", fmt.Errorf("channels.json 不存在（期待路径：%s）: %w", localPath, err)
	}

	data, err := os.ReadFile(localPath)
	if err != nil {
		return "", fmt.Errorf("读取 %s 失败: %w", localPath, err)
	}

	var cfg channelsConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("解析 %s 失败: %w", localPath, err)
	}

	// 去重：有些频道 IP/端口会重复。
	seen := make(map[string]struct{})
	var parts []string

	for _, srv := range cfg.Servers {
		for _, ch := range srv.Channels {
			if ch.IP == "" || ch.Port == 0 {
				continue
			}
			key := fmt.Sprintf("%s:%d", ch.IP, ch.Port)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			parts = append(parts, fmt.Sprintf("(host %s and port %d)", ch.IP, ch.Port))
		}
	}

	if len(parts) == 0 {
		return "", fmt.Errorf("channels.json 中未找到任何有效的 IP/端口")
	}

	filter := fmt.Sprintf("tcp and (%s)", strings.Join(parts, " or "))
	return filter, nil
}

// autoSelectNic 尝试自动选择一个有游戏流量的网卡。
// 逻辑类似 MabiTrade-core 的 FindNic：对每个设备尝试抓包一小段时间，谁先有包就用谁。
func autoSelectNic(filter string, wait time.Duration) (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("列出网卡失败: %w", err)
	}
	if len(devs) == 0 {
		return "", fmt.Errorf("未找到任何 pcap 网卡")
	}

	log.Printf("[AUTO-NIC] 共发现 %d 个网卡，开始自动探测...", len(devs))

	type result struct {
		name string
		err  error
	}

	resultCh := make(chan result, len(devs))

	for _, d := range devs {
		dev := d
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), wait)
			defer cancel()

			handle, err := pcap.OpenLive(dev.Name, defaultSnapLen, defaultPcapPromisc, defaultReadTimeout)
			if err != nil {
				resultCh <- result{"", err}
				return
			}
			defer handle.Close()

			if filter != "" {
				_ = handle.SetBPFFilter(filter)
			}

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packetSource.NoCopy = true

			for {
				select {
				case <-ctx.Done():
					resultCh <- result{"", fmt.Errorf("timeout")}
					return
				case pkt, ok := <-packetSource.Packets():
					if !ok {
						resultCh <- result{"", fmt.Errorf("packet source closed")}
						return
					}
					if pkt == nil {
						continue
					}
					// 只要能收到一个包，就认为这块网卡有流量，可以用
					log.Printf("[AUTO-NIC] 设备 %q 检测到数据包，选用此网卡", dev.Name)
					resultCh <- result{dev.Name, nil}
					return
				}
			}
		}()
	}

	var lastErr error
	for i := 0; i < len(devs); i++ {
		r := <-resultCh
		if r.err == nil && r.name != "" {
			return r.name, nil
		}
		lastErr = r.err
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("all nic probes failed")
	}
	return "", fmt.Errorf("自动探测网卡失败: %w", lastErr)
}

// setMTU 使用 netsh 修改指定接口的 MTU，并输出详细调试信息。
func setMTU(iface string, mtu int) error {
	// 为了避免各种奇怪的转义问题，这里将完整命令交给 cmd /C。
	cmdLine := fmt.Sprintf(
		`netsh interface ipv4 set subinterface %q mtu=%d store=persistent`,
		iface,
		mtu,
	)

	log.Printf("[MTU] 执行命令: %s", cmdLine)

	cmd := exec.Command("cmd", "/C", cmdLine)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		log.Printf("[MTU] netsh 输出: %s", string(out))
	}
	if err != nil {
		log.Printf("[MTU] netsh 执行失败: %v", err)
		return err
	}

	log.Printf("[MTU] 已将接口 %q 的 MTU 设置为 %d", iface, mtu)
	return nil
}

type state int

const (
	stateIdle state = iota
	stateLowMTU
)

func (s state) String() string {
	switch s {
	case stateIdle:
		return "Idle"
	case stateLowMTU:
		return "LowMTU"
	default:
		return "Unknown"
	}
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	log.Printf("[%s] mtu-watcher 启动", time.Now().Format(defaultLogTimeLayout))

	var (
		nicName    string
		ifaceName  string
		lowMTU     int
		normalMTU  int
		bpfFilter  string
		idleSec    int
		verbosePkt bool
	)

	flag.StringVar(&nicName, "nic", "", "要抓包的网卡名（pcap 设备名，例如 \"\\Device\\NPF_{...}\"）")
	flag.StringVar(&ifaceName, "iface", "以太网", "netsh 中显示的接口名（例如 \"以太网\" 或 \"Ethernet\"）")
	flag.IntVar(&lowMTU, "low-mtu", 386, "降低后的 MTU 数值")
	flag.IntVar(&normalMTU, "normal-mtu", 1500, "恢复时的 MTU 数值")
	flag.StringVar(&bpfFilter, "filter", "", "pcap BPF 过滤表达式（留空时会尝试根据 MabiTrade-core 的 channels.json 自动生成）")
	flag.IntVar(&idleSec, "idle-timeout", 60, "在多少秒内无新“游戏包”时恢复 MTU")
	flag.BoolVar(&verbosePkt, "verbose-packet", false, "是否输出每个匹配数据包的详细信息")
	flag.Parse()

	idleTimeout := time.Duration(idleSec) * time.Second

	// 如果用户没有手动指定 filter，则尝试从 channels.json 自动构建。
	if bpfFilter == "" {
		if autoFilter, err := buildDefaultFilter(); err != nil {
			log.Printf("[FILTER] 自动构建 BPF 过滤表达式失败，将不使用过滤器: %v", err)
		} else {
			bpfFilter = autoFilter
			log.Printf("[FILTER] 已根据 channels.json 自动生成过滤器: %s", bpfFilter)
		}
	}

	if nicName == "" {
		log.Printf("[CFG] 未指定 -nic，将尝试自动探测网卡（类似 MabiTrade-core 的行为）...")
		autoNic, err := autoSelectNic(bpfFilter, 1*time.Second)
		if err != nil {
			log.Fatalf("[AUTO-NIC] 自动选择网卡失败，请手工指定 -nic: %v", err)
		}
		nicName = autoNic
		log.Printf("[AUTO-NIC] 选用网卡: %q", nicName)
	}

	log.Printf("[CFG] nic=%q iface=%q lowMTU=%d normalMTU=%d idleTimeout=%v filter=%q verbosePacket=%v",
		nicName, ifaceName, lowMTU, normalMTU, idleTimeout, bpfFilter, verbosePkt)

	// 打开网卡
	handle, err := pcap.OpenLive(nicName, defaultSnapLen, defaultPcapPromisc, defaultReadTimeout)
	if err != nil {
		log.Fatalf("[ERR] 打开网卡 %q 失败: %v", nicName, err)
	}
	defer handle.Close()

	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			log.Fatalf("[ERR] 设置 BPF 过滤表达式失败: %v", err)
		}
		log.Printf("[PCAP] 已设置过滤器: %s", bpfFilter)
	} else {
		log.Printf("[PCAP] 未设置过滤器，将抓取该网卡上的全部流量（可能较多）")
	}

	linkType := handle.LinkType()
	log.Printf("[PCAP] 链路层类型: %v (%d)", linkType, linkType)

	// 解析器：根据链路类型选合适的起始层
	ethLayer := layers.Ethernet{}
	ip4Layer := layers.IPv4{}
	tcpLayer := layers.TCP{}
	payload := gopacket.Payload{}

	var parser *gopacket.DecodingLayerParser

	switch linkType {
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeLoopback,
			&ip4Layer, &tcpLayer, &payload,
		)
	case layers.LinkTypeRaw:
		parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeIPv4,
			&ip4Layer, &tcpLayer, &payload,
		)
	default:
		parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer, &ip4Layer, &tcpLayer, &payload,
		)
	}

	packetLayers := []gopacket.LayerType(nil)

	// 状态机
	curState := stateIdle
	lastActive := time.Time{} // 上一次检测到“疑似游戏包”的时间

	// 捕获 Ctrl+C 等信号，退出前恢复 MTU
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("[SIGNAL] 收到信号 %v，准备恢复 MTU 并退出", sig)
		if err := setMTU(ifaceName, normalMTU); err != nil {
			log.Printf("[SIGNAL] 恢复 MTU 失败: %v", err)
		}
		os.Exit(0)
	}()

	log.Printf("[LOOP] 开始抓取数据包并监控 MTU 状态...")

	for pktIndex := 0; ; pktIndex++ {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			log.Printf("[PCAP] 读取数据包失败: %v", err)
			time.Sleep(time.Second)
			continue
		}

		if err := parser.DecodeLayers(data, &packetLayers); err != nil {
			if pktIndex < 10 {
				log.Printf("[PCAP] 解码失败(包 #%d): %v", pktIndex, err)
			}
			continue
		}

		now := ci.Timestamp
		hasGamePacket := false

		for _, layerType := range packetLayers {
			if layerType != layers.LayerTypeTCP {
				continue
			}
			if len(tcpLayer.Payload) == 0 {
				continue
			}

			hasGamePacket = true

			if verbosePkt {
				srcIP := ip4Layer.SrcIP.String()
				dstIP := ip4Layer.DstIP.String()
				srcPort := uint16(tcpLayer.SrcPort)
				dstPort := uint16(tcpLayer.DstPort)

				log.Printf("[PKT] %s -> %s %s:%d -> %s:%d len=%d",
					now.Format(defaultLogTimeLayout),
					linkType.String(),
					srcIP, srcPort,
					dstIP, dstPort,
					len(tcpLayer.Payload),
				)
			}

			// 一旦发现一个“疑似游戏包”，就够了
			break
		}

		if hasGamePacket {
			lastActive = now

			switch curState {
			case stateIdle:
				log.Printf("[STATE] %s -> %s，检测到游戏流量，尝试降低 MTU",
					stateIdle, stateLowMTU)
				if err := setMTU(ifaceName, lowMTU); err != nil {
					log.Printf("[ERR] 降低 MTU 失败，保持 Idle 状态: %v", err)
				} else {
					curState = stateLowMTU
				}

			case stateLowMTU:
				// 已经是低 MTU 状态，只更新 lastActive
			}
		}

		// 如果处于 LowMTU 状态，检查是否长时间没有新包
		if curState == stateLowMTU && !lastActive.IsZero() {
			if now.Sub(lastActive) >= idleTimeout {
				log.Printf("[STATE] %s -> %s，%v 内未检测到新游戏流量，恢复 MTU",
					stateLowMTU, stateIdle, idleTimeout)
				if err := setMTU(ifaceName, normalMTU); err != nil {
					log.Printf("[ERR] 恢复 MTU 失败，将继续保持低 MTU 状态: %v", err)
				} else {
					curState = stateIdle
					lastActive = time.Time{}
				}
			}
		}
	}
}

