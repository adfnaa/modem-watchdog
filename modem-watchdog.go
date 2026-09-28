//go:build linux

// 本程序依赖 Linux 专有接口：ICMP DGRAM socket（非 root ping）、
// setgroups/setgid/setuid 降权、syscall.Exec 原地重启，因此显式限定 Linux，
// 避免在其它平台被误编译（在 Windows/macOS 上会直接报"build constraints exclude all Go files"）。

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata" // 内嵌时区数据库，容器内无需安装 tzdata

	"golang.org/x/sys/unix"
)

// ==================== 配置 ====================

type Config struct {
	DeviceIP          string
	DeviceToken       string
	SIID              int
	PIID              int
	MiPort            int
	PingIP1           string
	PingIP2           string
	PingInterval      time.Duration
	PingTimeout       time.Duration
	OfflineThreshold  time.Duration
	RebootCooldown    time.Duration
	RebootOffTime     time.Duration
	MiioRetryInterval time.Duration

	// 稳定在线期：网络恢复后必须"连续在线这么久"才清零重启计数与熔断。
	// 若一恢复就清零，老化光猫（重启后能撑几分钟又断）永远不会熔断，
	// 会长期每 (阈值+冷却) 就真断电一次，正是熔断机制要防的场景。
	OnlineStable time.Duration

	// 熔断：连续这么多次"触发重启动作"（无论动作是否真正完成）后停止自动动作，
	// 只告警等人工介入。无此限制时，一旦 Ping 目标被运营商屏蔽或插板不可用，
	// 程序会每 (阈值+冷却) 反复断电光猫一次。范围 1~10，见 validateConfig。
	MaxRebootAttempts int

	// 远程管理（Web）
	WebPort         int    // HTTP 端口
	WebListen       string // 监听地址，空 = 所有接口（容器内需为 0.0.0.0）
	WebPasswordHash string // sha256 十六进制；仅当 WebAuthDisabled 为假时参与鉴权
	WebAuthDisabled bool   // 用户主动"关闭鉴权"：持久化，重启后不会再自动生成随机密码
	ConfigFile      string // 运行时配置持久化路径，默认 /data/config.json（不会为空，见 loadConfig）

	// 容器部署辅助：entrypoint 会把该路径的二进制复制到 /tmp 再执行。
	// restart_self 时若发现源二进制已更新（体积不同），则改为退出进程，
	// 交由容器的 restart 策略重新执行 entrypoint 以复制新版二进制。
	SourceBinary string

	webPasswordFromEnv bool // 内部标记：密码由环境变量显式指定时，不被配置文件覆盖

	// 日志环形缓冲字节数（仅内存，不落盘）
	LogBufferSize int

	PUID int
	PGID int
	TZ   string
}

// persistedConfig 是 Web 页保存到磁盘的运行时配置（全量写入）。
// 带 omitempty 的字段在零值时被省略，加载侧据此判断"未设置"并沿用环境变量值。
// 注意 siid/piid/mi_port/max_reboot_attempts/web_port 的合法区间都从 1 开始
// （见 validateConfig），因此 0 只可能表示"未设置"，不会与合法配置混淆——
// 这也是把 siid/piid 的范围从 0~9999 收紧为 1~9999 的原因。
// 加载顺序：默认值 → 环境变量 → 本文件（文件优先）；删除本文件即"恢复出厂"。
type persistedConfig struct {
	DeviceIP          string `json:"device_ip,omitempty"`
	DeviceToken       string `json:"device_token,omitempty"`
	SIID              int    `json:"siid,omitempty"`
	PIID              int    `json:"piid,omitempty"`
	MiPort            int    `json:"mi_port,omitempty"`
	PingIP1           string `json:"ping_ip1,omitempty"`
	PingIP2           string `json:"ping_ip2,omitempty"`
	PingInterval      string `json:"ping_interval,omitempty"`
	PingTimeout       string `json:"ping_timeout,omitempty"`
	OfflineThreshold  string `json:"offline_threshold,omitempty"`
	RebootCooldown    string `json:"reboot_cooldown,omitempty"`
	RebootOffTime     string `json:"reboot_off_time,omitempty"`
	MiioRetryInterval string `json:"miio_retry_interval,omitempty"`
	MaxRebootAttempts int    `json:"max_reboot_attempts,omitempty"`
	WebPort           int    `json:"web_port,omitempty"`
	WebListen         string `json:"web_listen,omitempty"`
	WebPasswordHash   string `json:"web_password_hash,omitempty"`
	WebAuthDisabled   bool   `json:"web_auth_disabled,omitempty"`
}

func getEnvStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("环境变量 %s 无效: %v", key, err)
	}
	return i, nil
}

// 支持 "15s"、"10m" 或纯秒数（"600"）
func getEnvDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d, nil
	}
	if i, err := strconv.Atoi(v); err == nil {
		return time.Duration(i) * time.Second, nil
	}
	return 0, fmt.Errorf("环境变量 %s 无效（例: 15s / 10m / 600）", key)
}

func loadConfig() (*Config, error) {
	cfg := &Config{}

	cfg.DeviceIP = os.Getenv("DEVICE_IP")
	if cfg.DeviceIP == "" {
		return nil, errors.New("必须设置环境变量 DEVICE_IP")
	}
	// 必须是 IPv4：NewMiiO 固定用 udp4 拨号，IPv6 地址会让连接永远建不起来，
	// 而"建不起来"又会让主循环每轮重试重建，功能静默失效。
	if ip := net.ParseIP(cfg.DeviceIP); ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("DEVICE_IP 必须是合法 IPv4 地址: %s", cfg.DeviceIP)
	}

	cfg.DeviceToken = os.Getenv("DEVICE_TOKEN")
	if cfg.DeviceToken == "" {
		return nil, errors.New("必须设置环境变量 DEVICE_TOKEN")
	}
	if tb, err := hex.DecodeString(cfg.DeviceToken); err != nil || len(tb) != 16 {
		return nil, errors.New("DEVICE_TOKEN 必须是 32 个十六进制字符")
	}

	var err error
	if cfg.SIID, err = getEnvInt("SIID", 2); err != nil {
		return nil, err
	}
	if cfg.PIID, err = getEnvInt("PIID", 1); err != nil {
		return nil, err
	}
	// 与固件版一致取 1~9999：0 不是合法属性号，而且会让
	// "omitempty = 未设置"的持久化判断失真（见 persistedConfig 注释）。
	if cfg.SIID < 1 || cfg.SIID > 9999 {
		return nil, fmt.Errorf("SIID 必须在 1-9999 之间: %d", cfg.SIID)
	}
	if cfg.PIID < 1 || cfg.PIID > 9999 {
		return nil, fmt.Errorf("PIID 必须在 1-9999 之间: %d", cfg.PIID)
	}
	if cfg.MiPort, err = getEnvInt("MI_PORT", 54321); err != nil {
		return nil, err
	}
	if cfg.MiPort < 1 || cfg.MiPort > 65535 {
		return nil, fmt.Errorf("MI_PORT 必须在 1-65535 之间: %d", cfg.MiPort)
	}

	cfg.PingIP1 = getEnvStr("PING_IP1", "223.5.5.5")
	cfg.PingIP2 = getEnvStr("PING_IP2", "8.8.8.8")
	for _, t := range []struct{ name, ip string }{
		{"PING_IP1", cfg.PingIP1},
		{"PING_IP2", cfg.PingIP2},
	} {
		if err := validatePingTarget(t.name, t.ip, cfg.DeviceIP); err != nil {
			return nil, err
		}
	}

	if cfg.PingInterval, err = getEnvDuration("PING_INTERVAL", 15*time.Second); err != nil {
		return nil, err
	}
	// 默认 1s，与固件版 Ping.ping(ip, 1) 的行为对齐
	if cfg.PingTimeout, err = getEnvDuration("PING_TIMEOUT", time.Second); err != nil {
		return nil, err
	}
	if cfg.OfflineThreshold, err = getEnvDuration("OFFLINE_THRESHOLD", 10*time.Minute); err != nil {
		return nil, err
	}
	if cfg.RebootCooldown, err = getEnvDuration("REBOOT_COOLDOWN", 2*time.Minute); err != nil {
		return nil, err
	}
	if cfg.RebootOffTime, err = getEnvDuration("REBOOT_OFF_TIME", 10*time.Second); err != nil {
		return nil, err
	}
	if cfg.MiioRetryInterval, err = getEnvDuration("MIIO_RETRY_INTERVAL", time.Minute); err != nil {
		return nil, err
	}
	// 稳定在线期：故意不放进 Web 配置页（概念偏底层），只能用环境变量调整
	if cfg.OnlineStable, err = getEnvDuration("ONLINE_STABLE", 5*time.Minute); err != nil {
		return nil, err
	}

	// 熔断阈值（与固件版一致取 1~10，见 validateConfig）
	if cfg.MaxRebootAttempts, err = getEnvInt("MAX_REBOOT_ATTEMPTS", 5); err != nil {
		return nil, err
	}

	// 远程管理（Web）
	if cfg.WebPort, err = getEnvInt("WEB_PORT", 8848); err != nil {
		return nil, err
	}
	cfg.WebListen = getEnvStr("WEB_LISTEN", "") // 空 = 所有接口；可用 127.0.0.1 限制本机

	// CONFIG_FILE 有三种取值：
	//   未设置              → 默认 /data/config.json（配合挂载数据卷做持久化）
	//   显式留空（CONFIG_FILE=）→ 关闭持久化，纯内存运行，不写任何文件
	//   指定路径            → 写到该路径
	// 注意不能用 getEnvStr：它会把"显式留空"当成"未设置"而回落到默认值。
	// 另外即便这里给出了路径，启动时还会实测一次可写性（ensureConfigWritable），
	// 不可写就自动降级为纯内存模式 —— 所以"不挂载数据卷"也是受支持的用法。
	if v, ok := os.LookupEnv("CONFIG_FILE"); ok {
		cfg.ConfigFile = strings.TrimSpace(v)
	} else {
		cfg.ConfigFile = "/data/config.json"
	}
	if pw := os.Getenv("WEB_PASSWORD"); pw != "" {
		cfg.WebPasswordHash = hashPassword(pw)
		cfg.webPasswordFromEnv = true
	}

	// 日志环形缓冲：默认 8 MiB（只占内存、不落盘，进程重启即清空）
	if cfg.LogBufferSize, err = getEnvInt("LOG_BUFFER_SIZE", 8<<20); err != nil {
		return nil, err
	}

	// 原地重启（restart_self）时用于判断容器里的副本是否已被更换
	cfg.SourceBinary = getEnvStr("SOURCE_BINARY", "/src/modem-watchdog")

	// PUID/PGID：两者都为 0 表示不降权（保持当前身份）
	if cfg.PUID, err = getEnvInt("PUID", 0); err != nil {
		return nil, err
	}
	if cfg.PGID, err = getEnvInt("PGID", 0); err != nil {
		return nil, err
	}
	if cfg.PUID < 0 || cfg.PGID < 0 {
		return nil, errors.New("PUID/PGID 不能为负数")
	}
	cfg.TZ = getEnvStr("TZ", "")

	// 环境变量加载也要过一遍统一校验（范围、IP 规则等）
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	// 文件中的运行时配置（Web 页保存的）优先于环境变量。
	// 该函数不返回错误：坏文件只降级为警告，保证进程一定能启动（否则容器会无限重启）。
	loadPersistedConfig(cfg)

	return cfg, nil
}

// ensureConfigWritable 在启动时探测"配置能不能落盘"，并据此决定运行模式。
// 这是"不想挂载数据卷 / 只读根文件系统"的一等公民用法：探测失败就把 ConfigFile 置空，
// 程序自动进入**纯内存模式** —— 之后所有持久化路径都因为 ConfigFile == "" 而跳过，
// 既不会反复报错，也不会每轮重试写盘。
// 旧版只是一直打"持久化失败"的警告，看起来像是程序坏了，实际只是没挂卷。
func ensureConfigWritable(cfg *Config) {
	if cfg.ConfigFile == "" {
		log.Println("配置持久化：已关闭（CONFIG_FILE 为空）—— 本次运行不写任何文件")
		log.Println("  Web 上的修改只在内存中生效，进程重启后回到环境变量配置")
		return
	}
	if dir := filepath.Dir(cfg.ConfigFile); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			disablePersistence(cfg, fmt.Sprintf("无法使用目录 %s: %v", dir, err))
			return
		}
	}
	// 真正试写一次：能创建就说明目录可写（也覆盖了"目录存在但只读"的情况）
	probe := cfg.ConfigFile + ".probe"
	f, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		disablePersistence(cfg, fmt.Sprintf("%s 不可写: %v", cfg.ConfigFile, err))
		return
	}
	_ = f.Close()
	_ = os.Remove(probe)
	log.Printf("配置持久化：已启用（%s）", cfg.ConfigFile)
}

// disablePersistence 降级为纯内存模式：把 ConfigFile 置空，后续持久化逻辑自动全部跳过。
func disablePersistence(cfg *Config, reason string) {
	log.Printf("配置持久化：已关闭 —— %s", reason)
	log.Println("  Web 上的修改只在内存中生效，进程重启后回到环境变量配置")
	log.Println("  （这是预期行为，不是故障：不挂载数据卷即可实现\"不落盘\"运行；")
	log.Println("    若想显式关闭持久化，把环境变量设为 CONFIG_FILE= 即可）")
	log.Println("  提示：纯内存模式下访问密码每次启动都会重新生成，建议设置 WEB_PASSWORD 固定下来")
	cfg.ConfigFile = ""
}

// ==================== 运行时配置：持久化 / 校验 ====================
// Web 页保存的配置写入 CONFIG_FILE（默认 /data/config.json，建议挂载卷持久化）。
// 环境变量仍是"初始值/兜底值"：删除该文件即回到环境变量配置（对应 Web 上的"恢复出厂设置"）。

// hashPassword 用无盐 SHA-256，格式与固件版完全一致（64 位十六进制）。
// 不加盐是有意为之：配置文件里同时存着明文 DEVICE_TOKEN，拿到文件的人
// 根本不需要破解口令；两版保持同一格式便于互相对照排查。
func hashPassword(pw string) string {
	sum := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(sum[:])
}

// randomPassword 生成随机初始口令。
// crypto/rand 失败时不再退化成"可预测口令"（那等于没有密码），而是把错误交给调用方终止启动。
func randomPassword(n int) (string, error) {
	// 去掉 0/O/1/l/I 等易混淆字符，方便用户从日志里抄写
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	// 拒绝采样消除取模偏差：256 % 56 != 0，直接 % 会让前半段字符概率偏高
	limit := byte(256 - (256 % len(alphabet)))
	out := make([]byte, 0, n)
	buf := make([]byte, 1)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("读取随机数失败: %w", err)
		}
		if buf[0] >= limit {
			continue
		}
		out = append(out, alphabet[int(buf[0])%len(alphabet)])
	}
	return string(out), nil
}

const (
	maxSegmentValue = 1000000   // 时长单段数值上限（与固件版一致）
	maxTotalSeconds = 100000000 // 时长总秒数上限（与固件版一致）
)

// parseDuration 解析时长字符串，语义与固件版 parseDurationSeconds 完全一致：
//   - 纯数字 = 秒（"600"）
//   - "整数+单位"可串联，单位只认 s / m / h（"15s"、"10m"、"1h"、"1m30s"）
//   - 刻意不支持小数（"1.5h"）与毫秒（"500ms"）：本项目所有时长下限都是 5 秒，
//     两版行为一致比"多支持几种写法"更重要（旧版直接用 time.ParseDuration，与固件版不一致）。
//   - 数值上限也与固件版相同：单段 ≤ 1e6、总和 ≤ 1e8 秒，避免溢出后误判为合法。
func parseDuration(s string) (time.Duration, error) {
	orig := s
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("时长不能为空（例: 15s / 10m / 600）")
	}

	// 纯数字 = 秒
	allDigits := true
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		sec, err := strconv.ParseUint(s, 10, 32)
		if err != nil || sec > maxTotalSeconds {
			return 0, fmt.Errorf("无效时长 %q：数值过大", orig)
		}
		return time.Duration(sec) * time.Second, nil
	}

	var total uint64
	i := 0
	for i < len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("无效时长 %q（例: 15s / 10m / 600；不支持小数与毫秒）", orig)
		}
		var val uint64
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			val = val*10 + uint64(s[i]-'0')
			if val > maxSegmentValue {
				return 0, fmt.Errorf("无效时长 %q：单段数值过大", orig)
			}
			i++
		}
		if i >= len(s) {
			return 0, fmt.Errorf("无效时长 %q：数字后面缺少单位 s/m/h", orig)
		}
		switch s[i] {
		case 's':
			total += val
		case 'm':
			total += val * 60
		case 'h':
			total += val * 3600
		default:
			return 0, fmt.Errorf("无效时长 %q：不支持的单位 %q（只支持 s/m/h）", orig, string(s[i]))
		}
		i++
		if total > maxTotalSeconds {
			return 0, fmt.Errorf("无效时长 %q：数值过大", orig)
		}
	}
	if total == 0 {
		return 0, fmt.Errorf("无效时长 %q：必须大于 0", orig)
	}
	return time.Duration(total) * time.Second, nil
}

// loadPersistedConfig 把 Web 保存的运行时配置叠加到环境变量配置之上。
// 任何异常（文件损坏、字段非法、权限问题）都只降级为警告并保留环境变量配置，
// 绝不 Fatal：否则 restart: unless-stopped 的容器会陷入
// "解析失败→退出→重启→再失败" 的死循环，Web 页面完全不可用，
// 用户只能进宿主机手删文件才能恢复。
func loadPersistedConfig(cfg *Config) {
	if cfg.ConfigFile == "" {
		return
	}
	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return // 首次运行，没有配置文件属正常
		}
		// 读不到（权限/挂载问题）不应阻止程序运行，退回环境变量配置
		log.Printf("警告: 无法读取配置文件 %s: %v（本次仅使用环境变量配置）", cfg.ConfigFile, err)
		return
	}

	var pc persistedConfig
	if err := json.Unmarshal(data, &pc); err != nil {
		// 常见于掉电/磁盘写满留下的空文件或半截文件：备份后继续，不阻塞启动
		backup := cfg.ConfigFile + ".corrupt"
		if rerr := os.Rename(cfg.ConfigFile, backup); rerr != nil {
			log.Printf("警告: 配置文件 %s 解析失败: %v（备份为 %s 也失败: %v）", cfg.ConfigFile, err, backup, rerr)
		} else {
			log.Printf("警告: 配置文件 %s 解析失败: %v，已备份为 %s，本次使用环境变量配置", cfg.ConfigFile, err, backup)
		}
		return
	}

	// 先在副本上应用，整体校验通过才生效，避免"坏字段改了一半"
	cand := *cfg

	// 只覆盖"有值"的项：空值/零值保持环境变量的设定
	if pc.DeviceIP != "" {
		cand.DeviceIP = pc.DeviceIP
	}
	if pc.DeviceToken != "" {
		cand.DeviceToken = pc.DeviceToken
	}
	if pc.SIID != 0 {
		cand.SIID = pc.SIID
	}
	if pc.PIID != 0 {
		cand.PIID = pc.PIID
	}
	if pc.MiPort != 0 {
		cand.MiPort = pc.MiPort
	}
	if pc.PingIP1 != "" {
		cand.PingIP1 = pc.PingIP1
	}
	if pc.PingIP2 != "" {
		cand.PingIP2 = pc.PingIP2
	}
	durFields := []struct {
		raw  string
		dst  *time.Duration
		name string
	}{
		{pc.PingInterval, &cand.PingInterval, "ping_interval"},
		{pc.PingTimeout, &cand.PingTimeout, "ping_timeout"},
		{pc.OfflineThreshold, &cand.OfflineThreshold, "offline_threshold"},
		{pc.RebootCooldown, &cand.RebootCooldown, "reboot_cooldown"},
		{pc.RebootOffTime, &cand.RebootOffTime, "reboot_off_time"},
		{pc.MiioRetryInterval, &cand.MiioRetryInterval, "miio_retry_interval"},
	}
	for _, f := range durFields {
		if f.raw == "" {
			continue
		}
		d, err := parseDuration(f.raw)
		if err != nil {
			log.Printf("警告: 配置文件字段 %s %v，已忽略该项（沿用环境变量值 %v）", f.name, err, *f.dst)
			continue
		}
		*f.dst = d
	}
	if pc.MaxRebootAttempts != 0 {
		cand.MaxRebootAttempts = pc.MaxRebootAttempts
	}
	if pc.WebPort != 0 {
		cand.WebPort = pc.WebPort
	}
	if pc.WebListen != "" {
		cand.WebListen = pc.WebListen
	}
	// 环境变量显式指定密码 = 明确要求鉴权，优先于文件里的"关闭鉴权"
	if cfg.webPasswordFromEnv {
		cand.WebAuthDisabled = false
	} else {
		cand.WebAuthDisabled = pc.WebAuthDisabled
		if pc.WebPasswordHash != "" {
			cand.WebPasswordHash = pc.WebPasswordHash
		}
	}

	// 文件内容同样要过一遍统一校验，避免坏配置把程序带进"每 10 分钟重启光猫"的状态
	if err := validateConfig(&cand); err != nil {
		log.Printf("警告: 配置文件 %s 内容无效: %v", cfg.ConfigFile, err)
		log.Printf("  已忽略该文件，本次使用环境变量配置；修正或删除该文件后重启即可恢复")
		return
	}
	*cfg = cand
	log.Printf("已加载运行时配置: %s", cfg.ConfigFile)
}

// 先写临时文件、fsync 落盘，再原子替换：避免"写一半被杀/掉电"留下损坏的配置。
// 临时文件名带 pid，避免同目录下多个进程互相覆盖；没有 fsync 的话，
// 掉电后 rename 可能留下 0 字节文件（旧版就会因此让进程启动即失败）。
func savePersistedConfig(cfg Config) error {
	if cfg.ConfigFile == "" {
		return nil // 纯内存模式：持久化已被（显式或自动）关闭，不算失败
	}
	pc := persistedConfig{
		DeviceIP:          cfg.DeviceIP,
		DeviceToken:       cfg.DeviceToken,
		SIID:              cfg.SIID,
		PIID:              cfg.PIID,
		MiPort:            cfg.MiPort,
		PingIP1:           cfg.PingIP1,
		PingIP2:           cfg.PingIP2,
		PingInterval:      cfg.PingInterval.String(),
		PingTimeout:       cfg.PingTimeout.String(),
		OfflineThreshold:  cfg.OfflineThreshold.String(),
		RebootCooldown:    cfg.RebootCooldown.String(),
		RebootOffTime:     cfg.RebootOffTime.String(),
		MiioRetryInterval: cfg.MiioRetryInterval.String(),
		MaxRebootAttempts: cfg.MaxRebootAttempts,
		WebPort:           cfg.WebPort,
		WebListen:         cfg.WebListen,
		WebPasswordHash:   cfg.WebPasswordHash,
		WebAuthDisabled:   cfg.WebAuthDisabled,
	}
	data, err := json.MarshalIndent(pc, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(cfg.ConfigFile)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建配置目录失败: %w", err)
		}
	}
	tmp := fmt.Sprintf("%s.tmp.%d", cfg.ConfigFile, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("写入配置失败: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("写入配置失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("同步配置到磁盘失败: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("关闭配置文件失败: %w", err)
	}
	if err := os.Rename(tmp, cfg.ConfigFile); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("替换配置文件失败: %w", err)
	}
	// 目录项也尽量落盘，减少"掉电后文件名在但内容还是旧的"的窗口
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// loopbackNet 是 127.0.0.0/8，用于拒绝"永远可达"的 Ping 目标
var loopbackNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("127.0.0.0/8")
	return n
}()

// validatePingTarget 校验一个 Ping 目标。被拒的三种情况和固件版的 validIP+额外规则完全一致：
//   - 非 IPv4（域名 / IPv6）：pingICMP 基于原始 IPv4 地址，探测必然失败 → 误判断网 → 真的断电光猫；
//   - 0.0.0.0 / 127.0.0.0/8：永远"可达"，看门狗形同关闭；
//   - 等于插板地址：同上。
func validatePingTarget(name, ip, deviceIP string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("%s 必须是合法 IPv4 地址（不支持域名/IPv6）: %s", name, ip)
	}
	v4 := parsed.To4()
	if v4.Equal(net.IPv4zero) {
		return fmt.Errorf("%s 不能是 0.0.0.0", name)
	}
	if loopbackNet.Contains(v4) {
		return fmt.Errorf("%s 不能是回环地址（永远可达，看门狗会形同关闭）: %s", name, ip)
	}
	if deviceIP != "" {
		if d := net.ParseIP(deviceIP); d != nil && d.To4() != nil && d.To4().Equal(v4) {
			return fmt.Errorf("%s 不能与插板地址相同（%s）：看门狗会永远认为在线", name, ip)
		}
	}
	return nil
}

// durationLimit / durationLimits 定义所有时长参数的合法区间。
// 固件版（modem-watchdog.ino）使用完全相同的区间和默认值，改动时请同步两边。
type durationLimit struct {
	name     string
	min, max time.Duration
	get      func(*Config) time.Duration
}

var durationLimits = []durationLimit{
	{"检测间隔(PING_INTERVAL)", 5 * time.Second, time.Hour, func(c *Config) time.Duration { return c.PingInterval }},
	{"单次超时(PING_TIMEOUT)", 500 * time.Millisecond, 10 * time.Second, func(c *Config) time.Duration { return c.PingTimeout }},
	{"断网阈值(OFFLINE_THRESHOLD)", 30 * time.Second, 24 * time.Hour, func(c *Config) time.Duration { return c.OfflineThreshold }},
	{"重启冷却(REBOOT_COOLDOWN)", 10 * time.Second, time.Hour, func(c *Config) time.Duration { return c.RebootCooldown }},
	{"断电时长(REBOOT_OFF_TIME)", 5 * time.Second, 2 * time.Minute, func(c *Config) time.Duration { return c.RebootOffTime }},
	{"miIO 重试间隔(MIIO_RETRY_INTERVAL)", 5 * time.Second, time.Hour, func(c *Config) time.Duration { return c.MiioRetryInterval }},
	{"稳定在线期(ONLINE_STABLE)", 30 * time.Second, 24 * time.Hour, func(c *Config) time.Duration { return c.OnlineStable }},
}

func checkDurations(cfg *Config) error {
	for _, l := range durationLimits {
		if d := l.get(cfg); d < l.min || d > l.max {
			return fmt.Errorf("%s 必须在 %v-%v 之间，当前值 %v", l.name, l.min, l.max, d)
		}
	}
	return nil
}

// validateConfig 校验可由 Web 修改的字段（环境变量加载、文件加载、Web 保存共用同一套规则）
func validateConfig(cfg *Config) error {
	if ip := net.ParseIP(cfg.DeviceIP); ip == nil || ip.To4() == nil {
		return fmt.Errorf("设备 IP 必须是合法 IPv4 地址: %s", cfg.DeviceIP)
	}
	tb, err := hex.DecodeString(cfg.DeviceToken)
	if err != nil || len(tb) != 16 {
		return errors.New("设备 Token 必须是 32 个十六进制字符")
	}
	if cfg.SIID < 1 || cfg.SIID > 9999 {
		return fmt.Errorf("SIID 必须在 1-9999 之间: %d", cfg.SIID)
	}
	if cfg.PIID < 1 || cfg.PIID > 9999 {
		return fmt.Errorf("PIID 必须在 1-9999 之间: %d", cfg.PIID)
	}
	if cfg.MiPort < 1 || cfg.MiPort > 65535 {
		return fmt.Errorf("设备端口必须在 1-65535 之间: %d", cfg.MiPort)
	}
	if err := validatePingTarget("Ping 目标 1", cfg.PingIP1, cfg.DeviceIP); err != nil {
		return err
	}
	if err := validatePingTarget("Ping 目标 2", cfg.PingIP2, cfg.DeviceIP); err != nil {
		return err
	}
	if err := checkDurations(cfg); err != nil {
		return err
	}
	if cfg.MaxRebootAttempts < 1 || cfg.MaxRebootAttempts > 10 {
		return fmt.Errorf("熔断阈值必须在 1-10 之间: %d", cfg.MaxRebootAttempts)
	}
	if cfg.WebPort < 1 || cfg.WebPort > 65535 {
		return fmt.Errorf("WEB_PORT 必须在 1-65535 之间: %d", cfg.WebPort)
	}
	if cfg.LogBufferSize < 64<<10 || cfg.LogBufferSize > 256<<20 {
		return fmt.Errorf("LOG_BUFFER_SIZE 必须在 64KiB-256MiB 之间: %d", cfg.LogBufferSize)
	}
	return nil
}

// ==================== 运行时状态持久化 ====================
// 熔断状态与重启计数单独存一个小文件（<CONFIG_FILE>.state），与配置解耦：
//   - 不会因"Web 保存配置"重写配置文件而丢失；
//   - 不会因进程重启 / 容器重启把熔断悄悄清零，从而又对光猫连开 N 次断电。
//
// 写入只在状态变化时发生（熔断、计数增减），属低频事件，不磨损磁盘。
type runtimeState struct {
	FatalLatched   bool `json:"fatal_latched"`
	RebootAttempts int  `json:"reboot_attempts"`
}

func stateFilePath(configFile string) string {
	if configFile == "" {
		return ""
	}
	return configFile + ".state"
}

func loadRuntimeState(configFile string) runtimeState {
	var st runtimeState
	path := stateFilePath(configFile)
	if path == "" {
		return st
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("警告: 无法读取状态文件 %s: %v（熔断计数从 0 开始）", path, err)
		}
		return st
	}
	if err := json.Unmarshal(data, &st); err != nil {
		log.Printf("警告: 状态文件 %s 解析失败: %v（熔断计数从 0 开始）", path, err)
		return runtimeState{}
	}
	if st.RebootAttempts < 0 {
		st.RebootAttempts = 0
	}
	return st
}

func saveRuntimeState(configFile string, st runtimeState) error {
	path := stateFilePath(configFile)
	if path == "" {
		return nil
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ==================== 时区 / 权限 ====================

func setupTimezone(tz string) {
	if tz == "" {
		return
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		log.Printf("警告: TZ=%s 无法加载: %v（保持 %s）", tz, err, time.Local)
		return
	}
	time.Local = loc
	log.Printf("时区已设置为 %s", tz)
}

// 若以 root 启动且指定了 PUID/PGID，则降权到该用户。
// 语义与文档一致：两者都为 0 = 不降权；只设置其中一个属于配置错误，直接报错，
// 而不是像旧版那样把另一个悄悄改成 1000（那会让"想保持 root"的用户莫名被降权）。
func dropPrivileges(puid, pgid int) error {
	if puid == 0 && pgid == 0 {
		log.Println("未设置 PUID/PGID（均为 0），保持当前权限运行")
		return nil
	}
	if (puid == 0) != (pgid == 0) {
		return fmt.Errorf("PUID/PGID 必须同时设置（或同时为 0 表示不降权），当前 PUID=%d PGID=%d", puid, pgid)
	}
	if os.Getuid() != 0 {
		log.Printf("当前非 root（uid=%d），跳过降权", os.Getuid())
		return nil
	}

	// 顺序很重要：先 setgroups、setgid，最后 setuid
	if err := unix.Setgroups([]int{pgid}); err != nil {
		log.Printf("警告: setgroups 失败: %v", err)
	}
	if err := unix.Setgid(pgid); err != nil {
		return fmt.Errorf("setgid(%d) 失败: %w", pgid, err)
	}
	if err := unix.Setuid(puid); err != nil {
		return fmt.Errorf("setuid(%d) 失败: %w", puid, err)
	}

	log.Printf("已降权到 UID=%d GID=%d", puid, pgid)
	return nil
}

// ==================== miIO 协议 ====================

const (
	miioRequestID   = 1                      // 命令与响应共用的 id（与固件版一致，固定 1）
	miioAckTimeout  = 2 * time.Second        // 等待设备确认一条命令的时间（对应固件版 MIIO_ACK_TIMEOUT=2000）
	miioBufSize     = 2048                   // UDP 接收缓冲：miIO payload 一般 < 100 字节，留足余量
	miioDrainQuiet  = 150 * time.Millisecond // 发送命令前静默排空残留包的时间
	miioLogTruncate = 200                    // 日志中打印响应片段的最大长度
)

// truncateForLog 把设备响应的 JSON 片段截断，避免长响应刷爆日志
func truncateForLog(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > miioLogTruncate {
		return s[:miioLogTruncate] + "…"
	}
	return s
}

type MiiO struct {
	conn     *net.UDPConn
	token    []byte
	deviceID uint32
	stamp    uint32

	// 记录建连时的目标：主循环据此发现"Web 改了插板地址/Token"，从而重建连接
	targetIP   string
	targetPort int
	tokenHex   string
}

func NewMiiO(cfg *Config) (*MiiO, error) {
	token, err := hex.DecodeString(cfg.DeviceToken)
	if err != nil || len(token) != 16 {
		return nil, errors.New("设备 token 必须是 32 个十六进制字符")
	}
	dst := &net.UDPAddr{IP: net.ParseIP(cfg.DeviceIP), Port: cfg.MiPort}
	conn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		return nil, fmt.Errorf("建立 UDP 连接失败: %w", err)
	}
	return &MiiO{
		conn:       conn,
		token:      token,
		targetIP:   cfg.DeviceIP,
		targetPort: cfg.MiPort,
		tokenHex:   cfg.DeviceToken,
	}, nil
}

func (m *MiiO) Close() {
	if m.conn != nil {
		_ = m.conn.Close()
	}
}

// drainQuiet 静默排空：连续有包就继续读，直到出现 d 的静默期。
// SetReadDeadline 用的是绝对时刻，所以循环一定有界（一直有包也不会无限读下去）。
func (m *MiiO) drainQuiet(d time.Duration) {
	if d <= 0 {
		d = 100 * time.Millisecond
	}
	end := time.Now().Add(d)
	buf := make([]byte, miioBufSize)
	dropped := 0
	for time.Now().Before(end) {
		_ = m.conn.SetReadDeadline(end)
		if _, err := m.conn.Read(buf); err != nil {
			break
		}
		dropped++
	}
	// 汇总一条日志，防止 flood 打爆日志
	if dropped > 0 {
		log.Printf("丢弃残留包 %d 个", dropped)
	}
}

// miioReply 是设备响应解密后的 JSON（只取关心的字段）
type miioReply struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *miioError      `json:"error"`
}

type miioError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *miioError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("设备返回错误 code=%d: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("设备返回错误 code=%d", e.Code)
}

// deriveKeyIV 按 miIO 约定派生 AES key/iv：key = MD5(token)，iv = MD5(key || token)
func (m *MiiO) deriveKeyIV() ([]byte, []byte) {
	key := md5.Sum(m.token)
	keyToken := make([]byte, 32)
	copy(keyToken, key[:])
	copy(keyToken[16:], m.token)
	iv := md5.Sum(keyToken)
	return key[:], iv[:]
}

// decrypt 解密响应数据区（AES-128-CBC）并去掉 PKCS#7 填充
func (m *MiiO) decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("密文长度非法: %d", len(data))
	}
	key, iv := m.deriveKeyIV()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, data)

	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(plain) {
		return nil, errors.New("PKCS#7 填充非法")
	}
	return plain[:len(plain)-pad], nil
}

// waitReply 等待一条"checksum 校验通过且 id 匹配"的响应。
// 与固件版 miio_wait_reply 的行为一致：
//   - 只有 >32 字节且 checksum 校验通过的包才能证明 token 正确、包来自真实设备；
//   - 解出 JSON 后要求 "id" 等于本次请求 id，避免把上一次命令的迟到 ACK
//     或局域网内其它同 token 设备的回包当成本次命令的确认。
func (m *MiiO) waitReply(timeout time.Duration) (*miioReply, error) {
	end := time.Now().Add(timeout)
	buf := make([]byte, miioBufSize)
	invalid := 0
	defer func() {
		if invalid > 0 {
			log.Printf("丢弃无效响应 %d 个", invalid)
		}
	}()
	for time.Now().Before(end) {
		_ = m.conn.SetReadDeadline(end)
		n, err := m.conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("等待设备响应超时（%v）", timeout)
		}
		if n <= 32 || !m.validMiiOPacket(buf[:n]) {
			invalid++
			continue
		}
		plain, derr := m.decrypt(buf[32:n])
		if derr != nil {
			invalid++
			continue
		}
		var r miioReply
		if jerr := json.Unmarshal(plain, &r); jerr != nil {
			invalid++
			continue
		}
		if r.ID != miioRequestID {
			log.Printf("忽略 id=%d 的响应（期望 %d）: %s", r.ID, miioRequestID, truncateForLog(plain))
			invalid++
			continue
		}
		return &r, nil
	}
	return nil, fmt.Errorf("等待设备响应超时（%v）", timeout)
}

func (m *MiiO) Handshake() error {
	if m == nil || m.conn == nil {
		return errors.New("miIO 连接不可用")
	}
	m.drainQuiet(100 * time.Millisecond)

	hello := make([]byte, 32)
	hello[0] = 0x21
	hello[1] = 0x31
	hello[2] = 0x00
	hello[3] = 0x20
	for i := 4; i < 32; i++ {
		hello[i] = 0xFF
	}

	if _, err := m.conn.Write(hello); err != nil {
		return fmt.Errorf("发送握手包失败: %w", err)
	}

	// 重要：设备对 hello 的响应是 32 字节、checksum 字段固定回显 0xFF，没有有效校验和
	// （与 python-miio 行为一致），所以"握手成功"只能说明该地址上有个 miIO 设备，
	// 不能证明 token 正确。token 是否正确由后续带数据的响应（checksum 校验）来判定。
	_ = m.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, miioBufSize)
	invalid := 0
	for {
		n, err := m.conn.Read(buf)
		if err != nil {
			if invalid > 0 {
				log.Printf("握手期间丢弃无效响应 %d 个", invalid)
			}
			return fmt.Errorf("握手超时: %w", err)
		}
		if !m.validMiiOPacket(buf[:n]) {
			// 诊断关键：出现此日志说明设备有回包但未通过校验（魔数/长度字段不符）；
			// 若超时且无此日志，说明设备完全没回包（IP/端口错误或设备不在线）。
			// 只打印第一条详情，其余的汇总，避免被 flood 刷爆日志。
			invalid++
			if invalid == 1 {
				log.Printf("握手响应未通过校验，已丢弃 %d 字节: % X", n, buf[:min(n, 48)])
			}
			continue
		}
		if invalid > 0 {
			log.Printf("握手期间丢弃无效响应 %d 个", invalid)
		}
		m.deviceID = binary.BigEndian.Uint32(buf[8:12])
		m.stamp = binary.BigEndian.Uint32(buf[12:16])
		log.Printf("握手成功 DID=%08X Stamp=%d（握手不校验 token）", m.deviceID, m.stamp)
		return nil
	}
}

// validMiiOPacket 校验 miIO 响应包：魔数 0x21 0x31、长度字段一致。
// 注意：设备对 hello 的响应（32 字节无数据）中 checksum 字段固定回显 0xFF×16，
// 无有效校验和，因此不做 checksum 校验（与 python-miio 行为一致）；
// 带数据的响应才校验 checksum = MD5(header + token + data)，
// 通过即确认 token 正确、包来自真实设备。
func (m *MiiO) validMiiOPacket(pkt []byte) bool {
	if len(pkt) < 32 {
		return false
	}
	if pkt[0] != 0x21 || pkt[1] != 0x31 {
		return false
	}
	if int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) {
		return false
	}
	if len(pkt) == 32 {
		return true // hello 响应：checksum 字段为 0xFF×16，无有效校验和
	}
	h := md5.New()
	h.Write(pkt[:16])
	h.Write(m.token)
	h.Write(pkt[32:])
	return bytes.Equal(h.Sum(nil), pkt[16:32])
}

// SendCommand 发送一条 miIO 命令并等待设备确认。
// 与固件版一致：只有"收到 checksum 校验通过、id 匹配的响应"才算成功；
// 设备明确返回 error 时返回该错误；超时无响应同样返回错误。
// 旧实现只判断 UDP Write 是否报错，于是"设备根本没收到/没接受"也会被当成成功，
// 让上层把一次无效动作记成"重启完成"并累加熔断计数。
func (m *MiiO) SendCommand(method, params string) error {
	if m == nil || m.conn == nil {
		return errors.New("miIO 连接不可用")
	}
	if m.deviceID == 0 {
		return errors.New("尚未握手，无法发送命令")
	}

	payload := fmt.Sprintf(`{"id":%d,"method":"%s","params":%s}`, miioRequestID, method, params)
	log.Printf("Payload: %s", payload)

	// PKCS#7 填充：payload 长度正好是 16 的倍数时补满一整块（正确写法，不是 off-by-one）
	padLen := aes.BlockSize - (len(payload) % aes.BlockSize)
	padded := make([]byte, len(payload)+padLen)
	copy(padded, payload)
	for i := len(payload); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	key, iv := m.deriveKeyIV()
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, padded)

	totalLen := 16 + 16 + len(encrypted)
	header := make([]byte, 16)
	header[0] = 0x21
	header[1] = 0x31
	binary.BigEndian.PutUint16(header[2:4], uint16(totalLen))
	binary.BigEndian.PutUint32(header[8:12], m.deviceID)
	m.stamp++
	binary.BigEndian.PutUint32(header[12:16], m.stamp)

	// checksum = MD5(header + token + encrypted)
	h := md5.New()
	h.Write(header)
	h.Write(m.token)
	h.Write(encrypted)
	checksum := h.Sum(nil)

	packet := make([]byte, 0, totalLen)
	packet = append(packet, header...)
	packet = append(packet, checksum...)
	packet = append(packet, encrypted...)

	// 发送前先清掉残留包，否则可能把上一次命令的旧 ACK 当成本次结果（固件版同样处理）
	m.drainQuiet(miioDrainQuiet)

	if _, err := m.conn.Write(packet); err != nil {
		return fmt.Errorf("发送命令失败: %w", err)
	}
	log.Printf("命令已发送 len=%d，等待设备确认...", totalLen)

	reply, err := m.waitReply(miioAckTimeout)
	if err != nil {
		return err
	}
	if reply.Error != nil {
		return reply.Error
	}
	log.Printf("设备已确认命令: %s", truncateForLog(reply.Result))
	return nil
}

// setPower 开关插板电源。与固件版 miio_setPower 一致：最多重试 3 次，
// 只有设备明确确认才算成功——"断没断电、上没上电"这种动作绝不能靠猜。
func (m *MiiO) setPower(on bool, siid, piid int) error {
	params := fmt.Sprintf(`[{"siid":%d,"piid":%d,"value":%t}]`, siid, piid, on)
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		err := m.SendCommand("set_properties", params)
		if err == nil {
			log.Printf("插板电源已%s", onOffText(on))
			return nil
		}
		lastErr = err
		log.Printf("设置电源(%s) 第 %d/3 次未确认: %v", onOffText(on), attempt, err)
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("设置电源(%s) 失败: %w", onOffText(on), lastErr)
}

func onOffText(on bool) string {
	if on {
		return "打开"
	}
	return "关闭"
}

// ==================== ICMP ping（DGRAM 套接字，非 root 可用）====================

var pingSeq atomic.Uint32

// icmpChecksum 计算 16 位反码校验和。
// 说明：在 Linux 的 ping socket（SOCK_DGRAM + IPPROTO_ICMP）下，内核会用
// inet_sport 覆盖 ICMP 的 id 字段并重新计算校验和，因此这里算出的值只是形式上的
// （python/iputils 的实现也会填），不影响功能；保留它是为了报文结构完整。
func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// 使用 SOCK_DGRAM + IPPROTO_ICMP（Linux ping socket）。
// 非 root 用户需要 sysctl net.ipv4.ping_group_range 覆盖其 GID。
func pingICMP(target string, timeout time.Duration) bool {
	dst := net.ParseIP(target)
	if dst == nil {
		log.Printf("ping: 目标地址无效 %s", target)
		return false
	}
	dst4 := dst.To4()
	if dst4 == nil {
		log.Printf("ping: 仅支持 IPv4: %s", target)
		return false
	}

	// SOCK_CLOEXEC：restart_self 会用 syscall.Exec 替换进程映像，这个 fd 不应被继承
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		log.Printf("ping: ICMP DGRAM socket 创建失败: %v", err)
		log.Printf("  非 root 用户需要: sysctl net.ipv4.ping_group_range 覆盖当前 GID")
		log.Printf("  compose 中可加: sysctls: [net.ipv4.ping_group_range=0 2147483647]")
		return false
	}
	defer unix.Close(fd)

	if err := unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
		log.Printf("ping: bind 失败: %v", err)
		return false
	}

	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	seq := uint16(pingSeq.Add(1) & 0xFFFF)

	// ICMP Echo Request：8 字节头 + 8 字节负载
	msg := make([]byte, 16)
	msg[0] = 8 // Type = Echo Request
	msg[1] = 0
	// ID（4:6）由内核在 DGRAM 模式下自动填充
	binary.BigEndian.PutUint16(msg[6:8], seq)
	binary.BigEndian.PutUint64(msg[8:16], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(msg[2:4], icmpChecksum(msg))

	var sa unix.SockaddrInet4
	copy(sa.Addr[:], dst4)

	// connect 后内核只投递来自该目标的回包，防止内网伪造 Echo Reply 干扰检测
	if err := unix.Connect(fd, &sa); err != nil {
		log.Printf("ping %s: connect 失败: %v", target, err)
		return false
	}
	if err := unix.Send(fd, msg, 0); err != nil {
		log.Printf("ping %s: 发送失败: %v", target, err)
		return false
	}

	buf := make([]byte, 1500)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return false // 超时 / 错误
		}
		// DGRAM ICMP 收到的是裸 ICMP 消息（无 IP 头）
		if n < 8 {
			continue
		}
		if buf[0] != 0 { // 不是 Echo Reply
			continue
		}
		if binary.BigEndian.Uint16(buf[6:8]) != seq {
			continue
		}
		return true
	}
}

// checkICMPReady 自检 ICMP DGRAM socket 是否可用。
// 若不可用（非 root 且 ping_group_range 未覆盖 GID），程序将永远探测不到网络，
// 继续运行只会每 10 分钟重启一次光猫，因此启动阶段直接失败退出。
func checkICMPReady() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("ICMP DGRAM socket 创建失败: %w（非 root 需 sysctl net.ipv4.ping_group_range 覆盖当前 GID；compose 可加 sysctls: [net.ipv4.ping_group_range=0 2147483647]）", err)
	}
	_ = unix.Close(fd)
	return nil
}

// ==================== 业务逻辑 ====================

// rebootModem 执行一次完整的"断电 → 等待 → 上电"。
// 返回 nil 表示插板确实断电并重新上电；返回错误表示动作没走完，
// 上层仍会累加熔断计数，并对"可能停在断电状态"这种最坏情况告警。
func rebootModem(m *MiiO, cfg *Config) error {
	log.Println("尝试重启光猫...")

	if err := m.Handshake(); err != nil {
		return fmt.Errorf("miIO 握手失败: %w", err)
	}

	log.Println("关闭插板电源...")
	if err := m.setPower(false, cfg.SIID, cfg.PIID); err != nil {
		return fmt.Errorf("关闭插板失败: %w", err)
	}

	log.Printf("等待 %v 后重新上电...", cfg.RebootOffTime)
	time.Sleep(cfg.RebootOffTime)

	log.Println("打开插板电源...")
	if err := m.setPower(true, cfg.SIID, cfg.PIID); err != nil {
		// 最坏情况：断电成功但上电命令始终没被确认 → 光猫会一直处于断电状态
		return fmt.Errorf("严重：插板未确认恢复供电，光猫可能仍处于断电状态: %w", err)
	}

	// 措辞要准确：这里只完成了"插板断电+上电"，光猫本身还要几十秒才启动完，
	// 是否真的恢复由后续的 ping 判定。
	log.Println("插板已断电并重新上电（光猫仍在启动，稍后由 ping 判定）")
	return nil
}

// ==================== 运行时组件 ====================

// RingLog 是固定容量的环形日志缓冲：写满自动覆盖最旧内容。
// 只占内存、不落盘（避免磨损磁盘），进程重启即清空。
// total 是单调递增的写入总量，既当"日志版本号"又当"增量拉取游标"
// （与固件版的 logSeqCounter 语义一致，永不回绕重号）。
type RingLog struct {
	mu    sync.Mutex
	buf   []byte
	head  int    // 下一个写入位置
	size  int    // 当前有效字节数
	total uint64 // 单调递增的写入总量
}

func NewRingLog(n int) *RingLog {
	if n < 4096 {
		n = 4096
	}
	return &RingLog{buf: make([]byte, n)}
}

func (r *RingLog) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	capacity := len(r.buf)
	if capacity == 0 || len(p) == 0 {
		return len(p), nil
	}
	// 分两段拷贝，替代旧版逐字节写入（1 MiB 缓冲下开销可观）
	if len(p) >= capacity {
		// 单次写入就超过整个缓冲：只保留最后 capacity 字节
		copy(r.buf, p[len(p)-capacity:])
		r.head = 0
		r.size = capacity
		r.total += uint64(len(p))
		return len(p), nil
	}
	first := copy(r.buf[r.head:], p)
	copy(r.buf, p[first:])
	r.head = (r.head + len(p)) % capacity
	if r.size < capacity {
		r.size += len(p)
		if r.size > capacity {
			r.size = capacity
		}
	}
	r.total += uint64(len(p))
	return len(p), nil
}

// rawRange 取出"第 from 个字节起、到最新为止"仍被保留的内容。
// from 的语义是客户端已收到的字节数（上一次响应的 total）。
// ok=false 表示 from 太旧（已被覆盖）或超前，调用方应改为全量重取。
func (r *RingLog) rawRange(from uint64) (out []byte, oldest uint64, ok bool) {
	capacity := len(r.buf)
	oldest = r.total - uint64(r.size)
	if capacity == 0 || r.size == 0 || from < oldest || from > r.total {
		return nil, oldest, false
	}
	n := int(r.total - from)
	if n == 0 {
		return []byte{}, oldest, true
	}
	// 最新字节是 total-1、位于 head-1，故第 seq 个字节位于 (head-(total-seq)) mod capacity
	off := int(r.total - from)
	start := ((r.head-off)%capacity + capacity) % capacity
	first := capacity - start
	if first > n {
		first = n
	}
	out = make([]byte, 0, n)
	out = append(out, r.buf[start:start+first]...)
	if first < n {
		out = append(out, r.buf[:n-first]...)
	}
	return out, oldest, true
}

// alignUTF8 丢掉开头不完整的 UTF-8 字符：环形缓冲按字节截断，
// 直接从中间输出会渲染出半个汉字。
func alignUTF8(b []byte) []byte {
	i := 0
	for i < len(b) && b[i]&0xC0 == 0x80 { // UTF-8 续字节 10xxxxxx
		i++
	}
	return b[i:]
}

// Snapshot 返回全量日志（已对齐 UTF-8 边界）与当前版本号
func (r *RingLog) Snapshot() ([]byte, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out, _, _ := r.rawRange(r.total - uint64(r.size))
	return alignUTF8(out), r.total
}

// SnapshotSince 返回 fromSeq 之后的新增日志；reset=true 表示 fromSeq 太旧
// （内容已被环形缓冲覆盖），调用方应丢弃已有内容改为全量显示。
func (r *RingLog) SnapshotSince(fromSeq uint64) (data []byte, seq uint64, reset bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out, _, ok := r.rawRange(fromSeq)
	if !ok {
		full, _, _ := r.rawRange(r.total - uint64(r.size))
		return alignUTF8(full), r.total, true
	}
	return alignUTF8(out), r.total, false
}

func (r *RingLog) Usage() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size, len(r.buf)
}

// Seq 返回日志版本号（不复制缓冲，供 /status 轮询使用）
func (r *RingLog) Seq() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

// Cap 返回缓冲区容量（启动时据此判断是否需要按配置重建）
func (r *RingLog) Cap() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buf)
}

// ConfigStore 让主循环与 Web 服务安全共享配置：
// 主循环每轮取一份值快照，Web 保存时整体替换。
type ConfigStore struct {
	mu  sync.RWMutex
	cfg Config
}

func NewConfigStore(c Config) *ConfigStore { return &ConfigStore{cfg: c} }

func (s *ConfigStore) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *ConfigStore) Update(fn func(*Config)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.cfg)
}

// WatchState 保存看门狗运行状态（主循环写、Web 读，必须加锁）
type WatchState struct {
	mu             sync.Mutex
	started        time.Time
	offlineSince   time.Time // 零值 = 当前外网可达
	onlineSince    time.Time // 网络恢复时刻（用于"连续在线多久"判定；零值 = 尚未恢复）
	rebooting      bool
	rebootAt       time.Time
	rebootAttempts int
	fatalLatched   bool
	miioOK         bool
}

func NewWatchState() *WatchState { return &WatchState{started: time.Now()} }

// StateSnapshot 是给 Web 展示的一致快照
type StateSnapshot struct {
	Uptime         time.Duration
	Online         bool
	OfflineFor     time.Duration
	Rebooting      bool
	RebootAttempts int
	FatalLatched   bool
	MiioOK         bool
}

func (s *WatchState) Snapshot() StateSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := StateSnapshot{
		Uptime:         time.Since(s.started),
		Online:         s.offlineSince.IsZero(),
		Rebooting:      s.rebooting,
		RebootAttempts: s.rebootAttempts,
		FatalLatched:   s.fatalLatched,
		MiioOK:         s.miioOK,
	}
	if !s.offlineSince.IsZero() {
		snap.OfflineFor = time.Since(s.offlineSince)
	}
	return snap
}

func (s *WatchState) SetMiioOK(ok bool) {
	s.mu.Lock()
	s.miioOK = ok
	s.mu.Unlock()
}

// MarkOnline 记录"网络已恢复"，并返回本轮已连续在线的时长。
// 熔断计数只在连续在线超过 OnlineStable 之后才清零：否则"重启后能撑几分钟又断"
// 的老化光猫永远不会熔断，会长期每 (阈值+冷却) 真断电一次。
func (s *WatchState) MarkOnline(t time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offlineSince = time.Time{}
	if s.onlineSince.IsZero() {
		s.onlineSince = t
	}
	return t.Sub(s.onlineSince)
}

// ResetOffline 清空断网与在线计时（一次重启动作之后重新开始观察）
func (s *WatchState) ResetOffline() {
	s.mu.Lock()
	s.offlineSince = time.Time{}
	s.onlineSince = time.Time{}
	s.mu.Unlock()
}

// MarkOfflineStart 记录断网起点（仅在尚未开始计时时生效），并重置"连续在线"计时
func (s *WatchState) MarkOfflineStart(t time.Time) {
	s.mu.Lock()
	if s.offlineSince.IsZero() {
		s.offlineSince = t
	}
	s.onlineSince = time.Time{}
	s.mu.Unlock()
}

func (s *WatchState) OfflineSince() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.offlineSince
}

func (s *WatchState) SetRebooting(on bool, at time.Time) {
	s.mu.Lock()
	s.rebooting = on
	s.rebootAt = at
	s.mu.Unlock()
}

func (s *WatchState) Rebooting() (bool, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rebooting, s.rebootAt
}

// IncRebootAttempts 记一次"已触发的重启动作"（无论动作是否真正完成），返回累计次数。
// 语义与固件版一致：动作失败也计数，否则插板不可用 / Token 错误时
// 会每 (阈值+冷却) 无限重试且永不熔断。
func (s *WatchState) IncRebootAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rebootAttempts++
	return s.rebootAttempts
}

func (s *WatchState) RebootAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rebootAttempts
}

func (s *WatchState) SetFatal(v bool) {
	s.mu.Lock()
	s.fatalLatched = v
	s.mu.Unlock()
}

func (s *WatchState) Fatal() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fatalLatched
}

// RestoreFatal 从持久化的运行时状态恢复熔断与计数（启动时调用一次）。
// 目的是：即使进程/容器重启，也不会把熔断悄悄清零、再对光猫连开 N 次断电。
func (s *WatchState) RestoreFatal(fatal bool, attempts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if attempts < 0 {
		attempts = 0
	}
	s.fatalLatched = fatal
	s.rebootAttempts = attempts
}

// ClearFatal 解除熔断并清零计数（连续在线足够久之后，或人工点"清除熔断"）
func (s *WatchState) ClearFatal() {
	s.mu.Lock()
	s.fatalLatched = false
	s.rebootAttempts = 0
	s.mu.Unlock()
}

// Controller 是"Web → 主循环"的单槽控制标志（不是队列：忙碌时直接返回 409）。
// HTTP 处理只登记动作（避免在请求里做十几秒的阻塞操作），主循环每轮取走执行。
// running 字段很重要：rebootModem 要跑十几秒，若只清 pending，
// 这期间用户再点一次"断电重启光猫"就会被接受并真的执行第二次。
type Controller struct {
	mu      sync.Mutex
	pending string
	running string
}

var errActionBusy = errors.New("已有任务在执行")

func (c *Controller) Request(action string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != "" || c.running != "" {
		return errActionBusy
	}
	c.pending = action
	return nil
}

// Take 取出待执行动作并标记为"执行中"；执行完必须调用 Done
func (c *Controller) Take() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	a := c.pending
	if a == "" {
		return ""
	}
	c.pending = ""
	c.running = a
	return a
}

// Done 结束"执行中"状态
func (c *Controller) Done() {
	c.mu.Lock()
	c.running = ""
	c.mu.Unlock()
}

// Pending 返回当前待执行或正在执行的动作（供 /status 显示"任务执行中"）
func (c *Controller) Pending() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running != "" {
		return c.running
	}
	return c.pending
}

// restartSelf 原地重启进程：优先 syscall.Exec 直接替换自身（不依赖容器重启策略），
// 失败则退出，交给 compose 里的 restart: unless-stopped 拉起。
// Go 的 socket 默认带 CLOEXEC，Exec 时旧监听自动关闭，新进程可立即重新占用端口。
//
// 特殊处理：容器 entrypoint 是 "cp /src/... /tmp/... && exec /tmp/..."，
// 而 Exec 不会重跑 entrypoint，于是"重启看门狗进程"用的仍是旧副本。
// 这里先比较源二进制的体积，若已更新就直接退出，让容器重启策略重新复制。
func restartSelf(sourceBinary string) {
	if sourceBinary != "" {
		if src, err := os.Stat(sourceBinary); err == nil {
			if self, err2 := os.Executable(); err2 == nil {
				if me, err3 := os.Stat(self); err3 == nil && src.Size() != me.Size() {
					log.Printf("检测到 %s 已被替换（%d → %d 字节），退出进程交由容器重启策略重新复制",
						sourceBinary, me.Size(), src.Size())
					os.Exit(0)
				}
			}
		}
	}
	if exe, err := os.Executable(); err == nil {
		log.Printf("重启进程: %s", exe)
		if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
			log.Printf("原地重启失败: %v（改为退出进程，交由容器重启策略拉起）", err)
		} else {
			return // Exec 成功后不会执行到这里
		}
	}
	os.Exit(0)
}

// executeAction 在主循环里执行来自 Web 的控制动作。
// 执行期间 Controller 处于 running 状态，新请求会被拒绝（见 Controller 注释）。
func executeAction(action string, cfg Config, state *WatchState, m *MiiO) {
	switch action {
	case "reboot_modem":
		log.Println(">>> 执行手动任务：断电重启光猫")
		if m == nil {
			log.Println(">>> 插板连接不可用，无法执行（请检查插板 IP/Token 与网络）")
			state.SetMiioOK(false)
			return
		}
		if err := rebootModem(m, &cfg); err != nil {
			log.Printf(">>> 手动重启光猫未完成: %v", err)
			state.SetMiioOK(false)
		} else {
			log.Println(">>> 手动重启光猫完成（等待网络恢复）")
			state.SetMiioOK(true)
		}
		// 与自动重启保持一致：重置观察窗口并进入冷却期。
		// 手动动作不计入熔断计数——是人在操作，不是看门狗在试错。
		state.ResetOffline()
		state.SetRebooting(true, time.Now())
	case "power_on":
		log.Println(">>> 执行手动任务：恢复插板供电")
		if m == nil {
			log.Println(">>> 插板连接不可用，无法恢复供电")
			state.SetMiioOK(false)
			return
		}
		if err := m.Handshake(); err != nil {
			log.Printf(">>> miIO 握手失败，无法恢复供电: %v", err)
			state.SetMiioOK(false)
			return
		}
		if err := m.setPower(true, cfg.SIID, cfg.PIID); err != nil {
			log.Printf(">>> 恢复供电未获设备确认: %v", err)
			log.Println(">>> !!! 请人工确认插板是否已通电 !!!")
			state.SetMiioOK(false)
			return
		}
		log.Println(">>> 插板已恢复供电")
		state.SetMiioOK(true)
	case "restart_self":
		log.Println(">>> 远程指令：重启看门狗进程")
		restartSelf(cfg.SourceBinary)
	case "factory_reset":
		log.Println(">>> 远程指令：恢复出厂设置（删除运行时配置文件）")
		if cfg.ConfigFile == "" {
			log.Println(">>> 纯内存模式：没有配置文件可删，直接重启进程（环境变量配置保持不变）")
		} else if err := os.Remove(cfg.ConfigFile); err != nil && !os.IsNotExist(err) {
			// 删除失败说明"恢复出厂"并没有真的生效，此时重启只会让用户误以为已重置
			log.Printf(">>> 删除配置文件失败: %v", err)
			log.Println(">>> 未执行重启：配置未被删除，请检查挂载权限后重试")
			return
		} else {
			log.Printf(">>> 已删除 %s，重启后回到环境变量配置", cfg.ConfigFile)
		}
		// 运行时状态（熔断/计数）也要清掉，否则"恢复出厂"后仍带着旧熔断
		if p := stateFilePath(cfg.ConfigFile); p != "" {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				log.Printf(">>> 删除状态文件 %s 失败: %v", p, err)
			}
		}
		restartSelf(cfg.SourceBinary)
	}
}

func main() {
	// 日志同时写标准输出（docker logs 可见）和内存环形缓冲（Web 页可见）。
	// 先按默认 8 MiB 建缓冲（loadConfig 期间的日志也要进缓冲），拿到配置后再按
	// LOG_BUFFER_SIZE 重建一次。缓冲只占内存、不落盘。
	ring := NewRingLog(8 << 20)
	log.SetOutput(io.MultiWriter(os.Stdout, ring))
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("=== 光猫看门狗启动 ===")

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	if cfg.LogBufferSize != ring.Cap() {
		ring = NewRingLog(cfg.LogBufferSize)
		log.SetOutput(io.MultiWriter(os.Stdout, ring))
	}

	setupTimezone(cfg.TZ)

	// 仅在"从未设置过密码"且用户没有主动关闭鉴权时生成随机初始口令。
	// WebAuthDisabled 是持久化字段：在页面上点过"关闭鉴权"之后，重启不会再被强制加回密码。
	generatedPassword := ""
	if cfg.WebPasswordHash == "" && !cfg.WebAuthDisabled {
		pw, err := randomPassword(12)
		if err != nil {
			log.Fatalf("无法生成初始访问密码: %v（可设置 WEB_PASSWORD，或在配置文件中打开 web_auth_disabled）", err)
		}
		generatedPassword = pw
		cfg.WebPasswordHash = hashPassword(pw)
	}

	if err := dropPrivileges(cfg.PUID, cfg.PGID); err != nil {
		log.Fatalf("降权失败: %v", err)
	}

	// 决定运行模式：能落盘就持久化，不能就自动降级为纯内存模式（不写任何文件、不再报错）
	ensureConfigWritable(cfg)

	log.Printf("设备 IP      : %s:%d", cfg.DeviceIP, cfg.MiPort)
	log.Printf("SIID/PIID    : %d / %d", cfg.SIID, cfg.PIID)
	log.Printf("Ping 目标    : %s, %s", cfg.PingIP1, cfg.PingIP2)
	log.Printf("Ping 间隔    : %v (超时 %v)", cfg.PingInterval, cfg.PingTimeout)
	log.Printf("断网阈值     : %v（需连续 2 次检测失败才开始计时）", cfg.OfflineThreshold)
	log.Printf("重启冷却     : %v", cfg.RebootCooldown)
	log.Printf("断电时长     : %v", cfg.RebootOffTime)
	log.Printf("miIO 重试    : %v", cfg.MiioRetryInterval)
	log.Printf("稳定在线期   : %v（连续在线这么久才清零熔断计数）", cfg.OnlineStable)
	log.Printf("熔断阈值     : 连续 %d 次触发重启后停止自动动作", cfg.MaxRebootAttempts)
	log.Printf("Web 管理     : 端口 %d，监听 %q", cfg.WebPort, cfg.WebListen)
	if cfg.ConfigFile == "" {
		log.Printf("配置文件     : （纯内存模式，不写文件）")
	} else {
		log.Printf("配置文件     : %s", cfg.ConfigFile)
	}
	log.Printf("日志缓冲     : %d 字节（仅内存）", cfg.LogBufferSize)
	log.Printf("PUID/PGID    : %d / %d", cfg.PUID, cfg.PGID)

	// 启动自检：ICMP socket 不可用属本机配置问题，直接退出而非误判为断网引发重启风暴
	if err := checkICMPReady(); err != nil {
		log.Fatalf("网络检测自检失败: %v", err)
	}

	// 持久化当前配置（含首次生成的密码）：放在降权之后，保证文件属主是运行用户。
	// 纯内存模式下 savePersistedConfig 直接返回 nil（什么都不做），不算失败。
	if err := savePersistedConfig(*cfg); err != nil {
		log.Printf("警告: 配置持久化失败: %v", err)
	} else if cfg.ConfigFile != "" {
		log.Printf("运行时配置已写入 %s（删除该文件即恢复出厂）", cfg.ConfigFile)
	}

	store := NewConfigStore(*cfg)
	state := NewWatchState()
	// 恢复上次的熔断状态与重启计数：进程/容器重启不该成为"绕过熔断"的手段
	if rs := loadRuntimeState(cfg.ConfigFile); rs.FatalLatched || rs.RebootAttempts > 0 {
		state.RestoreFatal(rs.FatalLatched, rs.RebootAttempts)
		log.Printf("已恢复运行时状态: 熔断=%v，已累计重启动作 %d 次", rs.FatalLatched, rs.RebootAttempts)
	}
	ctl := &Controller{}
	web := NewWebServer(store, ring, state, ctl)
	if err := web.Start(); err != nil {
		log.Fatalf("启动 Web 管理失败: %v", err)
	}
	log.Printf("远程管理已开启: http://<本机IP>:%d/  （用户名 admin）", cfg.WebPort)
	if generatedPassword != "" {
		log.Printf("★ 首次启动生成的访问密码: %s", generatedPassword)
		log.Println("★ 请登录后到「配置」页修改；也可用环境变量 WEB_PASSWORD 指定固定密码")
	} else if cfg.WebPasswordHash == "" {
		log.Println("★ 警告: 当前未启用访问密码（鉴权已关闭），请仅在可信局域网内使用")
	}

	// 启动时探测一次，便于尽早发现问题。
	// 这里只警告：真正的断网判定走主循环的"连续 2 次检测失败"，
	// 避免启动瞬间网络未就绪就被当成断网。
	if !pingICMP(cfg.PingIP1, cfg.PingTimeout) && !pingICMP(cfg.PingIP2, cfg.PingTimeout) {
		log.Println("警告: 启动时两个 ping 目标均不可达（网络可能异常，或 Ping 目标配置有误）")
	}

	m, err := NewMiiO(cfg)
	if err != nil {
		// 插板暂时连不上不应该让整个看门狗不启动：网络检测与 Web 管理仍然可用，
		// 主循环会按 MIIO_RETRY_INTERVAL 周期重建连接。
		log.Printf("初始 miIO 连接失败: %v（%v 后重试）", err, cfg.MiioRetryInterval)
		state.SetMiioOK(false)
		m = nil
	} else if err := m.Handshake(); err != nil {
		log.Printf("初始握手失败: %v（%v 后重试）", err, cfg.MiioRetryInterval)
		state.SetMiioOK(false)
	} else {
		log.Println("初始握手成功（握手不校验 token，token 是否正确由第一条命令确认）")
		state.SetMiioOK(true)
	}
	defer func() {
		if m != nil {
			m.Close()
		}
	}()

	// 记录"最近一次建连尝试的目标"：即使建连失败（m == nil），
	// 用户改了插板 IP/Token 也能立刻重试，而不必干等一个重试间隔。
	type miioTarget struct {
		ip    string
		port  int
		token string
	}
	attempted := miioTarget{ip: cfg.DeviceIP, port: cfg.MiPort, token: cfg.DeviceToken}

	lastFatal, lastAttempts := state.Fatal(), state.RebootAttempts() // 供状态落盘时做变化检测
	lastMiioCheck := time.Now()
	lastPing := time.Now()
	pingFailures := 0 // 连续检测失败次数：连续 2 次才判定断网，防单次抖动误判

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// 统一用真实时间：ticker 通道容量为 1，长阻塞（重启约十几秒）后读到的
		// tick 时间戳可能滞后十几秒，会把冷却期和断网计时算歪。
		now := time.Now()
		cfg := store.Get() // 每轮取配置快照：Web 上的修改立即生效

		// 熔断状态 / 重启计数有变化就落盘（低频事件，写盘开销可忽略）
		if fatal, attempts := state.Fatal(), state.RebootAttempts(); fatal != lastFatal || attempts != lastAttempts {
			lastFatal, lastAttempts = fatal, attempts
			if err := saveRuntimeState(cfg.ConfigFile, runtimeState{FatalLatched: fatal, RebootAttempts: attempts}); err != nil {
				log.Printf("警告: 保存运行时状态失败: %v", err)
			}
		}

		// 0. 执行来自 Web 的控制动作（在主循环里执行，避免与检测逻辑并发）
		if action := ctl.Take(); action != "" {
			executeAction(action, cfg, state, m)
			ctl.Done()
			lastPing = time.Now()
			pingFailures = 0
			continue
		}

		// 1. 插板配置变更 → 立即重建连接；连接不可用（m==nil）→ 目标变了立即重试，否则按重试间隔
		want := miioTarget{ip: cfg.DeviceIP, port: cfg.MiPort, token: cfg.DeviceToken}
		if m != nil && (m.targetIP != cfg.DeviceIP ||
			m.targetPort != cfg.MiPort || m.tokenHex != cfg.DeviceToken) {
			log.Printf("插板配置已变更，重建连接: %s:%d", cfg.DeviceIP, cfg.MiPort)
			m.Close()
			m = nil
		}
		if m == nil && (attempted != want || now.Sub(lastMiioCheck) >= cfg.MiioRetryInterval) {
			attempted = want
			lastMiioCheck = now
			nm, derr := NewMiiO(&cfg)
			if derr != nil {
				log.Printf("建立 miIO 连接失败: %v（%v 后重试）", derr, cfg.MiioRetryInterval)
				state.SetMiioOK(false)
			} else {
				m = nm
				if err := m.Handshake(); err != nil {
					log.Printf("miIO 握手失败: %v（%v 后重试）", err, cfg.MiioRetryInterval)
					state.SetMiioOK(false)
				} else {
					log.Println("miIO 握手成功")
					state.SetMiioOK(true)
				}
			}
		}

		// 2. 冷却期
		if rebooting, rebootAt := state.Rebooting(); rebooting && now.Sub(rebootAt) >= cfg.RebootCooldown {
			state.SetRebooting(false, time.Time{})
			log.Println("冷却期结束，恢复检测")
		}

		// 3. miIO 异常时按间隔重试握手（与固件版 checkMiioHeartbeat 行为一致）
		if m != nil && !state.Snapshot().MiioOK && now.Sub(lastMiioCheck) >= cfg.MiioRetryInterval {
			lastMiioCheck = now
			log.Println("尝试重新握手...")
			if err := m.Handshake(); err != nil {
				log.Printf("重新握手失败: %v", err)
			} else {
				log.Println("重新握手成功")
				state.SetMiioOK(true)
			}
		}

		// 4. 网络检测
		if rebooting, _ := state.Rebooting(); rebooting {
			continue
		}
		if now.Sub(lastPing) < cfg.PingInterval {
			continue
		}
		lastPing = now

		online := pingICMP(cfg.PingIP1, cfg.PingTimeout)
		if !online {
			online = pingICMP(cfg.PingIP2, cfg.PingTimeout)
		}

		if online {
			wasOffline := !state.OfflineSince().IsZero()
			stable := state.MarkOnline(now)
			pingFailures = 0
			if wasOffline {
				log.Println("网络恢复，重置断网计时")
			}
			// 必须"连续在线满 OnlineStable"才清零计数：否则"重启后能撑几分钟又断"的
			// 老化光猫永远不会熔断，会长期每 (阈值+冷却) 真断电一次。
			if (state.Fatal() || state.RebootAttempts() > 0) && stable >= cfg.OnlineStable {
				log.Printf("已连续在线 %v（≥ %v），重置自动重启计数与熔断状态",
					stable.Round(time.Second), cfg.OnlineStable)
				state.ClearFatal()
			}
			continue
		}

		// 连续 2 次检测失败才判定断网，避免单次丢包把计时重新拉起来
		pingFailures++
		if pingFailures < 2 {
			log.Println("两个 Ping 目标均不通（第 1 次；需连续 2 次才判定断网）")
			continue
		}
		if state.OfflineSince().IsZero() {
			state.MarkOfflineStart(now)
			log.Println("两个 Ping 目标连续 2 次均不通，开始断网计时")
			continue
		}

		elapsed := now.Sub(state.OfflineSince())
		log.Printf("断网已持续 %.0f 秒", elapsed.Seconds())

		// 已熔断则只观察、不再动手，等网络自己恢复或人工介入
		if state.Fatal() {
			continue
		}
		if elapsed < cfg.OfflineThreshold {
			continue
		}

		log.Println("连续断网达到阈值，触发光猫重启")
		var rebootErr error
		if m == nil {
			rebootErr = errors.New("插板连接不可用（IP/Token 或网络问题）")
			log.Printf("无法执行重启: %v", rebootErr)
		} else if rebootErr = rebootModem(m, &cfg); rebootErr != nil {
			log.Printf("重启未完成: %v", rebootErr)
		}
		state.SetMiioOK(rebootErr == nil)
		if rebootErr != nil {
			lastMiioCheck = time.Now()
		}

		// 无论成败都重新开始观察，并进入冷却期
		state.ResetOffline()
		state.SetRebooting(true, time.Now())

		// 熔断计数：动作"触发"就 +1，无论是否真正完成（与固件版一致）。
		// 否则插板不可用 / Token 错误时会每 (阈值+冷却) 无限重试且永不熔断。
		attempts := state.IncRebootAttempts()
		if rebootErr != nil {
			log.Printf("本次重启动作未完成（插板可能没断电或没上电），仍计入熔断计数: %d/%d",
				attempts, cfg.MaxRebootAttempts)
			log.Println("!!! 请人工检查插板 IP/Token 与供电，并确认光猫是否已恢复供电 !!!")
		} else {
			log.Printf("已累计 %d 次自动重启（上限 %d 次）", attempts, cfg.MaxRebootAttempts)
		}
		if attempts >= cfg.MaxRebootAttempts {
			state.SetFatal(true)
			log.Println("!!! 连续多次触发自动重启，已熔断：停止自动动作，请人工检查网络与 Ping 目标配置 !!!")
			log.Printf("!!! 网络恢复并连续在线 %v 后会自动解除熔断，也可在管理页点「清除熔断状态」 !!!", cfg.OnlineStable)
		}
	}
}

// ==================== Web 管理服务 ====================

const (
	adminUser    = "admin"  // Basic Auth 用户名（两版一致，固定）
	maxFormBytes = 64 << 10 // 表单请求体上限：防止巨型 POST 把 512m 内存打满
)

type WebServer struct {
	store *ConfigStore
	ring  *RingLog
	state *WatchState
	ctl   *Controller
	srv   *http.Server
}

func NewWebServer(store *ConfigStore, ring *RingLog, state *WatchState, ctl *Controller) *WebServer {
	return &WebServer{store: store, ring: ring, state: state, ctl: ctl}
}

// Start 先 Listen 再 Serve：端口被占用等问题能在启动阶段直接暴露，而不是静默失败
func (w *WebServer) Start() error {
	cfg := w.store.Get()

	mux := http.NewServeMux()
	mux.HandleFunc("/", w.handleRoot)
	mux.HandleFunc("/log", w.handleLog)
	mux.HandleFunc("/status", w.handleStatus)
	mux.HandleFunc("/api/control", w.handleControl)
	mux.HandleFunc("/api/config", w.handleConfig)

	addr := net.JoinHostPort(cfg.WebListen, strconv.Itoa(cfg.WebPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("监听 %s 失败: %w", addr, err)
	}
	w.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second, // 日志响应可能较大，给慢客户端留足时间
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if err := w.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("Web 服务退出: %v", err)
		}
	}()
	return nil
}

// authOK 校验 Basic Auth。
// 未设置密码、或用户在页面上主动关闭了鉴权（WebAuthDisabled，且该状态会持久化），
// 都视为"开放访问"（页面会显示醒目警告）。
func (w *WebServer) authOK(r *http.Request) bool {
	cfg := w.store.Get()
	if cfg.WebAuthDisabled || cfg.WebPasswordHash == "" {
		return true
	}
	user, pass, ok := r.BasicAuth()
	// 用户名也用常量时间比较，避免通过响应时间区分"用户名错"与"口令错"
	if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(adminUser)) != 1 {
		return false
	}
	got := hashPassword(pass)
	return subtle.ConstantTimeCompare([]byte(got), []byte(cfg.WebPasswordHash)) == 1
}

func (w *WebServer) requireAuth(wr http.ResponseWriter, r *http.Request) bool {
	if w.authOK(r) {
		return true
	}
	wr.Header().Set("WWW-Authenticate", `Basic realm="modem-watchdog"`)
	http.Error(wr, "401 Unauthorized", http.StatusUnauthorized)
	return false
}

// csrfOK 防跨站请求伪造：Basic Auth 的凭据会被浏览器自动附加到跨站请求上，
// 仅靠密码挡不住"恶意网页替你点按钮"（例如让插板断电）。
// 跨站 JS 想伪造自定义头必须先通过 CORS 预检，而本服务不回应预检，请求根本发不出去；
// 再叠加 Origin 同源校验作为第二道防线。
func csrfOK(r *http.Request) bool {
	if r.Header.Get("X-Requested-With") != "watchdog" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	return true
}

type apiResp struct {
	OK  bool   `json:"ok"`
	Msg string `json:"msg"`
}

func writeJSON(wr http.ResponseWriter, code int, v interface{}) {
	wr.Header().Set("Content-Type", "application/json; charset=utf-8")
	wr.Header().Set("Cache-Control", "no-store")
	wr.WriteHeader(code)
	_ = json.NewEncoder(wr).Encode(v)
}

func actionLabel(a string) string {
	switch a {
	case "reboot_modem":
		return "断电重启光猫"
	case "power_on":
		return "恢复插板供电"
	case "restart_self":
		return "重启看门狗进程"
	case "factory_reset":
		return "恢复出厂设置"
	}
	return a
}

func actionAcceptedMsg(a string) string {
	switch a {
	case "reboot_modem":
		return "已接受：即将断电重启光猫，网络将中断约 1–3 分钟"
	case "power_on":
		return "已接受：即将恢复插板供电"
	case "restart_self":
		return "已接受：看门狗进程即将重启，片刻后自动恢复"
	case "factory_reset":
		return "已接受：将删除运行时配置并重启；配置回到 compose 环境变量，访问密码也可能随之改变"
	}
	return "已接受"
}

func (w *WebServer) handleRoot(wr http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(wr, r)
		return
	}
	if !w.requireAuth(wr, r) {
		return
	}
	wr.Header().Set("Content-Type", "text/html; charset=utf-8")
	wr.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(wr, indexHTML)
}

// 纯文本日志。支持 ?since=<seq> 增量拉取：只返回该序号之后的新增字节，
// 前端因此不必每 2 秒重传整个环形缓冲（缓冲默认 8 MiB）。
// 若 since 太旧（内容已被环形缓冲覆盖），响应头 X-Log-Reset: 1 表示"这是全量，请整体替换"。
func (w *WebServer) handleLog(wr http.ResponseWriter, r *http.Request) {
	if !w.requireAuth(wr, r) {
		return
	}
	var (
		data  []byte
		seq   uint64
		reset bool
	)
	if raw := r.URL.Query().Get("since"); raw != "" {
		if since, err := strconv.ParseUint(raw, 10, 64); err == nil {
			data, seq, reset = w.ring.SnapshotSince(since)
		} else {
			data, seq = w.ring.Snapshot()
			reset = true
		}
	} else {
		data, seq = w.ring.Snapshot()
		reset = true
	}
	h := wr.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Log-Seq", strconv.FormatUint(seq, 10))
	if reset {
		h.Set("X-Log-Reset", "1")
	}
	h.Set("Content-Length", strconv.Itoa(len(data)))
	wr.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = wr.Write(data)
	}
}

type statusPayload struct {
	Ver        string `json:"ver"`
	Uptime     int64  `json:"uptime"` // 秒
	Online     bool   `json:"online"`
	LinkDown   int64  `json:"linkDown"`  // 秒；0 = 外网可达
	Rebooting  bool   `json:"rebooting"` // 冷却期中（刚执行过重启动作，暂不检测）
	Reboots    int    `json:"reboots"`
	MaxReboots int    `json:"maxReboots"`
	Fatal      bool   `json:"fatal"`
	Pending    string `json:"pending"`
	Miio       bool   `json:"miio"`
	LogUsed    int    `json:"logUsed"`
	LogTotal   int    `json:"logTotal"`
	LogSeq     uint64 `json:"logSeq"`
	WebPort    int    `json:"webPort"`
	Auth       bool   `json:"auth"`
	ConfigFile string `json:"configFile"`
}

func (w *WebServer) handleStatus(wr http.ResponseWriter, r *http.Request) {
	if !w.requireAuth(wr, r) {
		return
	}
	cfg := w.store.Get()
	snap := w.state.Snapshot()
	used, total := w.ring.Usage()
	writeJSON(wr, http.StatusOK, statusPayload{
		Ver:        "1.0",
		Uptime:     int64(snap.Uptime.Seconds()),
		Online:     snap.Online,
		LinkDown:   int64(snap.OfflineFor.Seconds()),
		Rebooting:  snap.Rebooting,
		Reboots:    snap.RebootAttempts,
		MaxReboots: cfg.MaxRebootAttempts,
		Fatal:      snap.FatalLatched,
		Pending:    w.ctl.Pending(), // 动作名（与固件版同一套 key），空闲为空串
		Miio:       snap.MiioOK,
		LogUsed:    used,
		LogTotal:   total,
		LogSeq:     w.ring.Seq(),
		WebPort:    cfg.WebPort,
		Auth:       cfg.WebPasswordHash != "" && !cfg.WebAuthDisabled,
		ConfigFile: cfg.ConfigFile,
	})
}

// 远程控制：POST /api/control  action=xxx[&confirm=1]
func (w *WebServer) handleControl(wr http.ResponseWriter, r *http.Request) {
	if !w.requireAuth(wr, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(wr, http.StatusMethodNotAllowed, apiResp{false, "请使用 POST"})
		return
	}
	if !csrfOK(r) {
		writeJSON(wr, http.StatusForbidden, apiResp{false, "缺少防跨站请求头，请在管理页面内操作"})
		return
	}
	r.Body = http.MaxBytesReader(wr, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeJSON(wr, http.StatusBadRequest, apiResp{false, "表单解析失败（请求体过大或格式错误）"})
		return
	}

	switch action := r.FormValue("action"); action {
	case "clear_fatal":
		// 无破坏性，立即执行
		w.state.ClearFatal()
		log.Println("远程操作：已清除熔断状态与重启计数")
		writeJSON(wr, http.StatusOK, apiResp{true, "熔断状态与重启计数已清除"})
	case "reboot_modem", "power_on", "restart_self", "factory_reset":
		if r.FormValue("confirm") != "1" { // 前端已弹确认框，这里是双保险
			writeJSON(wr, http.StatusBadRequest, apiResp{false, "缺少 confirm=1"})
			return
		}
		if err := w.ctl.Request(action); err != nil {
			writeJSON(wr, http.StatusConflict, apiResp{false, err.Error() + "，请稍候"})
			return
		}
		log.Printf("远程操作：请求%s（由主循环执行）", actionLabel(action))
		writeJSON(wr, http.StatusOK, apiResp{true, actionAcceptedMsg(action)})
	default:
		writeJSON(wr, http.StatusBadRequest, apiResp{false, "未知操作"})
	}
}

type configPayload struct {
	DeviceIP string `json:"deviceIp"`
	HasToken bool   `json:"hasToken"`
	SIID     int    `json:"siid"`
	PIID     int    `json:"piid"`
	MiPort   int    `json:"miPort"`
	Ping1    string `json:"ping1"`
	Ping2    string `json:"ping2"`
	// 时长字段与固件版一致：统一回传"秒数"（输入框同时接受纯秒数与 15s/10m 写法）
	PingInterval     int64  `json:"pingInterval"`
	PingTimeout      int64  `json:"pingTimeout"`
	OfflineThreshold int64  `json:"offlineThreshold"`
	RebootCooldown   int64  `json:"rebootCooldown"`
	RebootOffTime    int64  `json:"rebootOffTime"`
	MiioRetry        int64  `json:"miioRetry"`
	MaxReboots       int    `json:"maxReboots"`
	WebPort          int    `json:"webPort"`
	WebListen        string `json:"webListen"`
	HasPassword      bool   `json:"hasPassword"`
	WebAuthDisabled  bool   `json:"webAuthDisabled"`
	ConfigFile       string `json:"configFile"`
}

// GET /api/config 读取当前配置（敏感字段不回传明文）
func (w *WebServer) handleConfig(wr http.ResponseWriter, r *http.Request) {
	if !w.requireAuth(wr, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg := w.store.Get()
		writeJSON(wr, http.StatusOK, configPayload{
			DeviceIP:         cfg.DeviceIP,
			HasToken:         cfg.DeviceToken != "",
			SIID:             cfg.SIID,
			PIID:             cfg.PIID,
			MiPort:           cfg.MiPort,
			Ping1:            cfg.PingIP1,
			Ping2:            cfg.PingIP2,
			PingInterval:     int64(cfg.PingInterval.Seconds()),
			PingTimeout:      int64(cfg.PingTimeout.Seconds()),
			OfflineThreshold: int64(cfg.OfflineThreshold.Seconds()),
			RebootCooldown:   int64(cfg.RebootCooldown.Seconds()),
			RebootOffTime:    int64(cfg.RebootOffTime.Seconds()),
			MiioRetry:        int64(cfg.MiioRetryInterval.Seconds()),
			MaxReboots:       cfg.MaxRebootAttempts,
			WebPort:          cfg.WebPort,
			WebListen:        cfg.WebListen,
			HasPassword:      cfg.WebPasswordHash != "" && !cfg.WebAuthDisabled,
			WebAuthDisabled:  cfg.WebAuthDisabled,
			ConfigFile:       cfg.ConfigFile,
		})
	case http.MethodPost:
		if !csrfOK(r) {
			writeJSON(wr, http.StatusForbidden, apiResp{false, "缺少防跨站请求头，请在管理页面内操作"})
			return
		}
		r.Body = http.MaxBytesReader(wr, r.Body, maxFormBytes)
		w.saveConfig(wr, r)
	default:
		writeJSON(wr, http.StatusMethodNotAllowed, apiResp{false, "请使用 GET 或 POST"})
	}
}

// POST /api/config 保存配置：先整体校验，全部通过后再应用 + 落盘，
// 校验失败时不会留下"改了一半"的状态。密码类字段留空 = 保持不变。
// 注意：落盘失败时内存配置仍然生效（并如实告知），因此"内存与文件不一致"
// 这一种情况是可能存在的——重启后会回到文件/环境变量的值。
func (w *WebServer) saveConfig(wr http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(wr, http.StatusBadRequest, apiResp{false, "表单解析失败"})
		return
	}

	cur := w.store.Get()
	next := cur
	var errs []string

	if v := strings.TrimSpace(r.FormValue("device_ip")); v != "" {
		if net.ParseIP(v) == nil {
			errs = append(errs, "设备 IP 格式无效")
		} else {
			next.DeviceIP = v
		}
	}
	if v := strings.TrimSpace(r.FormValue("device_token")); v != "" {
		if tb, err := hex.DecodeString(v); err != nil || len(tb) != 16 {
			errs = append(errs, "Token 必须是 32 个十六进制字符")
		} else {
			next.DeviceToken = v
		}
	}
	if v := strings.TrimSpace(r.FormValue("ping_ip1")); v != "" {
		if net.ParseIP(v) == nil {
			errs = append(errs, "Ping 目标 1 必须是合法 IPv4 地址")
		} else {
			next.PingIP1 = v
		}
	}
	if v := strings.TrimSpace(r.FormValue("ping_ip2")); v != "" {
		if net.ParseIP(v) == nil {
			errs = append(errs, "Ping 目标 2 必须是合法 IPv4 地址")
		} else {
			next.PingIP2 = v
		}
	}

	intField := func(name string, min, max int, dst *int, label string) {
		raw := strings.TrimSpace(r.FormValue(name))
		if raw == "" {
			return
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < min || n > max {
			errs = append(errs, fmt.Sprintf("%s 必须在 %d-%d 之间", label, min, max))
			return
		}
		*dst = n
	}
	intField("siid", 1, 9999, &next.SIID, "siid")
	intField("piid", 1, 9999, &next.PIID, "piid")
	intField("mi_port", 1, 65535, &next.MiPort, "设备端口")
	intField("max_reboot_attempts", 1, 10, &next.MaxRebootAttempts, "最大连续重启次数")
	intField("web_port", 1, 65535, &next.WebPort, "HTTP 端口")

	// 时长字段：留空 = 保持不变；范围与 durationLimits / 固件版完全一致
	durField := func(name string, dst *time.Duration, label string, min, max time.Duration) {
		raw := strings.TrimSpace(r.FormValue(name))
		if raw == "" {
			return
		}
		d, err := parseDuration(raw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s：%v", label, err))
			return
		}
		if d < min || d > max {
			errs = append(errs, fmt.Sprintf("%s 必须在 %v-%v 之间", label, min, max))
			return
		}
		*dst = d
	}
	durField("ping_interval", &next.PingInterval, "检测间隔", 5*time.Second, time.Hour)
	durField("ping_timeout", &next.PingTimeout, "单次超时", 500*time.Millisecond, 10*time.Second)
	durField("offline_threshold", &next.OfflineThreshold, "断网阈值", 30*time.Second, 24*time.Hour)
	durField("reboot_cooldown", &next.RebootCooldown, "重启冷却", 10*time.Second, time.Hour)
	durField("reboot_off_time", &next.RebootOffTime, "断电时长", 5*time.Second, 2*time.Minute)
	durField("miio_retry_interval", &next.MiioRetryInterval, "miIO 重试间隔", 5*time.Second, time.Hour)

	if v := strings.TrimSpace(r.FormValue("web_listen")); v == "" {
		next.WebListen = ""
	} else if net.ParseIP(v) == nil {
		errs = append(errs, "监听地址必须是合法 IP（留空 = 所有接口）")
	} else {
		next.WebListen = v
	}

	// "关闭鉴权"作为持久化状态（WebAuthDisabled）：重启后不会再自动生成随机密码，
	// 否则用户点了"关闭鉴权"，重启后又变成"有密码且没人知道"。
	if r.FormValue("clear_web_password") == "1" {
		next.WebAuthDisabled = true
		next.WebPasswordHash = ""
	} else if v := r.FormValue("web_password"); v != "" {
		next.WebAuthDisabled = false
		next.WebPasswordHash = hashPassword(v)
	}

	if len(errs) > 0 {
		log.Printf("远程操作：配置保存被拒绝 - %s", strings.Join(errs, "；"))
		writeJSON(wr, http.StatusBadRequest, apiResp{false, "未保存：" + strings.Join(errs, "；")})
		return
	}
	if err := validateConfig(&next); err != nil {
		writeJSON(wr, http.StatusBadRequest, apiResp{false, "未保存：" + err.Error()})
		return
	}

	msg := "配置已保存并生效"
	if next.ConfigFile == "" {
		// 纯内存模式（显式关闭持久化，或没挂数据卷时自动降级）：这不是错误，如实说明即可
		msg = "配置已在内存中生效（当前为纯内存模式，不写文件；重启进程后回到环境变量配置）"
	} else if err := savePersistedConfig(next); err != nil {
		log.Printf("警告: 配置持久化失败: %v", err)
		msg = "配置已在内存中生效，但写入文件失败：" + err.Error()
	}
	w.store.Update(func(c *Config) { *c = next })
	log.Printf("远程操作：配置已更新（%s）", msg)

	if next.WebPort != cur.WebPort || next.WebListen != cur.WebListen {
		msg += fmt.Sprintf("；HTTP 监听改为 %s，需重启看门狗进程后生效",
			net.JoinHostPort(next.WebListen, strconv.Itoa(next.WebPort)))
		if ip := net.ParseIP(next.WebListen); ip != nil && ip.IsLoopback() {
			msg += "。注意：监听 127.0.0.1 时容器外将无法访问，重启后可能把自己关在门外"
		}
	}
	if next.DeviceIP != cur.DeviceIP || next.MiPort != cur.MiPort || next.DeviceToken != cur.DeviceToken {
		msg += "；插板连接将在下个循环重建"
	}
	if cur.webPasswordFromEnv && next.WebPasswordHash != cur.WebPasswordHash {
		msg += "；注意：启动时由 WEB_PASSWORD 环境变量指定了访问密码，它的优先级更高，重启后仍会用环境变量里的密码"
	}
	if next.WebAuthDisabled && !cur.WebAuthDisabled {
		msg += "；注意：访问鉴权已关闭（该状态会持久化，重启后保持关闭）"
	}
	writeJSON(wr, http.StatusOK, apiResp{true, msg})
}

const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>光猫看门狗·远程管理</title>
<style>
/* 跟随系统主题：默认浅色，系统为深色时自动切换；所有颜色统一走 CSS 变量 */
:root{color-scheme:light dark;--bg:#f6f8fa;--panel:#ffffff;--line:#d0d7de;--fg:#1f2328;--dim:#59636e;--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;--ok:#3fb950;--warn:#d29922;--bad:#f85149}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,Consolas,'Courier New',monospace;padding:16px}
h1{font-size:18px;margin:0 0 4px}
.sub{color:var(--dim);font-size:12px;margin:0 0 12px}
.tabs{display:flex;gap:8px;margin-bottom:12px}
.tab{background:var(--panel);border:1px solid var(--line);color:var(--dim);border-radius:6px;padding:6px 18px;cursor:pointer;font-size:14px}
.tab.active{color:var(--fg);border-color:var(--dim)}
.view{display:none}.view.active{display:block}
#status{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.badge{border:1px solid var(--line);border-radius:6px;padding:4px 10px;font-size:13px;background:var(--panel)}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.bar{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-bottom:8px;font-size:13px;color:var(--dim)}
button{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:4px 12px;cursor:pointer}
button:hover{border-color:var(--dim)}
a{color:var(--dim)}
.term{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;margin:0 0 14px;overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:12.5px;line-height:1.5}
#log{height:60vh}
#actlog{height:200px}
.ctlgrid{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}
.ctlgrid button{padding:10px 18px;font-size:14px;border-radius:8px}
.danger{border-color:var(--bad);color:var(--bad)}
fieldset{border:1px solid var(--line);border-radius:8px;margin:0 0 14px;padding:12px}
legend{padding:0 8px;color:var(--dim);font-size:13px}
label.row{display:flex;align-items:center;gap:8px;margin:7px 0;font-size:13px;flex-wrap:wrap}
label.row>span:first-child{width:170px;color:var(--dim)}
input{background:var(--bg);border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:6px 10px;font-family:inherit;width:220px}
input:focus{outline:none;border-color:var(--dim)}
input[type=checkbox]{width:auto}
form button[type=submit]{padding:9px 28px;font-size:14px}
#cfgmsg{white-space:pre-wrap;color:var(--dim);font-size:13px;margin-top:8px}
</style>
</head>
<body>
<h1>光猫看门狗·远程管理</h1>
<p class="sub">运行在服务器/容器内，通过米家智能插板控制光猫电源。日志仅存于内存（环形缓冲，不落盘），配置保存于配置文件，删除该文件即恢复出厂；管理页用户名固定 admin。</p>
<div class="tabs">
<button class="tab active" id="tab-log" onclick="showTab('log')">日志</button>
<button class="tab" id="tab-ctl" onclick="showTab('ctl')">控制</button>
<button class="tab" id="tab-cfg" onclick="showTab('cfg')">配置</button>
</div>

<div id="view-log" class="view active">
  <div id="status">加载中...</div>
  <div class="bar">
    <button onclick="refresh(1)">立即刷新</button>
    <label><input type="checkbox" id="auto" checked> 每 2 秒自动刷新</label>
    <span id="logmeta"></span>
    <a href="/log" target="_blank">原始日志 /log</a>
    <a href="/status" target="_blank">状态 JSON /status</a>
  </div>
  <pre class="term" id="log">加载中...</pre>
</div>

<div id="view-ctl" class="view">
  <p class="sub">操作由主循环执行，页面本身不会因此卡住（Web 服务在独立协程里）；断电重启光猫会让网络中断约 1–3 分钟。<br>
  同一时刻只允许一个任务：正在执行动作时再点按钮会返回"已有任务在执行"。</p>
  <div class="ctlgrid">
    <button onclick="doAction('clear_fatal',null)">清除熔断状态</button>
    <button class="danger" onclick="doAction('restart_self','确定重启看门狗进程吗？几秒后自动恢复。')">重启看门狗进程</button>
    <button class="danger" onclick="doAction('reboot_modem','确定断电重启光猫吗？网络会中断约 1–3 分钟。')">断电重启光猫</button>
    <button class="danger" onclick="doAction('power_on','确定打开插板电源吗？')">恢复插板供电</button>
    <button class="danger" onclick="doAction('factory_reset','恢复出厂将删除运行时配置文件并重启进程，配置回到 compose 里的环境变量，访问密码也可能随之改变。确定继续吗？')">恢复出厂设置</button>
  </div>
  <pre class="term" id="actlog">操作结果会显示在这里（也同步记录到日志页）。</pre>
</div>

<div id="view-cfg" class="view">
  <form id="cfgform" onsubmit="return saveCfg(event)">
    <fieldset><legend>插板 miIO（保存后主循环重建连接并重新握手）</legend>
      <label class="row"><span>插板 IP</span><input name="device_ip" maxlength="15"></label>
      <label class="row"><span>Token</span><input name="device_token" maxlength="32" id="device_token"></label>
      <label class="row"><span>siid / piid</span><input name="siid" type="number" min="0" max="9999" style="width:90px"> <input name="piid" type="number" min="0" max="9999" style="width:90px"></label>
      <label class="row"><span>设备端口</span><input name="mi_port" type="number" min="1" max="65535"></label>
    </fieldset>
    <fieldset><legend>网络检测</legend>
      <label class="row"><span>Ping 目标 1</span><input name="ping_ip1" maxlength="15"></label>
      <label class="row"><span>Ping 目标 2</span><input name="ping_ip2" maxlength="15"></label>
      <label class="row"><span>检测间隔</span><input name="ping_interval" placeholder="15s"></label>
      <label class="row"><span>单次超时</span><input name="ping_timeout" placeholder="2s"></label>
    </fieldset>
    <fieldset><legend>看门狗（时长支持 15s / 10m / 600 三种写法；留空表示保持不变）</legend>
      <label class="row"><span>断网阈值</span><input name="offline_threshold" placeholder="10m"></label>
      <label class="row"><span>重启冷却</span><input name="reboot_cooldown" placeholder="2m"></label>
      <label class="row"><span>断电时长</span><input name="reboot_off_time" placeholder="10s"></label>
      <label class="row"><span>miIO 重试间隔</span><input name="miio_retry_interval" placeholder="1m"></label>
      <label class="row"><span>最大连续重启次数</span><input name="max_reboot_attempts" type="number" min="1" max="10" style="width:90px"></label>
      <label class="row"><span></span><span style="color:var(--dim)">判定规则：连续 2 次探测失败才判定断网；网络恢复后需连续在线满 5 分钟才清零"重启计数 / 熔断"；每次触发重启都计数（含未完成的动作）。</span></label>
    </fieldset>
    <fieldset><legend>Web 访问</legend>
      <label class="row"><span>访问密码</span><input name="web_password" type="password" maxlength="64" placeholder="留空保持不变"></label>
      <label class="row"><span></span><span><input type="checkbox" name="clear_web_password" value="1"> 关闭鉴权（该状态会持久化，重启后仍保持关闭；服务对外暴露时应保留密码）</span></label>
      <label class="row"><span>HTTP 端口</span><input name="web_port" type="number" min="1" max="65535" style="width:90px">（重启进程后生效）</label>
      <label class="row"><span>监听地址</span><input name="web_listen" maxlength="45" placeholder="留空=所有接口"></label>
      <label class="row"><span>配置文件</span><span id="cfgfile" style="color:var(--dim)"></span></label>
    </fieldset>
    <button type="submit">保存配置</button>
  </form>
  <div id="cfgmsg"></div>
</div>

<script>
function badge(t,c){return '<span class="badge '+c+'">'+t+'</span>'}
// 动作名 → 中文（key 与固件版完全一致，两版前端共用同一张表）
const ACT={reboot_modem:'断电重启光猫',power_on:'恢复插板供电',restart_esp:'重启控制器',
           restart_self:'重启看门狗进程',factory_reset:'恢复出厂',apply_wifi:'切换 WiFi'};
function dur(s){s=Number(s)||0;const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);let t=m+'分钟';if(h||d)t=h+'小时'+t;if(d)t=d+'天'+t;return t}
function showTab(n){
  for(const v of document.querySelectorAll('.view'))v.classList.remove('active');
  for(const t of document.querySelectorAll('.tab'))t.classList.remove('active');
  document.getElementById('view-'+n).classList.add('active');
  document.getElementById('tab-'+n).classList.add('active');
  if(n==='cfg')loadCfg();
}
let lastSeq=0, logFull=true;
const LOG_VIEW_MAX=512*1024;   // 前端最多保留这么多日志文本，避免 DOM 无限增长
async function refresh(force){
  try{
    const s=await(await fetch('/status')).json();
    // 只在有新日志时才拉取，并且只拉增量（since = 上次拿到的版本号）。
    // 缓冲被写满覆盖时服务端会回 X-Log-Reset: 1，表示这是全量、需要整体替换。
    if(force||logFull||lastSeq!==s.logSeq){
      const r=await fetch('/log?since='+lastSeq,{cache:'no-store'});
      const reset=r.headers.get('X-Log-Reset')==='1';
      const t=await r.text();
      const pre=document.getElementById('log');
      const stick=pre.scrollTop+pre.clientHeight>=pre.scrollHeight-40;
      if(force||reset||logFull){
        pre.textContent=t||'(暂无日志)';
        logFull=false;
      }else{
        pre.textContent+=t;
        if(pre.textContent.length>LOG_VIEW_MAX){
          const keep=pre.textContent.slice(-Math.floor(LOG_VIEW_MAX*0.75));
          const nl=keep.indexOf('\n');
          pre.textContent='…（较早日志已省略）\n'+(nl>=0?keep.slice(nl+1):keep);
        }
      }
      if(stick)pre.scrollTop=pre.scrollHeight;
      lastSeq=s.logSeq;
    }
    document.getElementById('status').innerHTML=
      badge('运行 '+dur(s.uptime),'ok')+
      badge(s.online?(s.rebooting?'重启冷却中':'外网正常'):('断网 '+dur(s.linkDown)),
            s.online?(s.rebooting?'warn':'ok'):'warn')+
      badge('miIO '+(s.miio?'正常':'异常'),s.miio?'ok':'bad')+
      badge('重启 '+s.reboots+'/'+s.maxReboots,s.reboots>0?'warn':'ok')+
      badge(s.fatal?'已熔断 · 需人工介入':'看门狗待命',s.fatal?'bad':'ok')+
      (s.pending?badge('任务执行中（'+(ACT[s.pending]||s.pending)+'）','warn'):'')+
      (s.auth?'':badge('未设置访问密码','bad'));
    document.getElementById('logmeta').textContent='缓冲 '+s.logUsed+' / '+s.logTotal+' 字节';
  }catch(e){
    document.getElementById('status').innerHTML=badge('服务无响应（可能进程正在重启或执行任务）','bad');
  }
}
async function doAction(a,confirmText){
  if(confirmText&&!confirm(confirmText))return;
  const body=new URLSearchParams({action:a});
  if(confirmText)body.set('confirm','1');
  try{
    const j=await(await fetch('/api/control',{method:'POST',body,headers:{'X-Requested-With':'watchdog'}})).json();
    const el=document.getElementById('actlog');
    el.textContent=(new Date().toLocaleTimeString()+'  '+j.msg+'\n')+el.textContent;
    if(a!=='clear_fatal')setTimeout(refresh,800);
  }catch(e){
    const el=document.getElementById('actlog');
    el.textContent=(new Date().toLocaleTimeString()+'  请求失败（服务可能正忙）\n')+el.textContent;
  }
}
async function loadCfg(){
  try{
    const c=await(await fetch('/api/config')).json();
    const f=document.getElementById('cfgform');
    f.device_ip.value=c.deviceIp||'';
    f.device_token.value='';
    f.device_token.placeholder=c.hasToken?'已设置，留空保持不变':'未设置（32位十六进制）';
    f.siid.value=c.siid;f.piid.value=c.piid;f.mi_port.value=c.miPort;
    f.ping_ip1.value=c.ping1||'';f.ping_ip2.value=c.ping2||'';
    f.ping_interval.value=c.pingInterval||'';
    f.ping_timeout.value=c.pingTimeout||'';
    f.offline_threshold.value=c.offlineThreshold||'';
    f.reboot_cooldown.value=c.rebootCooldown||'';
    f.reboot_off_time.value=c.rebootOffTime||'';
    f.miio_retry_interval.value=c.miioRetry||'';
    f.max_reboot_attempts.value=c.maxReboots;
    f.web_port.value=c.webPort;f.web_listen.value=c.webListen||'';
    document.getElementById('cfgfile').textContent=c.configFile||'（纯内存模式：不写文件，重启后回到环境变量配置）';
    f.clear_web_password.checked=false;f.web_password.value='';
  }catch(e){document.getElementById('cfgmsg').textContent='配置读取失败';}
}
async function saveCfg(ev){
  ev.preventDefault();
  const f=document.getElementById('cfgform');
  const body=new URLSearchParams(new FormData(f));
  try{
    const j=await(await fetch('/api/config',{method:'POST',body,headers:{'X-Requested-With':'watchdog'}})).json();
    document.getElementById('cfgmsg').textContent=j.msg||'';
    if(j.ok){loadCfg();}
  }catch(e){document.getElementById('cfgmsg').textContent='请求失败';}
  return false;
}
refresh();
setInterval(()=>{if(document.getElementById('auto').checked&&document.getElementById('view-log').classList.contains('active'))refresh()},2000);
</script>
</body>
</html>
`
