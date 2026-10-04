#include <WiFi.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <ESP32Ping.h>
#include <Preferences.h>
#include <stdarg.h>
#include "mbedtls/md5.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

// ★ 注意：Arduino 会把所有函数的原型自动插到"第一个函数定义之前"。
//   因此凡是在函数签名里出现的自定义类型，都必须在那之前已经声明，
//   否则自动生成的原型会因为类型未声明而编译失败。
//   这里用 C++11 的枚举前向声明，完整定义见下方 miIO 协议区。
enum MiioReply : int;
enum PendingAction : int;

// ==================== 配置区域（默认值） ====================
// 以下均为"默认值"，启动时由 NVS（非易失存储）里已保存的配置覆盖，NVS 为空才用这里的值。
// 远程修改入口：浏览器访问 http://<设备IP>/ → 配置页（推荐，避免把口令写进源码）。
// ⚠️ 下面几行是明文硬编码的 WiFi 口令 / Token（Web 访问密码不在此列，它只存 SHA-256）。
//    本仓库已将其留空；填写后**切勿提交或分享本文件**。
// ⚠️ WIFI_SSID / WIFI_PASSWORD 是"首次烧录前必须填好"的：设备没有 AP 配网兜底，
//    连不上 WiFi 就一直停在重连循环里，配置页自然也打不开，只能重新烧录。
char WIFI_SSID[33]     = "wifissid";   // ← 你的 WiFi 名（首次烧录前必须填写，见下方说明）
char WIFI_PASSWORD[65] = "password";   // ← 你的 WiFi 口令
char DEVICE_IP[16]     = "192.168.0.88";                      // ← 插板的局域网 IP（必须 IPv4）
char DEVICE_TOKEN[33]  = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";  // ← 从米家提取的 Token（32 位十六进制）

// MIoT 属性 ID (根据你的设备型号修改，常见插座为 siid=2, piid=1；范围 1~9999，不允许 0)
int SIID = 2;
int PIID = 1;

// Ping 目标
char PING_IP1[16] = "223.5.5.5";
char PING_IP2[16] = "8.8.8.8";

// 时间参数（默认值，单位毫秒；配置页里用 "15s" / "10m" / "600" 三种写法均可编辑）
unsigned long PING_INTERVAL       = 15000;   // 15 秒检测一次（5~3600 秒）
unsigned long OFFLINE_THRESHOLD   = 600000;  // 连续 10 分钟断网（30~86400 秒）
unsigned long REBOOT_COOLDOWN     = 120000;  // 重启后冷却 2 分钟（10~3600 秒）
unsigned long REBOOT_OFF_TIME     = 10000;   // 插板断电时长（5~120 秒，已实测 10 秒足够）
unsigned long WIFI_RETRY_INTERVAL = 10000;   // WiFi 重连间隔（3~600 秒）
unsigned long MIIO_RETRY_INTERVAL = 60000;   // miIO 异常后的重新握手间隔（5~3600 秒）
const unsigned long LED_BLINK_INTERVAL  = 500;     // LED 闪烁周期
const unsigned long LED_FAST_INTERVAL   = 150;     // LED 熔断告警快闪周期
const unsigned long MIIO_ACK_TIMEOUT    = 2000;    // 等待设备确认一条命令的时间
const uint8_t       PING_TIMEOUT_S      = 1;       // 单次 ping 超时（秒），固定 1 秒

// 稳定在线期：网络恢复后不立即清零重启计数/熔断，必须"连续在线满 5 分钟"才清零。
// 编译期常量，不暴露到配置页。
const unsigned long ONLINE_STABLE_MS = 300000;

// 熔断：累计这么多次"触发重启动作"（无论动作是否真正完成）就停止自动动作，只告警等人工介入。
// 若无此限制，一旦 Ping 目标被运营商屏蔽，设备会每 12 分钟永久断电光猫一次。
int MAX_REBOOT_ATTEMPTS = 5;   // 1~10

// —— 远程管理（设备内置 Web 服务）——
// 浏览器访问 http://<设备IP>/（默认端口 80，可在配置页改为 1~65535）：
//   日志页  /log 纯文本日志，/status JSON 状态
//   控制页  断电重启光猫 / 恢复供电 / 清除熔断 / 重启控制器
//   配置页  WiFi / 插板 / 看门狗参数 / Web 访问（保存于 NVS，断电不丢）
// 访问鉴权：HTTP Basic Auth，用户名固定 "admin"；密码只以 SHA-256 十六进制（64 字符）存 NVS。
//   下面的 "admin" 是编译期默认口令，仅在"首次运行且 NVS 尚无鉴权配置"时使用，日志会提示尽快修改。
//   在配置页勾选"清除密码"= 关闭鉴权，该状态同样持久化（重启后不会自动恢复成某个密码）。
// 页面为局域网明文 HTTP，请只在可信局域网使用。
const bool     WEB_ENABLED  = true;
uint16_t       WEB_PORT     = 80;      // 修改后需重启控制器生效
const size_t   LOG_BUF_SIZE = 16384;   // RAM 环形日志缓冲字节数（约存 200 条日志）
const char*    WEB_DEFAULT_PASSWORD = "admin";   // 首次运行的编译期默认口令
char           webPasswordHash[65] = "";         // SHA-256 十六进制；空 = 关闭鉴权
bool           authConfigured = false;           // 是否已显式配置过鉴权（区分"首次运行"与"已清除密码"）

// miIO 常量
const uint16_t MI_PORT    = 54321;   // 目标端口（设备监听）
const uint16_t LOCAL_PORT = 0;       // 本地端口，0 = 由 lwIP 随机分配
const int      MIIO_REQUEST_ID = 1;  // 所有命令固定用 id=1；响应里的 "id" 必须与它一致才算有效

// LED 指示灯（ESP32-C3）
// 默认 GPIO8（C3 板载 LED 的常用引脚）。若你的板子灯不亮，可在此显式定义 LED_PIN，
// 或改用 RGB_BUILTIN + neopixelWrite()（WS2812 板型，digitalWrite 驱动不了）。
#ifndef LED_PIN
#define LED_PIN 8
#endif

// BOOT 键引脚（开机长按 5 秒恢复出厂配置）：ESP32-C3 = GPIO9
#define BOOT_BTN_PIN 9

#define LED_ON  LOW
#define LED_OFF HIGH

// 缓冲区上限（miIO payload 一般 < 100 字节，512 足够）
const size_t MAX_BUF = 512;

// 全局变量
WiFiUDP udp;
Preferences prefs;                 // NVS 配置存储
uint32_t deviceId = 0;
uint32_t stamp    = 0;

// 解析后的 Token（只解析一次，供握手校验与命令 checksum 复用）
uint8_t deviceToken[16];
bool    tokenValid = false;

// 看门狗状态
unsigned long lastPingTime  = 0;
// ★ 断网计时不再和 WiFi 状态挂钩。
//   linkDownSince = 0 表示"当前外网可达"，非 0 表示"从该时刻起外网不可达"。
//   WiFi 断开/重连、握手成功，一律不允许修改它，否则 WiFi 抖动会把计时反复清零，
//   10 分钟阈值永远达不到，看门狗静默失效。
unsigned long linkDownSince = 0;
bool          rebooting     = false;
unsigned long rebootTime    = 0;
int           pingFailStreak = 0;      // 连续 ping 检测失败次数（满 2 次才开始断网计时，防单次抖动误判）
unsigned long onlineSince    = 0;      // 稳定在线计时起点（0 = 尚未确认连续在线）

// 熔断 / 硬故障状态
//   fatalLatched：累计"触发重启动作"达到上限 → 停止自动动作，只观察等人工介入
//   powerFault  ：上电命令未得到确认等硬故障（需要人工介入）
//   LED 快闪条件统一为 fatalLatched || powerFault（见 fatalActive()）
int  rebootAttempts = 0;      // 已触发重启动作的次数（无论动作是否真正完成）
bool fatalLatched   = false;  // 熔断锁存：停止自动重启，只观察
bool powerFault     = false;  // 硬故障（上电未确认 / Token 无效）
bool miioOK         = false;  // miIO 是否正常（独立状态，不再用 LED 反推）

// WiFi 重连状态
unsigned long lastWifiRetry    = 0;
bool          wifiWasConnected = false;
unsigned long wifiDownSince    = 0;   // 仅用于诊断日志（0 = 当前已连接）

// LED 闪烁状态
// 优先级：硬故障/熔断快闪 > miIO 错误常亮 > WiFi 慢闪 > 熄灭
unsigned long lastLedToggle = 0;
bool          ledBlinking   = false;   // 慢闪（WiFi 未连接）
bool          ledError      = false;   // 常亮（miIO 握手/命令失败）
bool          ledState      = false;

unsigned long lastMiioCheck = 0;

// ==================== 远程控制：单槽控制标志（忙时返回 409）====================
// HTTP handler 只置标志位（避免在网络回调里执行秒级阻塞操作），主循环 loop() 每轮检查并执行；
// 同一时刻只允许一个动作占用，占用期间新的请求一律返回 409。
enum PendingAction : int {
    PA_NONE = 0,
    PA_REBOOT_MODEM,   // 断电重启光猫（完整断电→等待→上电流程）
    PA_POWER_ON,       // 恢复插板供电（补救用）
    PA_RESTART_ESP,    // 重启控制器自身
    PA_FACTORY_RESET   // 清除全部 NVS 配置并重启（回到文件里的默认值）
};
PendingAction pendingAction = PA_NONE;

// ==================== 非阻塞状态机：WiFi 切换 / 断电重启 ====================
// 这两件事以前在 Web handler / loop 里整段阻塞（最多 20 秒），浏览器收不到响应；
// 且 WiFi.disconnect() 会掐断与浏览器的 TCP 连接（旧版"切换 WiFi 后页面永远转圈"的根因）。
// 现统一改为主循环分步推进，等待阶段照常处理 Web 请求与 LED。
// 详细流程见下方各自的"状态机"注释块。
enum WifiSwitchPhase : int { WF_IDLE = 0, WF_TRYING, WF_ROLLBACK };
WifiSwitchPhase wifiSwitchPhase = WF_IDLE;
unsigned long   wifiSwitchArmAt = 0;      // 到点才真正断开（先给 HTTP 响应留出发送时间）
unsigned long   wifiSwitchStart = 0;      // 试连开始时刻（20 秒超时从此算）
char            wifiNewSsid[33] = {0};
char            wifiNewPass[65] = {0};

enum RebootPhase : int { RB_IDLE = 0, RB_HANDSHAKE, RB_POWER_OFF, RB_WAIT_OFF, RB_POWER_ON };
RebootPhase   rebootPhase      = RB_IDLE;
bool          rebootFromManual = false;
unsigned long rebootPhaseStart = 0;
unsigned long rebootLastTry    = 0;     // 命令重试节流时间戳
int           rebootTry        = 0;     // 当前阶段已尝试次数（最多 3）
bool          rebootOffOK      = false; // 断电是否得到设备确认

// ==================== 远程日志：环形缓冲 + 双写 ====================
// 实现说明：
//   - 所有 logPrintf / logPrint / logPrintln 都"串口 + RAM 环形缓冲"双写，
//     串口行为与旧版一致，另外每行自动加 [运行秒.毫秒] 时间戳前缀。
//   - 环形缓冲只保留最近 LOG_BUF_SIZE 字节，写满后自动覆盖最旧内容；
//     日志仅存于 RAM，设备断电/复位即清空（写 flash 会磨损芯片，故不做持久化）。
//   - 单线程 loop 架构：Web 应答与日志写入都在同一 loop 线程，无需加锁。
static char   logBuf[LOG_BUF_SIZE];   // 环形缓冲
static size_t logHead = 0;            // 下一个写入位置
static size_t logLen  = 0;            // 有效字节数
static bool   logAtLineStart = true;  // 行首标记（用于打时间戳）
uint32_t      logSeqCounter  = 0;     // 日志版本号：每次写日志自增（单调递增，不能再用环形下标当版本号）

// 注意：这里按默认端口构造，真正的监听端口由 webServerSetup() 里的 begin(WEB_PORT) 指定，
// 因为 WEB_PORT 的值要等 setup() 中 loadConfig() 从 NVS 读出后才确定（不能依赖构造参数）。
WebServer webServer;
uint16_t  activeWebPort = WEB_PORT;   // 当前实际监听的端口（供状态页显示）
bool      webReady = false;           // Web 服务是否已启动（loop 里据此决定是否轮询）

void handleRoot();         // Web 路由前置声明
void handleLog();
void handleStatus();
void handleControl();
void handleConfigGet();
void handleConfigSave();
void webServerSetup();
bool checkAuth();          // 鉴权（Basic Auth + SHA-256 口令比对）
bool checkCSRF();          // 写操作的防跨站校验（自定义请求头）
void loadConfig();         // NVS 配置
bool saveConfig();         // 写 NVS；返回 false = 保存失败（NVS 不可写）
bool factoryReset();       // 清 NVS；返回 false = 清除失败
void handlePendingAction();
void checkFactoryResetButton();   // BOOT 键长按恢复出厂（运行期检测）
// 日志双写（Arduino 自动原型生成之外的手动保险）
void logAppendChar(char c);
void logWrite(const char* s);
void logPrintf(const char* fmt, ...);
void logPrint(const char* s);
void logPrint(const String& s);
void logPrintln();
void logPrintln(const char* s);
void logPrintln(const String& s);
// miIO / 看门狗（跨区块调用，手动声明）
bool miio_handshake();
bool miio_setPower(bool on);
MiioReply miio_setPowerTry(bool on);
MiioReply miio_send_command(const char* method, const char* paramsJson, char* detail, size_t detailSize);
// ★ 默认参数值必须写在这里（手写声明区），函数定义处不再重复：
//   arduino-cli 不会为"带默认参数的函数"生成自动原型，靠调用顺序侥幸通过属于隐患。
void miio_drain_response(unsigned long quietMs = 200, unsigned long hardLimitMs = 1500);
// 新增工具 / 状态机（跨区块调用）
bool parseToken();                    // 严格逐字符解析 DEVICE_TOKEN → deviceToken[16]
bool parseDurationSeconds(const String& raw, unsigned long& outSec);   // "15s" / "10m" / "600"
bool parseIPv4(const String& s, int out[4]);
bool validIP(const String& s);
bool validPingTarget(const String& s);   // 严格 IPv4，且拒绝 0.0.0.0 / 127.0.0.0/8 / 插板自身
void sha256_hex(const char* input, size_t len, char* out64);
bool fatalActive();                   // 熔断 / 硬故障 → LED 快闪
void setMiioState(bool ok);           // miIO 状态的唯一入口（同步 LED）
void clearFatalState(const char* reason);
void saveRuntimeState();              // 熔断状态/重启计数/powerFault 落盘（低频）
void rebootStart(bool fromManual);    // 启动非阻塞断电重启状态机
void rebootStep();                    // 主循环分步推进重启
void wifiSwitchStep();                // 主循环分步推进 WiFi 切换
bool controlBusy();                   // 单槽控制标志是否被占用（忙时 HTTP 返回 409）
const char* controlActionName();      // /status 的 pending 字段：动作名（空闲为空串）

// 追加一个字节进环形缓冲（写满自动覆盖最旧内容）
void logAppendChar(char c) {
    logBuf[logHead] = c;
    logHead = (logHead + 1) % LOG_BUF_SIZE;
    if (logLen < LOG_BUF_SIZE) logLen++;
}

// 核心双写：串口 + 环形缓冲；行首自动加时间戳，空行不加
void logWrite(const char* s) {
    if (s == nullptr || *s == '\0') return;
    logSeqCounter++;   // 日志版本号单调递增（/status 的 logSeq 用它，页面据此判断有无新日志）

    while (*s) {
        if (*s == '\n') {                 // 换行原样写，并回到行首状态
            Serial.print('\n');
            logAppendChar('\n');
            logAtLineStart = true;
            s++;
            continue;
        }
        if (logAtLineStart) {             // 行首（且非换行）→ 打时间戳
            char ts[20];
            unsigned long ms = millis();
            snprintf(ts, sizeof(ts), "[%lu.%03lu] ", ms / 1000, ms % 1000);
            Serial.print(ts);
            for (const char* p = ts; *p; ++p) logAppendChar(*p);
            logAtLineStart = false;
        }
        // 一次性写到行尾/结尾，减少串口调用次数
        const char* nl = strchr(s, '\n');
        size_t n = nl ? (size_t)(nl - s) : strlen(s);
        Serial.write((const uint8_t*)s, n);
        for (size_t i = 0; i < n; i++) logAppendChar(s[i]);
        s += n;
    }
}

// printf 风格（替代 Serial.printf）
void logPrintf(const char* fmt, ...) {
    char buf[384];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    logWrite(buf);
}

void logPrint(const char* s)     { logWrite(s); }
void logPrint(const String& s)   { logWrite(s.c_str()); }
void logPrintln()                { logWrite("\n"); }
void logPrintln(const char* s)   { logWrite(s); logWrite("\n"); }
void logPrintln(const String& s) { logWrite(s.c_str()); logWrite("\n"); }

// ==================== 配置存储（NVS） ====================
// NVS 只在"保存配置"和"恢复出厂"时写入，写入频率极低，不会磨损 flash。
// 键名一览（NVS 键名上限 15 字符）：
//   wifi_ssid / wifi_pass / dev_ip / dev_token / ping1 / ping2
//   siid / piid / ping_itv / off_th / cooldown / reboot_off / wifi_retry / miio_retry
//   max_reboots / web_port / web_pass（SHA-256 十六进制，64 字符）/ auth_set
const char* NVS_NS = "watchdog";

// 是否为恰好 n 个十六进制字符（Token 与密码 hash 校验共用）
bool isHexN(const char* s, size_t n) {
    if (s == nullptr || strlen(s) != n) return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

void loadConfig() {
    if (!prefs.begin(NVS_NS, true)) {   // 只读打开
        logPrintln("!!! NVS 打开失败，本次改用文件里的默认配置 !!!");
        return;
    }
    prefs.getString("wifi_ssid", WIFI_SSID, sizeof(WIFI_SSID));
    prefs.getString("wifi_pass", WIFI_PASSWORD, sizeof(WIFI_PASSWORD));
    prefs.getString("dev_ip",    DEVICE_IP, sizeof(DEVICE_IP));
    prefs.getString("dev_token", DEVICE_TOKEN, sizeof(DEVICE_TOKEN));
    prefs.getString("ping1",     PING_IP1, sizeof(PING_IP1));
    prefs.getString("ping2",     PING_IP2, sizeof(PING_IP2));
    SIID              = prefs.getInt("siid", SIID);
    PIID              = prefs.getInt("piid", PIID);
    PING_INTERVAL     = prefs.getULong("ping_itv", PING_INTERVAL);
    OFFLINE_THRESHOLD = prefs.getULong("off_th", OFFLINE_THRESHOLD);
    REBOOT_COOLDOWN   = prefs.getULong("cooldown", REBOOT_COOLDOWN);
    REBOOT_OFF_TIME   = prefs.getULong("reboot_off", REBOOT_OFF_TIME);
    WIFI_RETRY_INTERVAL = prefs.getULong("wifi_retry", WIFI_RETRY_INTERVAL);
    MIIO_RETRY_INTERVAL = prefs.getULong("miio_retry", MIIO_RETRY_INTERVAL);
    MAX_REBOOT_ATTEMPTS = prefs.getInt("max_reboots", MAX_REBOOT_ATTEMPTS);
    WEB_PORT            = prefs.getUShort("web_port", WEB_PORT);

    // 熔断状态与重启计数（运行时状态也持久化）：设备复位/断电重启不该成为"绕过熔断"的手段，
    // 否则一次复位就能重新对光猫连开 MAX_REBOOT_ATTEMPTS 次断电。
    // 写入只在状态变化时发生（低频），不会磨损 flash。
    fatalLatched   = prefs.getBool("fatal", false);
    rebootAttempts = prefs.getInt("reboot_cnt", 0);
    powerFault     = prefs.getBool("power_fault", false);

    // 访问密码：NVS 里只存 SHA-256 十六进制（64 字符），不再存明文
    char stored[65] = {0};
    prefs.getString("web_pass", stored, sizeof(stored));
    authConfigured = (prefs.getUChar("auth_set", 0) != 0);
    if (isHexN(stored, 64)) {
        strlcpy(webPasswordHash, stored, sizeof(webPasswordHash));
        authConfigured = true;
    } else if (stored[0] != '\0') {
        // 旧版固件在 NVS 里存的是明文口令：升级为 SHA-256（下次保存配置时落盘）
        sha256_hex(stored, strlen(stored), webPasswordHash);
        authConfigured = true;
        logPrintln("检测到旧版明文访问密码，已在内存中转换为 SHA-256（下次保存配置时写入 NVS）");
    } else if (!authConfigured) {
        // 首次运行且 NVS 里没有任何鉴权配置 → 使用编译期默认口令
        sha256_hex(WEB_DEFAULT_PASSWORD, strlen(WEB_DEFAULT_PASSWORD), webPasswordHash);
        logPrintf("首次运行：使用编译期默认访问口令 \"%s\"（用户名 admin），请尽快在配置页修改\n",
                  WEB_DEFAULT_PASSWORD);
    } else {
        webPasswordHash[0] = '\0';   // 曾显式"清除密码"→ 关闭鉴权，重启后不再自动启用
    }
    prefs.end();

    // 参数兜底：NVS 里可能残留越界的历史值，越界一律回落到默认值
    if (SIID < 1 || SIID > 9999) SIID = 2;
    if (PIID < 1 || PIID > 9999) PIID = 1;
    if (PING_INTERVAL < 5000UL || PING_INTERVAL > 3600000UL)         PING_INTERVAL = 15000;
    if (OFFLINE_THRESHOLD < 30000UL || OFFLINE_THRESHOLD > 86400000UL) OFFLINE_THRESHOLD = 600000;
    if (REBOOT_COOLDOWN < 10000UL || REBOOT_COOLDOWN > 3600000UL)   REBOOT_COOLDOWN = 120000;
    if (REBOOT_OFF_TIME < 5000UL || REBOOT_OFF_TIME > 120000UL)     REBOOT_OFF_TIME = 10000;
    if (WIFI_RETRY_INTERVAL < 3000UL || WIFI_RETRY_INTERVAL > 600000UL) WIFI_RETRY_INTERVAL = 10000;
    if (MIIO_RETRY_INTERVAL < 5000UL || MIIO_RETRY_INTERVAL > 3600000UL) MIIO_RETRY_INTERVAL = 60000;
    if (MAX_REBOOT_ATTEMPTS < 1 || MAX_REBOOT_ATTEMPTS > 10) MAX_REBOOT_ATTEMPTS = 5;
    if (rebootAttempts < 0 || rebootAttempts > 1000) rebootAttempts = 0;
}

// 写 NVS；返回 false = 保存失败（NVS 不可写），调用方必须把它如实写进 Web 响应文案
bool saveConfig() {
    if (!prefs.begin(NVS_NS, false)) {   // 读写打开
        logPrintln("!!! NVS 打开失败，配置未能保存（NVS 不可写） !!!");
        return false;
    }
    bool ok = true;

    // 字符串类：putString 返回的是字符串长度，空串本身就返回 0，
    // 所以要区分"值本来就是空"与"写入失败"，不能简单地把 0 当失败。
    const char* strKeys[]   = {"wifi_ssid", "wifi_pass", "dev_ip", "dev_token",
                               "ping1", "ping2", "web_pass"};
    const char* strValues[] = {WIFI_SSID, WIFI_PASSWORD, DEVICE_IP, DEVICE_TOKEN,
                               PING_IP1, PING_IP2, webPasswordHash};
    for (size_t i = 0; i < 7; i++) {
        size_t w = prefs.putString(strKeys[i], strValues[i]);
        if (w == 0 && strValues[i][0] != '\0') ok = false;
    }

    // 数值类：putXxx 返回写入字节数，0 = 失败
    if (prefs.putInt("siid", SIID) == 0)                       ok = false;
    if (prefs.putInt("piid", PIID) == 0)                       ok = false;
    if (prefs.putULong("ping_itv", PING_INTERVAL) == 0)        ok = false;
    if (prefs.putULong("off_th", OFFLINE_THRESHOLD) == 0)      ok = false;
    if (prefs.putULong("cooldown", REBOOT_COOLDOWN) == 0)      ok = false;
    if (prefs.putULong("reboot_off", REBOOT_OFF_TIME) == 0)    ok = false;
    if (prefs.putULong("wifi_retry", WIFI_RETRY_INTERVAL) == 0) ok = false;
    if (prefs.putULong("miio_retry", MIIO_RETRY_INTERVAL) == 0) ok = false;
    if (prefs.putInt("max_reboots", MAX_REBOOT_ATTEMPTS) == 0)  ok = false;
    if (prefs.putUShort("web_port", WEB_PORT) == 0)            ok = false;
    if (prefs.putUChar("auth_set", authConfigured ? 1 : 0) == 0) ok = false;

    prefs.end();
    if (!ok) logPrintln("!!! 部分配置写入 NVS 失败（NVS 不可写或空间不足） !!!");
    return ok;
}

// 清空本命名空间；返回 false = 清除失败（此时调用方不要重启，避免"以为恢复出厂却还是旧配置"）
bool factoryReset() {
    if (!prefs.begin(NVS_NS, false)) {
        logPrintln("!!! NVS 打开失败，未能清除配置 !!!");
        return false;
    }
    bool ok = prefs.clear();
    prefs.end();
    if (ok) {
        logPrintln("已清除全部保存在 NVS 的配置（恢复出厂默认值）");
    } else {
        logPrintln("!!! 清除 NVS 配置失败，原配置可能仍然保留 !!!");
    }
    return ok;
}

// ==================== Web 工具 ====================
// 鉴权：HTTP Basic Auth，用户名固定 "admin"，口令只以 SHA-256 十六进制存在 NVS（不存明文）。
// 为什么不用 webServer.authenticate(user, pass)：它需要拿明文口令去比对，而 NVS 里只有 hash；
// core 3.3.x 也没有提供 SHA-256 版本的 authenticate（只有 authenticateBasicSHA1）。
// webPasswordHash 为空 = 关闭鉴权；失败时发送 401（浏览器弹原生登录框），调用方直接 return。

// Base64 解码（严格：先剔除空白，只接受合法字符，长度必须是 4 的倍数）
// 返回解码字节数，失败返回 -1
int base64_decode(const char* in, uint8_t* out, size_t outSize) {
    if (in == nullptr) return -1;

    char clean[160];
    size_t cl = 0;
    for (const char* p = in; *p != '\0'; ++p) {
        if (*p == ' ' || *p == '\r' || *p == '\n' || *p == '\t') continue;
        if (cl >= sizeof(clean) - 1) return -1;   // 超长凭据：直接判失败，绝不静默截断后继续解码
        clean[cl++] = *p;
    }
    clean[cl] = '\0';
    if (cl == 0 || (cl % 4) != 0) return -1;

    size_t o = 0;
    for (size_t i = 0; i < cl; i += 4) {
        int v[4];
        int pad = 0;
        for (int k = 0; k < 4; k++) {
            char c = clean[i + k];
            if (c == '=') { v[k] = 0; pad++; continue; }
            if (pad > 0) return -1;             // '=' 之后不允许再出现数据字符
            if (c >= 'A' && c <= 'Z')      v[k] = c - 'A';
            else if (c >= 'a' && c <= 'z') v[k] = c - 'a' + 26;
            else if (c >= '0' && c <= '9') v[k] = c - '0' + 52;
            else if (c == '+')             v[k] = 62;
            else if (c == '/')             v[k] = 63;
            else return -1;
        }
        // 填充必须规范：最多 2 个 '='，且被填充位多出来的比特必须为 0
        if (pad > 2) return -1;
        if (pad == 2 && (v[1] & 0x0F) != 0) return -1;
        if (pad == 1 && (v[2] & 0x03) != 0) return -1;
        uint32_t trip = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
                        ((uint32_t)v[2] << 6)  |  (uint32_t)v[3];
        if (o >= outSize) return -1;
        out[o++] = (uint8_t)((trip >> 16) & 0xFF);
        if (pad < 2) { if (o >= outSize) return -1; out[o++] = (uint8_t)((trip >> 8) & 0xFF); }
        if (pad < 1) { if (o >= outSize) return -1; out[o++] = (uint8_t)(trip & 0xFF); }
    }
    return (int)o;
}

// 恒定时间比较（口令 hash 比对，避免按字节短路泄露信息）
bool hashEquals(const char* a, const char* b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < la; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

bool checkAuth() {
    if (webPasswordHash[0] == '\0') return true;      // 空 = 关闭鉴权

    String hdr = webServer.header("Authorization");
    const char* h = hdr.c_str();
    if (h != nullptr && strncasecmp(h, "Basic ", 6) == 0) {
        uint8_t raw[128];
        int n = base64_decode(h + 6, raw, sizeof(raw) - 1);
        if (n > 0) {
            raw[n] = '\0';
            char* colon = strchr((char*)raw, ':');
            if (colon != nullptr) {
                *colon = '\0';
                if (strcmp((char*)raw, "admin") == 0) {
                    char hash[65];
                    sha256_hex(colon + 1, strlen(colon + 1), hash);
                    if (hashEquals(hash, webPasswordHash)) return true;
                }
            }
        }
    }
    webServer.requestAuthentication();
    return false;
}

// 防 CSRF：只接受带自定义头 X-Requested-With 的写操作（控制/改配置）。
// 为什么必须加这一层：Basic Auth 的凭据由浏览器自动附加，恶意网页只要诱导你访问它，
// 就能用一条普通的跨站 POST 让插板断电（浏览器会替你带上凭据，服务端无法区分）。
// 而跨站 JS 想伪造自定义头，必须先发 CORS 预检请求；本服务不回应预检
// （无 CORS 头），预检失败后浏览器根本不会发出真正的请求，因此该头即可有效阻断。
bool checkCSRF() {
    if (webServer.header("X-Requested-With") == "watchdog") return true;
    webServer.send(403, "application/json; charset=utf-8",
                   "{\"ok\":false,\"msg\":\"缺少防跨站请求头，请在管理页面内操作\"}");
    return false;
}

// JSON 字符串转义（配置值可能含引号/反斜杠等）
String jsonEsc(const char* s) {
    String out;
    if (s == nullptr) return out;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (c == '"' || c == '\\')      { out += '\\'; out += c; }
        else if (c == '\n')             { out += "\\n"; }
        else if (c == '\r')             { /* 忽略 */ }
        else if ((uint8_t)c >= 0x20)    { out += c; }
    }
    return out;
}

// 严格 IPv4 解析：恰好 4 段，每段 1~3 位数字、0~255，且拒绝前导零（"01.1.1.1"）
// 前导零的写法存在八进制歧义，Go 版用 net.ParseIP 会拒绝，这里保持一致。
bool parseIPv4(const String& s, int out[4]) {
    int parts = 0;
    int start = 0;
    int len = (int)s.length();
    for (int i = 0; i <= len; i++) {
        if (i == len || s[i] == '.') {
            if (i == start) return false;        // 空段（如 "1..2" 或结尾点）
            if (i - start > 3) return false;     // 段超过 3 位
            if (i - start > 1 && s[start] == '0') return false;   // 前导零（八进制歧义）
            int v = 0;
            for (int j = start; j < i; j++) {
                if (s[j] < '0' || s[j] > '9') return false;   // 不用 isDigit()：负 char 传入属于未定义行为
                v = v * 10 + (s[j] - '0');
            }
            if (v > 255) return false;
            if (parts < 4) out[parts] = v;
            parts++;
            start = i + 1;
        }
    }
    return parts == 4;
}

bool validIP(const String& s) {
    int o[4];
    return parseIPv4(s, o);
}

// Ping 目标校验：必须是严格 IPv4，且拒绝 0.0.0.0、回环 127.0.0.0/8、以及插板自身 IP
// （否则会出现"ping 自己当作外网可达"或"永远 ping 不通"的假象）
bool validPingTarget(const String& s) {
    int o[4];
    if (!parseIPv4(s, o)) return false;
    if (o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] == 0) return false;   // 0.0.0.0
    if (o[0] == 127) return false;                                        // 127.0.0.0/8 回环
    if (s == DEVICE_IP) return false;                                     // 不能是插板自己
    return true;
}

// 32 位十六进制 Token 校验
bool validHex32(const String& s) {
    return isHexN(s.c_str(), 32);
}

// ==================== 远程日志：Web 路由 ====================
// 单页应用：日志 / 控制 / 配置三个标签页，每 2 秒拉取 /status 与 /log。
const char INDEX_HTML[] = R"rawliteral(<!DOCTYPE html>
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
label.row>span{width:150px;color:var(--dim)}
input{background:var(--bg);border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:6px 10px;font-family:inherit;width:240px}
input:focus{outline:none;border-color:var(--dim)}
input[type=checkbox]{width:auto}
form button[type=submit]{padding:9px 28px;font-size:14px}
#cfgmsg{white-space:pre-wrap;color:var(--dim);font-size:13px;margin-top:8px}
</style>
</head>
<body>
<h1>光猫看门狗·远程管理</h1>
<p class="sub">日志仅存于 RAM（环形缓冲，断电清空）；配置保存于设备 NVS，断电不丢。</p>
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
  <p class="sub">操作由主循环分步执行；断电重启光猫期间页面仍可访问，只是状态徽章会提示"正在执行"。<br>
  离线兜底：设备<b>运行中</b>按住 BOOT 键 5 秒可恢复出厂设置（开机瞬间按住无效——那会让 C3 进入 ROM 下载模式，程序不运行）。</p>
  <div class="ctlgrid">
    <button onclick="doAction('clear_fatal',null)">清除熔断状态</button>
    <button class="danger" onclick="doAction('restart_self','确定重启控制器吗？')">重启控制器</button>
    <button class="danger" onclick="doAction('power_on','确定打开插板电源吗？')">恢复插板供电</button>
    <button class="danger" onclick="doAction('reboot_modem','确定断电重启光猫吗？网络会中断约 1–3 分钟。')">断电重启光猫</button>
    <button class="danger" onclick="doAction('factory_reset','恢复出厂将清除 WiFi、插板、看门狗与访问密码的全部配置，并重启控制器。设备会改用文件里的默认 WiFi 与默认密码 admin，IP 可能变化，可能需要重新寻找设备。确定继续吗？')">恢复出厂设置</button>
  </div>
  <pre class="term" id="actlog">操作结果会显示在这里（也同步记录到日志页）。</pre>
</div>

<div id="view-cfg" class="view">
  <form id="cfgform" onsubmit="return saveCfg(event)">
    <fieldset><legend>WiFi（保存后立即响应；后台 20 秒内试连新 WiFi，成功才落盘，失败自动回退）</legend>
      <label class="row"><span>SSID</span><input name="wifi_ssid" maxlength="32" placeholder="留空 = 沿用当前 SSID"></label>
      <label class="row"><span>密码</span><input name="wifi_pass" type="password" maxlength="64" placeholder="留空 = 沿用当前口令"></label>
      <label class="row"><span></span><span style="color:var(--dim)">只改路由器密码时，SSID 留空即可。</span></label>
    </fieldset>
    <fieldset><legend>插板 miIO（保存后立即重新握手验证）</legend>
      <label class="row"><span>插板 IP</span><input name="dev_ip" maxlength="15"></label>
      <label class="row"><span>Token</span><input name="dev_token" maxlength="32" id="dev_token"></label>
      <label class="row"><span>siid / piid</span><input name="siid" type="number" min="1" max="9999" style="width:90px"> <input name="piid" type="number" min="1" max="9999" style="width:90px"></label>
    </fieldset>
    <fieldset><legend>看门狗参数（立即生效，同时存入 NVS；时长支持 15s / 10m / 600 三种写法，留空表示保持不变）</legend>
      <label class="row"><span>Ping 目标 1</span><input name="ping1" maxlength="15"></label>
      <label class="row"><span>Ping 目标 2</span><input name="ping2" maxlength="15"></label>
      <label class="row"><span>检测间隔</span><input name="ping_interval" placeholder="15s / 10m / 600"></label>
      <label class="row"><span>断网阈值</span><input name="offline_threshold" placeholder="10m / 600"></label>
      <label class="row"><span>重启冷却</span><input name="cooldown" placeholder="120s / 2m"></label>
      <label class="row"><span>插板断电时长</span><input name="reboot_off_time" placeholder="10s"></label>
      <label class="row"><span>miIO 重试间隔</span><input name="miio_retry_interval" placeholder="60s / 1m"></label>
      <label class="row"><span>WiFi 重连间隔（秒）</span><input name="wifi_retry" type="number" min="3" max="600"></label>
      <label class="row"><span>最大连续重启次数</span><input name="max_reboots" type="number" min="1" max="10"></label>
    </fieldset>
    <fieldset><legend>Web 访问</legend>
      <label class="row"><span>访问密码</span><input name="web_pass" type="password" maxlength="32" placeholder="留空保持不变（只存 SHA-256，不存明文）"></label>
      <label class="row"><span></span><span><input type="checkbox" name="clear_web_pass" value="1"> 清除密码（关闭鉴权，该状态重启后仍保持）</span></label>
      <label class="row"><span>HTTP 端口</span><input name="web_port" type="number" min="1" max="65535" style="width:110px">（重启控制器后生效）</label>
    </fieldset>
    <button type="submit">保存配置</button>
  </form>
  <div id="cfgmsg"></div>
</div>

<script>
function badge(t,c){return '<span class="badge '+c+'">'+t+'</span>'}
// 动作名 → 中文（key 与 Go 版完全一致，两版前端共用同一张表）
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
let lastSeq=-1;
async function refresh(force){
  try{
    const s=await(await fetch('/status')).json();
    // 日志没有新内容时不重复拉取 /log，省下每 2 秒数 KB 的传输与解析
    if(force||lastSeq!==s.logSeq){
      const t=await(await fetch('/log')).text();
      const pre=document.getElementById('log');
      const stick=pre.scrollTop+pre.clientHeight>=pre.scrollHeight-40;
      pre.textContent=t||'(暂无日志)';
      if(stick)pre.scrollTop=pre.scrollHeight;
      lastSeq=s.logSeq;
    }
    document.getElementById('status').innerHTML=
      badge('运行 '+dur(s.uptime),'ok')+
      badge(s.wifi?('WiFi 已连接 '+s.ip):'WiFi 断开',s.wifi?'ok':'bad')+
      badge('RSSI '+s.rssi+' dBm',s.rssi>=-70?'ok':(s.rssi>=-80?'warn':'bad'))+
      badge('miIO '+(s.miio?'正常':'异常'),s.miio?'ok':'bad')+
      badge(s.linkDown>0?('断网 '+dur(s.linkDown)):'外网正常',s.linkDown>0?'warn':'ok')+
      (s.rebooting?badge('重启冷却中','warn'):'')+
      badge('重启 '+s.reboots+'/'+s.maxReboots,s.reboots>0?'warn':'ok')+
      badge(s.fatal?'已熔断 · 需人工介入':'看门狗待命',s.fatal?'bad':'ok')+
      (s.pending?badge('任务执行中（'+(ACT[s.pending]||s.pending)+'）','warn'):'')+
      (s.auth?'':badge('未设置访问密码','bad'));
    document.getElementById('logmeta').textContent='缓冲 '+s.logUsed+' / '+s.logTotal+' 字节';
  }catch(e){
    document.getElementById('status').innerHTML=badge('设备无响应（可能 WiFi 断开、重启中或正在执行任务）','bad');
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
    el.textContent=(new Date().toLocaleTimeString()+'  请求失败（设备可能正忙）\n')+el.textContent;
  }
}
async function loadCfg(){
  try{
    const c=await(await fetch('/api/config')).json();
    const f=document.getElementById('cfgform');
    f.wifi_ssid.value=c.wifiSsid||'';
    f.wifi_pass.value='';
    f.dev_ip.value=c.deviceIp||'';
    f.dev_token.value='';
    f.dev_token.placeholder=c.hasToken?'已设置，留空保持不变':'未设置（32位十六进制）';
    f.siid.value=c.siid;f.piid.value=c.piid;
    f.ping1.value=c.ping1||'';f.ping2.value=c.ping2||'';
    f.ping_interval.value=c.pingInterval;f.offline_threshold.value=c.offlineThreshold;
    f.cooldown.value=c.rebootCooldown;f.reboot_off_time.value=c.rebootOffTime;
    f.miio_retry_interval.value=c.miioRetry;
    f.wifi_retry.value=c.wifiRetry;
    f.max_reboots.value=c.maxReboots;f.web_port.value=c.webPort;
    f.clear_web_pass.checked=false;f.web_pass.value='';
  }catch(e){document.getElementById('cfgmsg').textContent='配置读取失败';}
}
async function saveCfg(ev){
  ev.preventDefault();
  const f=document.getElementById('cfgform');
  const body=new URLSearchParams(new FormData(f));
  try{
    const j=await(await fetch('/api/config',{method:'POST',body,headers:{'X-Requested-With':'watchdog'}})).json();
    document.getElementById('cfgmsg').textContent=j.msg||'';
    // WiFi 正在切换时不立刻回读配置：此时旧 SSID 还没被替换，回读会让用户误以为没生效
    if(j.ok&&(j.msg||'').indexOf('正在切换 WiFi')<0){loadCfg();}
  }catch(e){document.getElementById('cfgmsg').textContent='请求失败';}
  return false;
}
refresh();
setInterval(()=>{if(document.getElementById('auto').checked&&document.getElementById('view-log').classList.contains('active'))refresh()},2000);
</script>
</body>
</html>
)rawliteral";

// 首页：管理页（日志 / 控制 / 配置）
void handleRoot() {
    if (!checkAuth()) return;
    webServer.send(200, "text/html; charset=utf-8", INDEX_HTML);
}

// 纯文本全量日志（按写入顺序输出环形缓冲中的有效内容）
// 分块发送：不再一次性构造 16KB 的 String —— 页面每 2 秒轮询一次，
// 反复的大块堆分配/释放会长期制造堆碎片，这里改用 512 字节栈缓冲逐块写出。
void handleLog() {
    if (!checkAuth()) return;
    webServer.sendHeader("Cache-Control", "no-store");
    webServer.setContentLength(CONTENT_LENGTH_UNKNOWN);
    webServer.send(200, "text/plain; charset=utf-8", "");

    const size_t CHUNK = 512;
    char chunk[CHUNK];
    // 一次性快照长度与起点：分块期间不再重读 logLen，避免"起点按旧长度算、长度按新值读"
    // 这类不一致（当前单线程架构不会并发写入，但快照写法本身更不容易被后续改动踩坑）。
    const size_t total = logLen;
    const size_t start = (total < LOG_BUF_SIZE) ? 0 : logHead;   // 最旧字节的位置
    size_t idx = 0;
    while (idx < total) {
        size_t n = total - idx;
        if (n > CHUNK) n = CHUNK;
        for (size_t i = 0; i < n; i++) {
            chunk[i] = logBuf[(start + idx + i) % LOG_BUF_SIZE];
        }
        webServer.sendContent(chunk, n);
        idx += n;
        yield();   // 大日志分块期间让出 CPU，避免长时间饿死其它任务
    }
    webServer.sendContent("");   // 结束分块响应
}

// 当前"待执行 / 正在执行"的动作名（供 /status 的 pending 字段）。
// 空闲时返回空字符串；非空表示页面应显示"任务执行中"。
// key 与 Go 版完全一致：reboot_modem / power_on / restart_self / factory_reset / apply_wifi
// （"重启控制器"对外统一用 restart_self，与 Go 版同名，第三方脚本可同时驱动两版。）
const char* controlActionName() {
    if (wifiSwitchPhase != WF_IDLE) return "apply_wifi";
    if (rebootPhase != RB_IDLE)     return "reboot_modem";
    switch (pendingAction) {
        case PA_REBOOT_MODEM:  return "reboot_modem";
        case PA_POWER_ON:      return "power_on";
        case PA_RESTART_ESP:   return "restart_self";
        case PA_FACTORY_RESET: return "factory_reset";
        default:               return "";
    }
}

// JSON 状态（供页面徽章与第三方脚本轮询）
// 字段名/顺序与 Go 版保持一致：ver uptime wifi ip rssi miio online linkDown rebooting
//                              reboots maxReboots fatal pending logUsed logTotal logSeq webPort auth
// 说明：online 的语义是"当前判定为外网可达"。固件版比 Go 版多一个前提（WiFi 必须已连接），
//       因为链路层不通时不可能可达；WiFi 自身状态另有独立的 wifi 字段。
void handleStatus() {
    if (!checkAuth()) return;
    bool wifiOK = (WiFi.status() == WL_CONNECTED);
    bool online = wifiOK && (linkDownSince == 0);
    char json[512];
    snprintf(json, sizeof(json),
             "{\"ver\":\"1.0\",\"uptime\":%lu,\"wifi\":%s,\"ip\":\"%s\",\"rssi\":%d,"
             "\"miio\":%s,\"online\":%s,\"linkDown\":%lu,\"rebooting\":%s,"
             "\"reboots\":%d,\"maxReboots\":%d,\"fatal\":%s,\"pending\":\"%s\","
             "\"logUsed\":%u,\"logTotal\":%u,\"logSeq\":%lu,\"webPort\":%u,\"auth\":%s}",
             millis() / 1000,
             wifiOK ? "true" : "false",
             WiFi.localIP().toString().c_str(),
             (int)WiFi.RSSI(),
             miioOK ? "true" : "false",              // miIO 独立状态，不再用 LED 反推
             online ? "true" : "false",
             linkDownSince ? (millis() - linkDownSince) / 1000 : 0UL,
             rebooting ? "true" : "false",           // 重启冷却中（页面徽章用）
             rebootAttempts, MAX_REBOOT_ATTEMPTS,
             fatalLatched ? "true" : "false",
             controlActionName(),                    // 动作名（空闲为空串）
             (unsigned)logLen, (unsigned)LOG_BUF_SIZE,
             (unsigned long)logSeqCounter,           // 日志版本号：单调递增（不能用环形下标）
             (unsigned)activeWebPort,                // 实际监听端口（而非尚未生效的配置值）
             webPasswordHash[0] ? "true" : "false");
    webServer.sendHeader("Cache-Control", "no-store");
    webServer.send(200, "application/json; charset=utf-8", json);
}

// 远程控制：POST /api/control  action=xxx[&confirm=1]
// 单槽控制标志：HTTP handler 只置标志 / 启动状态机，实际动作由主循环分步执行（忙时返回 409）
void handleControl() {
    if (!checkAuth()) return;
    if (!checkCSRF()) return;

    String action = webServer.arg("action");

    // 清除熔断：无破坏性，立即执行，无需 confirm
    if (action == "clear_fatal") {
        clearFatalState("远程操作");
        webServer.send(200, "application/json; charset=utf-8",
                       "{\"ok\":true,\"msg\":\"熔断状态与重启计数已清除\"}");
        return;
    }

    // 危险操作必须带 confirm=1（前端已弹确认框，双保险）
    bool dangerous = (action == "reboot_modem" || action == "power_on" ||
                      action == "restart_self" || action == "factory_reset");
    if (dangerous && webServer.arg("confirm") != "1") {
        webServer.send(400, "application/json; charset=utf-8",
                       "{\"ok\":false,\"msg\":\"缺少 confirm=1\"}");
        return;
    }

    // 单槽控制标志：已有动作在执行（含 WiFi 切换与断电重启状态机）时一律 409
    if (controlBusy()) {
        webServer.send(409, "application/json; charset=utf-8",
                       "{\"ok\":false,\"msg\":\"已有任务正在执行，请稍候\"}");
        return;
    }

    if (action == "reboot_modem") {
        pendingAction = PA_REBOOT_MODEM;
        logPrintln("远程操作：请求断电重启光猫（主循环分步执行）");
        webServer.send(200, "application/json; charset=utf-8",
                       "{\"ok\":true,\"msg\":\"已接受：即将断电重启光猫，网络将中断约 1–3 分钟\"}");
    } else if (action == "power_on") {
        pendingAction = PA_POWER_ON;
        logPrintln("远程操作：请求恢复插板供电（主循环执行）");
        webServer.send(200, "application/json; charset=utf-8",
                       "{\"ok\":true,\"msg\":\"已接受：即将恢复插板供电\"}");
    } else if (action == "restart_self") {
        pendingAction = PA_RESTART_ESP;
        logPrintln("远程操作：请求重启控制器（主循环执行）");
        webServer.send(200, "application/json; charset=utf-8",
                       "{\"ok\":true,\"msg\":\"已接受：控制器即将重启\"}");
    } else if (action == "factory_reset") {
        pendingAction = PA_FACTORY_RESET;
        logPrintln("远程操作：请求恢复出厂设置（主循环执行）");
        webServer.send(200, "application/json; charset=utf-8",
                       "{\"ok\":true,\"msg\":\"已接受：将清除全部配置并重启；WiFi 与访问鉴权回到默认值"
                       "（首次运行口令 admin），设备 IP 可能变化，请留意串口或原网络\"}");
    } else {
        webServer.send(400, "application/json; charset=utf-8",
                       "{\"ok\":false,\"msg\":\"未知操作\"}");
    }
}

// 读取当前配置：GET /api/config（敏感字段不回传明文；时长统一回传秒数，也是页面接受的写法之一）
void handleConfigGet() {
    if (!checkAuth()) return;
    String cfg = "{";
    cfg += "\"wifiSsid\":\"" + jsonEsc(WIFI_SSID) + "\",";
    cfg += "\"deviceIp\":\""  + jsonEsc(DEVICE_IP) + "\",";
    cfg += "\"hasToken\":" + String(DEVICE_TOKEN[0] ? "true" : "false") + ",";
    cfg += "\"siid\":" + String(SIID) + ",\"piid\":" + String(PIID) + ",";
    cfg += "\"ping1\":\"" + jsonEsc(PING_IP1) + "\",";
    cfg += "\"ping2\":\"" + jsonEsc(PING_IP2) + "\",";
    cfg += "\"miPort\":" + String(MI_PORT) + ",";
    cfg += "\"pingInterval\":" + String(PING_INTERVAL / 1000UL) + ",";
    cfg += "\"pingTimeout\":" + String((unsigned)PING_TIMEOUT_S) + ",";   // 固件固定 1 秒，只读展示
    cfg += "\"offlineThreshold\":" + String(OFFLINE_THRESHOLD / 1000UL) + ",";
    cfg += "\"rebootCooldown\":" + String(REBOOT_COOLDOWN / 1000UL) + ",";
    cfg += "\"rebootOffTime\":" + String(REBOOT_OFF_TIME / 1000UL) + ",";
    cfg += "\"miioRetry\":" + String(MIIO_RETRY_INTERVAL / 1000UL) + ",";
    cfg += "\"wifiRetry\":" + String(WIFI_RETRY_INTERVAL / 1000UL) + ",";
    cfg += "\"maxReboots\":" + String(MAX_REBOOT_ATTEMPTS) + ",";
    cfg += "\"webPort\":" + String(WEB_PORT) + ",";
    cfg += "\"hasPassword\":" + String(webPasswordHash[0] ? "true" : "false") + ",";
    cfg += "\"webAuthDisabled\":" + String(webPasswordHash[0] ? "false" : "true");
    cfg += "}";
    webServer.sendHeader("Cache-Control", "no-store");
    webServer.send(200, "application/json; charset=utf-8", cfg);
}

// 保存配置：POST /api/config（表单编码；数字/文本字段留空 = 保持不变）
// 时长字段支持 "15s" / "10m" / "600" 三种写法（语义同 Go 版的 parseDuration）。
// ★ WiFi 变更不再在这里阻塞试连：handler 只暂存新的 SSID/口令、把状态机置为 TRYING 并立即返回。
//   旧版在这里直接 WiFi.disconnect() 会掐断与浏览器的 TCP 连接，浏览器永远收不到 HTTP 响应，
//   页面只能一直转圈 —— 这正是本次要修的 bug。实际试连由主循环 wifiSwitchStep() 分步推进。
void handleConfigSave() {
    if (!checkAuth()) return;
    if (!checkCSRF()) return;

    String msg;          // 附加说明（不含前导分隔符）
    String errMsg;

    // ========== 阶段 1：解析 + 校验（不改任何全局状态）==========
    // 全部字段先校验并暂存，任何错误都整体拒绝，保证不出现"改了一半"的状态。
    String newSsid     = webServer.arg("wifi_ssid");
    String newPass     = webServer.arg("wifi_pass");
    // SSID 留空 = 沿用当前 SSID；口令留空 = 沿用当前口令。
    // 注意这里不能用"SSID 必须非空"作为前提：**只改路由器密码**（SSID 输入框留空）
    // 是最常见的操作，旧逻辑会把它静默忽略掉，用户以为改了其实没改。
    String wifiUseSsid = (newSsid.length() > 0) ? newSsid : String(WIFI_SSID);
    String wifiUsePass = (newPass.length() > 0) ? newPass : String(WIFI_PASSWORD);
    bool   wifiChange  = (wifiUseSsid != WIFI_SSID) || (wifiUsePass != WIFI_PASSWORD);

    String stDevIp    = webServer.arg("dev_ip");
    String stDevToken = webServer.arg("dev_token");
    if (stDevIp.length() > 0 && !validIP(stDevIp))          errMsg += "插板IP格式无效；";
    if (stDevToken.length() > 0 && !validHex32(stDevToken)) errMsg += "Token格式无效（需32位十六进制）；";

    // 数字/文本字段一律"留空 = 保持不变"，留空不报错
    long stSiid = -1, stPiid = -1;
    String vSiid = webServer.arg("siid");
    String vPiid = webServer.arg("piid");
    if (vSiid.length() > 0) {
        stSiid = vSiid.toInt();
        if (stSiid < 1 || stSiid > 9999) { errMsg += "siid须在1~9999；"; stSiid = -1; }
    }
    if (vPiid.length() > 0) {
        stPiid = vPiid.toInt();
        if (stPiid < 1 || stPiid > 9999) { errMsg += "piid须在1~9999；"; stPiid = -1; }
    }

    String stP1 = webServer.arg("ping1");
    String stP2 = webServer.arg("ping2");
    if (stP1.length() > 0 && !validPingTarget(stP1))
        errMsg += "Ping目标1无效（须为普通 IPv4，且不能是 0.0.0.0、127.x.x.x 或插板自身）；";
    if (stP2.length() > 0 && !validPingTarget(stP2))
        errMsg += "Ping目标2无效（须为普通 IPv4，且不能是 0.0.0.0、127.x.x.x 或插板自身）；";

    // 时长参数：-1 = 未提供/无效。写法支持 "15s" / "10m" / "600"
    long stPingItv = -1, stOffTh = -1, stCooldown = -1, stRebootOff = -1, stMiioRetry = -1;
    long stWifiRetry = -1, stMaxReboots = -1, stWebPort = -1;
    String v;
    unsigned long sec = 0;

    v = webServer.arg("ping_interval");
    if (v.length() > 0) {
        if (!parseDurationSeconds(v, sec))  errMsg += "检测间隔格式无效（例: 15s / 10m / 600）；";
        else if (sec < 5 || sec > 3600)     errMsg += "检测间隔须在5~3600秒；";
        else                                stPingItv = (long)sec;
    }
    v = webServer.arg("offline_threshold");
    if (v.length() > 0) {
        if (!parseDurationSeconds(v, sec))  errMsg += "断网阈值格式无效（例: 10m / 600）；";
        else if (sec < 30 || sec > 86400)   errMsg += "断网阈值须在30~86400秒；";
        else                                stOffTh = (long)sec;
    }
    v = webServer.arg("cooldown");
    if (v.length() > 0) {
        if (!parseDurationSeconds(v, sec))  errMsg += "重启冷却格式无效（例: 120s / 2m）；";
        else if (sec < 10 || sec > 3600)    errMsg += "重启冷却须在10~3600秒；";
        else                                stCooldown = (long)sec;
    }
    v = webServer.arg("reboot_off_time");
    if (v.length() > 0) {
        if (!parseDurationSeconds(v, sec))  errMsg += "插板断电时长格式无效（例: 10s）；";
        else if (sec < 5 || sec > 120)      errMsg += "插板断电时长须在5~120秒；";
        else                                stRebootOff = (long)sec;
    }
    v = webServer.arg("miio_retry_interval");
    if (v.length() > 0) {
        if (!parseDurationSeconds(v, sec))  errMsg += "miIO重试间隔格式无效（例: 60s / 1m）；";
        else if (sec < 5 || sec > 3600)     errMsg += "miIO重试间隔须在5~3600秒；";
        else                                stMiioRetry = (long)sec;
    }
    v = webServer.arg("wifi_retry");
    if (v.length() > 0) {
        if (!parseDurationSeconds(v, sec))  errMsg += "WiFi重连间隔格式无效（例: 10s / 600）；";
        else if (sec < 3 || sec > 600)      errMsg += "WiFi重连间隔须在3~600秒；";
        else                                stWifiRetry = (long)sec;
    }
    v = webServer.arg("max_reboots");
    if (v.length() > 0) {
        stMaxReboots = v.toInt();
        if (stMaxReboots < 1 || stMaxReboots > 10) { errMsg += "最大连续重启须在1~10；"; stMaxReboots = -1; }
    }
    v = webServer.arg("web_port");
    if (v.length() > 0) {
        stWebPort = v.toInt();
        if (stWebPort < 1 || stWebPort > 65535) { errMsg += "端口须在1~65535；"; stWebPort = -1; }
    }

    bool   stClearPass = (webServer.arg("clear_web_pass") == "1");
    String stWebPass   = webServer.arg("web_pass");

    if (errMsg.length() > 0) {
        logPrintf("远程操作：配置保存被拒绝 - %s\n", errMsg.c_str());
        String resp = "{\"ok\":false,\"msg\":\"未保存：" + jsonEsc(errMsg.c_str()) + "\"}";
        webServer.send(400, "application/json; charset=utf-8", resp);
        return;
    }

    // 上一次 WiFi 切换还没结束（TRYING/ROLLBACK）时，不允许再改 WiFi：
    // 否则会用旧 SSID 落盘并打断正在进行的切换。
    if (wifiChange && wifiSwitchPhase != WF_IDLE) {
        webServer.send(409, "application/json; charset=utf-8",
                       "{\"ok\":false,\"msg\":\"WiFi 切换正在进行中，请等切换结束后再改\"}");
        return;
    }

    // ========== 阶段 2：应用变更（先记旧值，Token 解析失败时回滚）==========
    char oldDevIp[16] = {0};
    char oldToken[33] = {0};
    strlcpy(oldDevIp, DEVICE_IP, sizeof(oldDevIp));
    strlcpy(oldToken, DEVICE_TOKEN, sizeof(oldToken));
    int oldSiid = SIID, oldPiid = PIID;

    bool devChanged = false;
    if (stDevIp.length() > 0 && stDevIp != DEVICE_IP) {
        strlcpy(DEVICE_IP, stDevIp.c_str(), sizeof(DEVICE_IP));
        devChanged = true;
    }
    if (stDevToken.length() > 0 && stDevToken != DEVICE_TOKEN) {
        strlcpy(DEVICE_TOKEN, stDevToken.c_str(), sizeof(DEVICE_TOKEN));
        devChanged = true;
    }
    if (stSiid > 0 && stSiid != SIID) { SIID = (int)stSiid; devChanged = true; }
    if (stPiid > 0 && stPiid != PIID) { PIID = (int)stPiid; devChanged = true; }

    // 插板 IP / Token / siid / piid 任一变更 → 重新解析 Token，刷新 deviceToken[16] 与 tokenValid
    if (devChanged) {
        if (parseToken()) {
            logPrintf("插板配置已变更：Token 重新解析成功（插板=%s siid=%d/piid=%d，稍后重新握手）\n",
                      DEVICE_IP, SIID, PIID);
        } else {
            // 阶段 1 的格式校验已挡住非法 Token，这里是兜底：整块回滚并明确报错
            strlcpy(DEVICE_IP, oldDevIp, sizeof(DEVICE_IP));
            strlcpy(DEVICE_TOKEN, oldToken, sizeof(DEVICE_TOKEN));
            SIID = oldSiid;
            PIID = oldPiid;
            parseToken();                     // 恢复成旧 Token 对应的字节
            logPrintln("远程操作：插板配置保存被拒绝 - Token 无法解析（需 32 位十六进制）");
            webServer.send(400, "application/json; charset=utf-8",
                           "{\"ok\":false,\"msg\":\"未保存：插板 Token 无法解析（需 32 位十六进制）\"}");
            return;
        }
    }

    // Ping 目标
    if (stP1.length() > 0) strlcpy(PING_IP1, stP1.c_str(), sizeof(PING_IP1));
    if (stP2.length() > 0) strlcpy(PING_IP2, stP2.c_str(), sizeof(PING_IP2));

    // 看门狗时间参数（秒 → 毫秒）
    if (stPingItv > 0)    PING_INTERVAL = (unsigned long)stPingItv * 1000UL;
    if (stOffTh > 0)      OFFLINE_THRESHOLD = (unsigned long)stOffTh * 1000UL;
    if (stCooldown > 0)   REBOOT_COOLDOWN = (unsigned long)stCooldown * 1000UL;
    if (stRebootOff > 0)  REBOOT_OFF_TIME = (unsigned long)stRebootOff * 1000UL;
    if (stMiioRetry > 0)  MIIO_RETRY_INTERVAL = (unsigned long)stMiioRetry * 1000UL;
    if (stWifiRetry > 0)  WIFI_RETRY_INTERVAL = (unsigned long)stWifiRetry * 1000UL;
    if (stMaxReboots > 0) MAX_REBOOT_ATTEMPTS = (int)stMaxReboots;

    // Web 访问：口令只存 SHA-256；"清除密码"= 关闭鉴权，且该状态持久化
    if (stClearPass) {
        webPasswordHash[0] = '\0';
        authConfigured = true;
        msg += (msg.length() ? "；" : "");
        msg += "鉴权已关闭（已清除密码，重启后仍保持关闭）";
    } else if (stWebPass.length() > 0) {
        sha256_hex(stWebPass.c_str(), stWebPass.length(), webPasswordHash);
        authConfigured = true;
        msg += (msg.length() ? "；" : "");
        msg += "访问密码已更新（仅存 SHA-256）";
    }
    if (stWebPort > 0 && stWebPort != (long)WEB_PORT) {
        WEB_PORT = (uint16_t)stWebPort;
        msg += (msg.length() ? "；" : "");
        msg += "端口将在重启控制器后生效";
    }

    // 落盘 NVS：成功与失败必须区分，不能把"保存失败"报成"已保存"
    bool saved = saveConfig();
    if (saved) {
        logPrintf("远程操作：配置已保存并写入 NVS（%s）\n", msg.length() ? msg.c_str() : "无附加变更");
    } else {
        logPrintln("远程操作：配置写入 NVS 失败（NVS 不可写），改动只在本次运行内有效");
    }

    // 插板配置变更 → 作废旧连接状态，让 miIO 心跳按 MIIO_RETRY_INTERVAL 重新握手
    // （本函数不再阻塞握手，Web 响应会立刻返回）
    if (devChanged && !wifiChange) {
        setMiioState(false);
        lastMiioCheck = 0;          // 允许下一轮主循环立刻重试一次
        logPrintln("插板配置已变更：立即作废旧会话，等待 miIO 重新握手验证");
        msg += (msg.length() ? "；" : "");
        msg += "插板配置已变更，正在重新握手验证";
    }

    // ========== 阶段 3：响应（必须在断开 WiFi 之前发出）+ 启动切换状态机 ==========
    String resp = "{\"ok\":";
    resp += saved ? "true" : "false";
    resp += ",\"msg\":\"";
    resp += saved ? "配置已保存" : "配置已生效，但保存失败（NVS 不可写），重启后会丢失";
    if (msg.length() > 0) { resp += "；"; resp += jsonEsc(msg.c_str()); }
    if (wifiChange) {
        resp += "；已接受：正在切换 WiFi，20 秒内完成，失败自动回退";
    }
    resp += "\"}";
    webServer.send(saved ? 200 : 500, "application/json; charset=utf-8", resp);

    if (wifiChange) {
        // 只暂存新 SSID/口令并置状态为 TRYING；真正的断开与试连由主循环延后执行，
        // wifiSwitchArmAt 留出的这段时间足以让上面的 HTTP 响应送达浏览器。
        strlcpy(wifiNewSsid, wifiUseSsid.c_str(), sizeof(wifiNewSsid));
        strlcpy(wifiNewPass, wifiUsePass.c_str(), sizeof(wifiNewPass));
        wifiSwitchPhase = WF_TRYING;
        wifiSwitchArmAt = millis() + 800;
        wifiSwitchStart = wifiSwitchArmAt;
        logPrintf("配置变更：800 毫秒后尝试连接新 WiFi \"%s\"（20 秒内完成，失败自动回退）\n",
                  wifiNewSsid);
    }
}

// 注册路由并启动（须在 WiFi 连接成功后调用；WiFi 重连后无需重启，IP 变化服务仍在）
void webServerSetup() {
    if (!WEB_ENABLED) return;

    // 注册需要读取的请求头。
    // 注意：WebServer 内部默认就收集 Authorization（checkAuth 靠它做 Basic 鉴权），
    // 这里额外注册的是防跨站用的自定义头 X-Requested-With —— 未注册的头读不到。
    static const char* hdrKeys[] = {"X-Requested-With"};
    webServer.collectHeaders(hdrKeys, 1);

    webServer.on("/", HTTP_GET, handleRoot);
    webServer.on("/log", HTTP_GET, handleLog);
    webServer.on("/status", HTTP_GET, handleStatus);
    webServer.on("/api/control", HTTP_POST, handleControl);
    webServer.on("/api/config", HTTP_GET, handleConfigGet);
    webServer.on("/api/config", HTTP_POST, handleConfigSave);
    webServer.onNotFound([]() {
        webServer.send(404, "text/plain; charset=utf-8", "404 Not Found\n");
    });

    // ★ 用 NVS 加载后的端口启动：全局对象是按默认端口构造的，端口配置必须在这里生效
    activeWebPort = WEB_PORT;
    webServer.begin(activeWebPort);
    webReady = true;
}

// ==================== 主循环执行的控制任务 ====================
// 单槽控制标志：这里执行的动作本身都很快，或直接启动由主循环分步推进的状态机。
void handlePendingAction() {
    switch (pendingAction) {
        case PA_REBOOT_MODEM:
            logPrintln(">>> 执行手动任务：断电重启光猫（由主循环分步执行）");
            rebootStart(true);      // 与自动触发走同一状态机
            break;
        case PA_POWER_ON: {
            logPrintln(">>> 执行手动任务：恢复插板供电");
            if (miio_handshake()) {
                if (miio_setPower(true)) {
                    logPrintln(">>> 插板已恢复供电");
                } else {
                    // 断电状态下上电命令始终没被确认 → 硬故障，LED 快闪提醒人工介入
                    powerFault = true;
                    logPrintln(">>> 恢复供电命令未得到设备确认，光猫可能仍断电，请人工检查（LED 快闪）");
                }
            } else {
                logPrintln(">>> miIO 握手失败，无法恢复供电");
            }
            break;
        }
        case PA_RESTART_ESP:
            logPrintln(">>> 远程指令：3 秒后重启控制器");
            delay(3000);
            ESP.restart();
            break;                       // 不会到达
        case PA_FACTORY_RESET: {
            logPrintln(">>> 远程指令：恢复出厂设置");
            if (factoryReset()) {
                logPrintln(">>> 全部配置已清除，3 秒后重启（WiFi 与访问鉴权回到编译期默认值）");
                delay(3000);
                ESP.restart();
            } else {
                // NVS 清除失败就绝不重启：否则会出现"以为恢复出厂、实际还在跑旧配置"的假象
                logPrintln(">>> 恢复出厂未完成（NVS 清除失败），已取消重启，请查看上方日志");
            }
            break;
        }
        default:
            break;
    }
    pendingAction = PA_NONE;         // 释放单槽控制标志
}

// 运行期检测 BOOT 键长按 5 秒 → 恢复出厂配置（失联时的本地兜底手段）。
// ★ 为什么必须在"运行期"检测，而不是开机时检测：
//   ESP32-C3 的 GPIO9 是 strapping 引脚，上电/复位瞬间若它被按住（低电平），
//   ROM bootloader 会直接进入 UART 下载模式，用户程序根本不会启动 ——
//   所以"开机长按 BOOT 键"这条路在硬件层就走不通（按了只会进下载模式）。
//   运行期间按键不参与 strapping 采样，可以安全地做长按检测。
void checkFactoryResetButton() {
    static unsigned long pressedSince = 0;
    static bool warned = false;

    if (digitalRead(BOOT_BTN_PIN) != LOW) {   // 松开 → 复位计时
        pressedSince = 0;
        warned = false;
        return;
    }

    unsigned long now = millis();
    if (pressedSince == 0) {                  // 刚按下
        pressedSince = now;
        return;
    }

    unsigned long held = now - pressedSince;
    if (!warned && held >= 2000) {            // 中途提示，避免误触发
        warned = true;
        logPrintf("BOOT 键已按住 %lu 秒，继续按住到 5 秒将恢复出厂配置…\n", held / 1000);
    }
    if (held >= 5000) {
        logPrintln("BOOT 键长按 5 秒 → 恢复出厂配置并重启");
        if (factoryReset()) {
            delay(500);
            ESP.restart();
        } else {
            logPrintln("!!! NVS 清除失败，已取消重启（配置可能仍然保留）!!!");
            pressedSince = 0;     // 复位计时，避免按住不放反复触发
            warned = false;
        }
    }
}

// ==================== 工具函数 ====================
void md5_hash(const uint8_t* input, size_t len, uint8_t* output) {
    // 使用 mbedtls_md5() 一次性接口，兼容 mbedtls 2.x / 3.x
    mbedtls_md5(input, len, output);
}

// SHA-256 → 64 字符小写十六进制（+结尾 '\0'），用于 Web 访问口令的存储与比对。
// 使用 mbedtls 3.x 的一次性接口 mbedtls_sha256(input, len, output, is224)，
// 与上面的 mbedtls_md5() 同构（3.x 起 *_ret 后缀的一趟接口已改名去掉后缀）。
void sha256_hex(const char* input, size_t len, char* out64) {
    uint8_t digest[32];
    mbedtls_sha256((const unsigned char*)input, len, digest, 0);   // 0 = SHA-256（非 SHA-224）
    static const char* HEXD = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out64[i * 2]     = HEXD[(digest[i] >> 4) & 0x0F];
        out64[i * 2 + 1] = HEXD[digest[i] & 0x0F];
    }
    out64[64] = '\0';
}

void aes_encrypt(const uint8_t* key, const uint8_t* iv,
                 const uint8_t* input, size_t len, uint8_t* output) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len,
                          iv_copy, input, output);
    mbedtls_aes_free(&aes);
}

// ★ 修复2：新增解密，用来读取设备响应内容（判断命令是否被接受）
void aes_decrypt(const uint8_t* key, const uint8_t* iv,
                 const uint8_t* input, size_t len, uint8_t* output) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 128);
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len,
                          iv_copy, input, output);
    mbedtls_aes_free(&aes);
}

// 单个十六进制字符 → 0~15，非法字符返回 -1
int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// ★ 严格解析 DEVICE_TOKEN（32 位十六进制）→ deviceToken[16] + tokenValid。
// 逐字符校验，刻意不用 sscanf("%2x")：后者会接受 "0x"、" 1"、"+f" 等非严格输入，
// 可能把一段垃圾字符串解析成"看起来合法"的 Token。
// 返回 true = 解析成功且 tokenValid 已置位；false = 格式非法（deviceToken 被清零）。
bool parseToken() {
    tokenValid = false;
    memset(deviceToken, 0, sizeof(deviceToken));

    const char* s = DEVICE_TOKEN;
    if (s == nullptr || strlen(s) != 32) return false;

    uint8_t tmp[16];
    for (int i = 0; i < 16; i++) {
        int hi = hexNibble(s[i * 2]);
        int lo = hexNibble(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        tmp[i] = (uint8_t)((hi << 4) | lo);
    }
    memcpy(deviceToken, tmp, sizeof(deviceToken));
    tokenValid = true;
    return true;
}

// 解析时长字符串，语义对齐 Go 版的 parseDuration：
//   "15s" / "10m" / "1h" / "1m30s" / 纯数字（= 秒，"600"）
// 明确不支持小数与毫秒级单位（Go 版支持 "1.5h" / "500ms"，本项目所有时长下限都是 5 秒，
// 用不到亚秒精度，遇到这类写法会直接判为非法并提示写法）。
// 返回 false = 格式非法；成功时 outSec 为秒数。
bool parseDurationSeconds(const String& raw, unsigned long& outSec) {
    String s = raw;
    s.trim();
    unsigned int len = s.length();
    if (len == 0) return false;

    // 纯数字 = 秒
    bool allDigits = true;
    for (unsigned int i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') { allDigits = false; break; }
    }
    if (allDigits) {
        outSec = strtoul(s.c_str(), nullptr, 10);
        return true;
    }

    // "数字+单位"的串联，单位只认 s / m / h
    unsigned long total = 0;
    unsigned int i = 0;
    while (i < len) {
        if (s[i] < '0' || s[i] > '9') return false;     // 拒绝前导 +/-、小数点等写法
        unsigned long val = 0;
        while (i < len && s[i] >= '0' && s[i] <= '9') {
            val = val * 10UL + (unsigned long)(s[i] - '0');
            // 单段上限 1e6（约 11.5 天）：既远超所有参数的合法上限（最大 86400 秒），
            // 又保证 val*3600 不会溢出 unsigned long（32 位）造成回绕后误判为合法。
            if (val > 1000000UL) return false;
            i++;
        }
        if (i >= len) return false;                     // 数字后面必须跟单位
        char u = s[i++];
        if (u == 's')      total += val;
        else if (u == 'm') total += val * 60UL;
        else if (u == 'h') total += val * 3600UL;
        else               return false;
        if (total > 100000000UL) return false;
    }
    outSec = total;
    return true;
}

// 从 token 派生 key / iv（收发共用这一对）
// key = MD5(token)，iv = MD5(key || token)
void miio_derive_key_iv(uint8_t* key, uint8_t* iv) {
    uint8_t keyToken[32];
    md5_hash(deviceToken, 16, key);
    memcpy(keyToken, key, 16);
    memcpy(keyToken + 16, deviceToken, 16);
    md5_hash(keyToken, 32, iv);
}

// ==================== LED 控制 ====================
// 输出优先级：硬故障/熔断快闪 > miIO 错误常亮 > WiFi 慢闪 > 熄灭
// 快闪条件统一由 fatalActive() 决定（fatalLatched || powerFault），LED 不再自己存一份熔断状态，
// 避免"熔断已清除但 LED 还停在快闪相位"这类状态不同步的问题。

// 硬故障（熔断 / 上电命令未确认 / Token 无效）→ 需要人工介入，LED 快闪
bool fatalActive() {
    return fatalLatched || powerFault;
}

void ledStartBlink() {
    ledError = false;
    ledBlinking = true;
}

void ledStopBlink() {
    ledBlinking = false;
    ledError = false;
    if (!fatalActive()) digitalWrite(LED_PIN, LED_OFF);
}

void ledErrorOn() {
    ledBlinking = false;
    ledError = true;
    if (!fatalActive()) digitalWrite(LED_PIN, LED_ON);
}

// 把熔断状态与重启计数写回 NVS。只在状态真正变化时调用（熔断/清零/每次重启动作收尾），
// 属于低频写入，不会磨损 flash。写入失败只告警，不影响运行。
void saveRuntimeState() {
    if (!prefs.begin(NVS_NS, false)) {
        logPrintln("警告: NVS 打开失败，熔断状态与重启计数未能保存");
        return;
    }
    size_t n1 = prefs.putBool("fatal", fatalLatched);
    size_t n2 = prefs.putInt("reboot_cnt", rebootAttempts);
    size_t n3 = prefs.putBool("power_fault", powerFault);
    prefs.end();
    if (n1 == 0 || n2 == 0 || n3 == 0) {
        logPrintln("警告: 熔断状态/重启计数写入 NVS 失败");
    }
}

// 清除熔断 / 硬故障 / 重启计数（远程按钮与"连续在线满 5 分钟"都走这里）。
// ★ 必须立即重绘 LED 输出电平：只改标志会让 LED 停在快闪的残留相位（可能一直亮着不灭）。
void clearFatalState(const char* reason) {
    fatalLatched   = false;
    powerFault     = false;
    rebootAttempts = 0;
    if (ledError) {
        digitalWrite(LED_PIN, LED_ON);      // miIO 仍异常 → 保持常亮
    } else if (ledBlinking) {
        ledState = false;
        digitalWrite(LED_PIN, LED_OFF);     // 仍在等 WiFi → 交回慢闪逻辑
    } else {
        digitalWrite(LED_PIN, LED_OFF);
    }
    logPrintf("已清除熔断状态、硬故障标志与重启计数（%s）\n", reason ? reason : "未说明原因");
    saveRuntimeState();
}

void ledUpdate() {
    unsigned long now = millis();

    if (fatalActive()) {                    // 快闪优先级最高
        if (now - lastLedToggle >= LED_FAST_INTERVAL) {
            lastLedToggle = now;
            ledState = !ledState;
            digitalWrite(LED_PIN, ledState ? LED_ON : LED_OFF);
        }
        return;
    }
    if (ledError) return;      // 常亮，无需处理
    if (!ledBlinking) return;
    if (now - lastLedToggle >= LED_BLINK_INTERVAL) {
        lastLedToggle = now;
        ledState = !ledState;
        digitalWrite(LED_PIN, ledState ? LED_ON : LED_OFF);
    }
}

// miIO 状态的唯一入口：更新 miioOK 并同步 LED
// （异常 → 错误常亮；恢复正常 → 熄灭，但快闪/慢闪的更高优先级状态不会被覆盖）
void setMiioState(bool ok) {
    miioOK = ok;
    if (ok) {
        ledError = false;
        if (!fatalActive() && !ledBlinking) digitalWrite(LED_PIN, LED_OFF);
    } else {
        ledErrorOn();
    }
}

// ==================== miIO 协议 ====================
// 排空 UDP 缓冲区，避免上次命令的残留 ACK 污染下次交互。
// 连续 quietMs 没有新包就认为排空完成；hardLimitMs 兜底防止一直有包时卡住。
// 默认值写在文件顶部的手写前置声明处（定义处不再重复，避免依赖 Arduino 自动原型）。
void miio_drain_response(unsigned long quietMs, unsigned long hardLimitMs) {
    unsigned long start = millis();
    unsigned long lastRecv = start;

    while (millis() - lastRecv < quietMs && millis() - start < hardLimitMs) {
        int sz = udp.parsePacket();
        if (sz > 0) {
            uint8_t buf[MAX_BUF];
            udp.read(buf, sizeof(buf));
            lastRecv = millis();
        } else {
            delay(5);
        }
        ledUpdate();
    }
}

// ★ 修复3：校验 miIO 响应包（移植自 Go 版的 validMiiOPacket）。
// 之前只判断 packetSize >= 32 就采信，残留 ACK 或局域网内其它 miIO 设备的回包
// 都可能被当成握手响应，导致 deviceId/stamp 是垃圾值、后续命令静默失败。
bool miio_valid_packet(const uint8_t* pkt, int len) {
    if (pkt == nullptr || len < 32) return false;
    if (pkt[0] != 0x21 || pkt[1] != 0x31) return false;                       // 魔数
    if ((((uint16_t)pkt[2] << 8) | (uint16_t)pkt[3]) != (uint16_t)len) {      // 长度字段
        return false;
    }
    // 设备对 hello 的响应（32 字节无数据）checksum 字段固定回显 0xFF×16，无有效校验和
    if (len == 32) return true;
    if (!tokenValid) return false;

    int dataLen = len - 32;
    if (dataLen > (int)MAX_BUF) return false;

    // checksum = MD5(header + token + encrypted_data)
    // 校验通过即证明 token 正确、包确实来自真实设备
    uint8_t buf[16 + 16 + MAX_BUF];
    memcpy(buf, pkt, 16);
    memcpy(buf + 16, deviceToken, 16);
    memcpy(buf + 32, pkt + 32, (size_t)dataLen);

    uint8_t md[16];
    md5_hash(buf, (size_t)(16 + 16 + dataLen), md);
    return memcmp(md, pkt + 16, 16) == 0;
}

// 解密响应数据区，得到 JSON 文本
bool miio_decode_payload(const uint8_t* pkt, int len, char* out, size_t outSize) {
    if (!tokenValid || out == nullptr || outSize == 0) return false;

    int dataLen = len - 32;
    if (dataLen <= 0 || (dataLen % 16) != 0 || dataLen > (int)MAX_BUF) return false;

    uint8_t key[16], iv[16];
    miio_derive_key_iv(key, iv);

    uint8_t plain[MAX_BUF];
    aes_decrypt(key, iv, pkt + 32, (size_t)dataLen, plain);

    // 去掉 PKCS#7 填充
    uint8_t pad = plain[dataLen - 1];
    if (pad >= 1 && pad <= 16 && pad <= (uint8_t)dataLen) dataLen -= pad;

    size_t n = (size_t)dataLen;
    if (n >= outSize) n = outSize - 1;
    memcpy(out, plain, n);
    out[n] = '\0';
    return true;
}

// 命令的应答结果（底层类型必须与文件顶部的 C++11 前向声明一致）
enum MiioReply : int {
    MIIO_REPLY_NONE = 0,   // 无响应 / 未通过校验
    MIIO_REPLY_OK,         // 设备确认
    MIIO_REPLY_ERROR       // 设备明确返回 error
};

const char* miio_reply_name(MiioReply r) {
    switch (r) {
        case MIIO_REPLY_OK:    return "设备已确认";
        case MIIO_REPLY_ERROR: return "设备返回错误";
        default:               return "无响应";
    }
}

// 从响应 JSON 中取顶层 "id" 的数值；找不到或格式非法返回 -1
int miio_parse_reply_id(const char* json) {
    const char* p = strstr(json, "\"id\"");
    if (p == nullptr) return -1;
    p += 4;
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p < '0' || *p > '9') return -1;
    int v = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (*p - '0');
        if (v > 1000000) return -1;
        p++;
    }
    return v;
}

// 等待一个校验通过的响应；detail 可选，用于回传解密后的 JSON 片段
MiioReply miio_wait_reply(unsigned long timeoutMs, char* detail, size_t detailSize) {
    unsigned long start = millis();

    while (millis() - start < timeoutMs) {
        int packetSize = udp.parsePacket();
        if (packetSize > 0) {
            if (packetSize > (int)MAX_BUF) {          // 超长包不是我们要的
                uint8_t tmp[MAX_BUF];
                udp.read(tmp, sizeof(tmp));
                logPrintf("响应过大(%d)，已丢弃\n", packetSize);
                continue;
            }

            uint8_t pkt[MAX_BUF];
            int len = udp.read(pkt, sizeof(pkt));

            if (miio_valid_packet(pkt, len)) {
                if (len > 32) {
                    char json[MAX_BUF];
                    if (miio_decode_payload(pkt, len, json, sizeof(json))) {
                        // ★ 校验响应里的 id 必须等于请求 id（固定 MIIO_REQUEST_ID）：
                        //   不匹配的包（上一次命令迟到的 ACK、局域网里其它 miIO 设备的回包）
                        //   一律当无效包丢弃并继续等待，绝不能拿它当作本次命令的结果。
                        int rid = miio_parse_reply_id(json);
                        if (rid != MIIO_REQUEST_ID) {
                            logPrintf("响应 id 不匹配（id=%d，期望 %d），已丢弃\n", rid, MIIO_REQUEST_ID);
                            ledUpdate();
                            delay(10);
                            continue;
                        }
                        if (detail && detailSize > 0) {
                            strncpy(detail, json, detailSize - 1);
                            detail[detailSize - 1] = '\0';
                        }
                        if (strstr(json, "\"error\"") != nullptr) return MIIO_REPLY_ERROR;
                        return MIIO_REPLY_OK;
                    }
                }
                // 包校验通过即代表 token 正确、命令已送达真实设备
                return MIIO_REPLY_OK;
            }
            logPrintf("响应未通过校验，已丢弃 len=%d\n", len);
        }
        ledUpdate();
        delay(10);
    }
    return MIIO_REPLY_NONE;
}

// 发送一条 miIO 命令并确认设备是否接受
MiioReply miio_send_command(const char* method, const char* paramsJson,
                            char* detail, size_t detailSize) {
    if (detail && detailSize > 0) detail[0] = '\0';
    if (!tokenValid) return MIIO_REPLY_ERROR;

    // 全部使用栈缓冲区，避免 new/delete 造成堆碎片
    char payload[MAX_BUF];
    int plen = snprintf(payload, sizeof(payload),
                        "{\"id\":%d,\"method\":\"%s\",\"params\":%s}",
                        MIIO_REQUEST_ID, method, paramsJson);
    if (plen <= 0 || plen >= (int)sizeof(payload)) {
        logPrintln("Payload 构造失败/超长");
        return MIIO_REPLY_ERROR;
    }

    // PKCS#7 填充
    size_t payloadLen = (size_t)plen;
    size_t paddedLen = ((payloadLen / 16) + 1) * 16;
    if (paddedLen > MAX_BUF) {
        logPrintln("填充后超长");
        return MIIO_REPLY_ERROR;
    }
    uint8_t padded[MAX_BUF];
    memcpy(padded, payload, payloadLen);
    uint8_t padVal = (uint8_t)(paddedLen - payloadLen);
    for (size_t i = payloadLen; i < paddedLen; i++) padded[i] = padVal;

    // 派生 Key 和 IV，然后加密
    uint8_t key[16], iv[16];
    miio_derive_key_iv(key, iv);

    uint8_t encrypted[MAX_BUF];
    aes_encrypt(key, iv, padded, paddedLen, encrypted);

    // 构造头部
    uint16_t totalLen = (uint16_t)(16 + 16 + paddedLen);
    uint8_t header[16] = {0};
    header[0] = 0x21; header[1] = 0x31;
    header[2] = (totalLen >> 8) & 0xFF;
    header[3] = totalLen & 0xFF;
    header[8]  = (deviceId >> 24) & 0xFF;
    header[9]  = (deviceId >> 16) & 0xFF;
    header[10] = (deviceId >> 8) & 0xFF;
    header[11] = deviceId & 0xFF;
    uint32_t ts = ++stamp;
    header[12] = (ts >> 24) & 0xFF;
    header[13] = (ts >> 16) & 0xFF;
    header[14] = (ts >> 8) & 0xFF;
    header[15] = ts & 0xFF;

    // 校验和 = MD5(header + token + encrypted)
    // 注意：总长度是 16 + 16 + paddedLen，paddedLen 最大可达 MAX_BUF，
    // 所以缓冲区必须是 MAX_BUF + 32，不能沿用 MAX_BUF。
    uint8_t checksumInput[16 + 16 + MAX_BUF];
    memcpy(checksumInput, header, 16);
    memcpy(checksumInput + 16, deviceToken, 16);
    memcpy(checksumInput + 32, encrypted, paddedLen);
    uint8_t checksum[16];
    md5_hash(checksumInput, 16 + 16 + paddedLen, checksum);

    // ★ 修复2：发送前先清掉残留，否则会把上一次命令的旧 ACK 当成本次结果
    miio_drain_response(120, 500);

    udp.beginPacket(DEVICE_IP, MI_PORT);
    udp.write(header, 16);
    udp.write(checksum, 16);
    udp.write(encrypted, paddedLen);
    if (udp.endPacket() == 0) {
        logPrintln("指令发送失败！");
        return MIIO_REPLY_NONE;
    }

    MiioReply r = miio_wait_reply(MIIO_ACK_TIMEOUT, detail, detailSize);
    miio_drain_response(120, 500);   // 清掉可能重复送达的 ACK
    return r;
}

bool miio_handshake() {
    if (WiFi.status() != WL_CONNECTED) {
        // WiFi 没连上时无法判断 miIO 好坏，这里不动 miioOK / 错误常亮，
        // 否则会和"WiFi 慢闪"互相打架（链路问题应由 WiFi 流程负责提示）。
        logPrintln("WiFi 未连接，无法握手");
        return false;
    }
    if (!tokenValid) {
        logPrintln("Token 无效，无法握手");
        setMiioState(false);
        return false;
    }

    // 清空可能存在的残留包
    miio_drain_response(200, 800);

    // miIO 握手包（32 字节：16 头部 + 16 全 0xFF 数据）
    uint8_t hello[32];
    hello[0] = 0x21; hello[1] = 0x31;   // Magic Number
    hello[2] = 0x00; hello[3] = 0x20;   // Length = 32
    memset(hello + 4,  0xFF, 4);        // Unknown
    memset(hello + 8,  0xFF, 4);        // Device ID
    memset(hello + 12, 0xFF, 4);        // Timestamp
    memset(hello + 16, 0xFF, 16);       // Data

    udp.beginPacket(DEVICE_IP, MI_PORT);
    udp.write(hello, 32);
    if (udp.endPacket() == 0) {
        logPrintln("握手包发送失败");
        setMiioState(false);
        return false;
    }
    logPrintln("握手包已发送，等待响应...");

    uint32_t start = millis();
    while (millis() - start < 3000) {
        int packetSize = udp.parsePacket();
        if (packetSize > 0) {
            uint8_t resp[MAX_BUF];
            int len = udp.read(resp, sizeof(resp));

            // ★ 修复3：必须通过魔数/长度/checksum 校验才认账
            if (!miio_valid_packet(resp, len)) {
                logPrintf("握手响应未通过校验，已丢弃 len=%d\n", len);
                ledUpdate();
                delay(10);
                continue;
            }

            logPrintf("收到响应，长度=%d\n", len);
            logPrint("响应头部: ");
            for (int i = 0; i < 16 && i < len; i++) {
                logPrintf("%02X ", resp[i]);
            }
            logPrintln();

            deviceId = ((uint32_t)resp[8]  << 24) | ((uint32_t)resp[9]  << 16)
                     | ((uint32_t)resp[10] << 8)  |  (uint32_t)resp[11];
            stamp    = ((uint32_t)resp[12] << 24) | ((uint32_t)resp[13] << 16)
                     | ((uint32_t)resp[14] << 8)  |  (uint32_t)resp[15];
            logPrintf("Handshake OK  DID=%08X  Stamp=%u\n", deviceId, stamp);

            setMiioState(true);   // 握手成功 → miioOK = true，LED 熄灭
            return true;
        }
        ledUpdate();
        delay(10);
    }
    logPrintln("Handshake timeout");
    setMiioState(false);          // 握手失败 → miioOK = false，LED 常亮
    return false;
}

// 单次尝试设置插板电源（供重启状态机分步调用，内部不重试、不长时间阻塞）
MiioReply miio_setPowerTry(bool on) {
    // 全部使用栈缓冲区，避免 String 拼接造成堆碎片
    char params[64];
    snprintf(params, sizeof(params), "[{\"siid\":%d,\"piid\":%d,\"value\":%s}]",
             SIID, PIID, on ? "true" : "false");

    char detail[128] = {0};
    MiioReply r = miio_send_command("set_properties", params, detail, sizeof(detail));
    if (r == MIIO_REPLY_OK) {
        logPrintf("插板电源已%s（设备已确认）\n", on ? "打开" : "关闭");
        setMiioState(true);
    } else {
        logPrintf("设置电源(%s)未确认：%s %s\n", on ? "开" : "关", miio_reply_name(r), detail);
        setMiioState(false);
    }
    return r;
}

// 带重试的开关电源（用于"恢复插板供电"这类一次性小操作，只有设备确认才算成功）
bool miio_setPower(bool on) {
    for (int attempt = 1; attempt <= 3; attempt++) {
        if (miio_setPowerTry(on) == MIIO_REPLY_OK) return true;
        logPrintf("设置电源(%s) 第 %d/3 次未确认\n", on ? "开" : "关", attempt);
        delay(300);
    }
    return false;
}

// ==================== WiFi 管理 ====================
void ensureWifiConnected() {
    // WiFi 切换/回退由 wifiSwitchStep() 专门负责，期间不做常规重连，
    // 否则会用旧 SSID 去抢正在尝试的新网络。
    if (wifiSwitchPhase != WF_IDLE) return;

    if (WiFi.status() == WL_CONNECTED) {
        if (!wifiWasConnected) {
            logPrintln("\nWiFi 已连接: " + WiFi.localIP().toString());
            logPrintf("信号强度 RSSI: %d dBm\n", WiFi.RSSI());
            wifiWasConnected = true;

            if (wifiDownSince != 0) {
                logPrintf("WiFi 中断约 %lu 秒\n", (millis() - wifiDownSince) / 1000);
                wifiDownSince = 0;
            }

            WiFi.setSleep(false);
            ledStopBlink();   // 先熄灭，待握手结果决定是否常亮

            udp.stop();
            if (udp.begin(LOCAL_PORT) != 1) {
                logPrintln("!!! UDP 端口绑定失败，miIO 将无法工作 !!!");
            }

            rebooting     = false;
            lastPingTime  = millis();
            lastMiioCheck = millis();

            // ★ 修复1：这里绝对不能再写 linkDownSince = 0。
            //   WiFi 重连只说明链路层恢复，外网是否恢复要由 ping 说了算；
            //   否则每次 WiFi 抖动都会把断网计时清零，10 分钟阈值永远达不到。

            // ★ WiFi 重连后强制重新握手
            logPrintln("WiFi 重连，重新进行 miIO 握手...");
            if (miio_handshake()) {
                logPrintln("WiFi 重连后握手成功");
            } else {
                logPrintf("WiFi 重连后握手失败，LED 常亮，%lu 秒后重试\n", MIIO_RETRY_INTERVAL / 1000);
            }
        }
        return;
    }

    if (wifiWasConnected) {
        logPrintln("\nWiFi 断开，进入重连流程");
        wifiWasConnected = false;
        wifiDownSince = millis();
        // ★ 修复1：断网计时保持不动，WiFi 中断的时间会自然计入 linkDownSince
        ledStartBlink();
    }

    if (!ledBlinking && !ledError && !fatalActive()) ledStartBlink();

    unsigned long now = millis();
    if (now - lastWifiRetry < WIFI_RETRY_INTERVAL) return;
    lastWifiRetry = now;

    logPrintln("尝试重连 WiFi...");
    WiFi.disconnect();
    delay(100);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
}

// ==================== WiFi 切换状态机（由主循环分步推进）====================
// 为什么必须分步：旧版在 HTTP handler 里直接 WiFi.disconnect() 会掐断与浏览器的 TCP 连接，
// 浏览器永远收不到响应（现象就是"保存后页面一直转圈"）。现在：
//   ① handler 先把 HTTP 响应发出去，只暂存新 SSID/口令并把状态置为 TRYING；
//   ② 主循环再等 800ms（确保响应已送达）才断开并试连新网络；
//   ③ 成功 → 保存到 NVS；20 秒仍连不上 → 回退旧 SSID/口令（此时旧配置本来就没被覆盖）。
// 整个过程中 loop 照常运行：LED、Web 请求、BOOT 键检测都不受影响。
void wifiSwitchStep() {
    if (wifiSwitchPhase == WF_IDLE) return;
    unsigned long now = millis();

    if (wifiSwitchPhase == WF_ROLLBACK) {
        if (WiFi.status() == WL_CONNECTED) {
            logPrintf("已回退到原 WiFi，当前 IP: %s\n", WiFi.localIP().toString().c_str());
            wifiWasConnected = false;   // 交给 WiFi 恢复流程重绑 UDP + 重新握手
            wifiSwitchPhase = WF_IDLE;
        } else if (now - wifiSwitchStart > 60000) {
            logPrintln("回退后 60 秒仍未连上原 WiFi，交由常规重连流程继续尝试");
            wifiSwitchPhase = WF_IDLE;
        }
        return;
    }

    // WF_TRYING：先给 HTTP 响应留出发送时间，再真正断开
    if (wifiSwitchArmAt != 0) {
        if (now < wifiSwitchArmAt) return;
        wifiSwitchArmAt = 0;
        logPrintf("正在切换到新 WiFi \"%s\"...\n", wifiNewSsid);
        WiFi.disconnect();
        delay(100);
        WiFi.begin(wifiNewSsid, wifiNewPass);
        wifiSwitchStart  = millis();
        wifiWasConnected = false;      // 链路必然中断，恢复时走完整流程
        wifiDownSince    = millis();
        ledStartBlink();
        return;
    }

    if (WiFi.status() == WL_CONNECTED) {
        strlcpy(WIFI_SSID, wifiNewSsid, sizeof(WIFI_SSID));
        strlcpy(WIFI_PASSWORD, wifiNewPass, sizeof(WIFI_PASSWORD));
        WiFi.setSleep(false);
        wifiWasConnected = false;      // 让主循环走完整恢复流程（重绑 UDP + 重新握手）
        logPrintf("WiFi 切换成功，当前 IP: %s\n", WiFi.localIP().toString().c_str());
        if (saveConfig()) {
            logPrintln("新 WiFi 配置已写入 NVS");
        } else {
            logPrintln("!!! WiFi 已切换，但新配置写入 NVS 失败（重启后会回到旧 WiFi）!!!");
        }
        wifiSwitchPhase = WF_IDLE;
        return;
    }

    if (now - wifiSwitchStart >= 20000) {
        logPrintln("新 WiFi 连接失败（20 秒超时），回退原 WiFi，SSID/口令未保存");
        wifiSwitchPhase = WF_ROLLBACK;
        wifiSwitchStart = millis();
        WiFi.disconnect();
        delay(100);
        WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    }
}

// ==================== 单槽控制标志 ====================
// 忙 = 有远程动作待执行 / 断电重启状态机在跑 / WiFi 切换在跑；此时新的控制请求返回 409。
bool controlBusy() {
    return pendingAction != PA_NONE || rebootPhase != RB_IDLE || wifiSwitchPhase != WF_IDLE;
}

// ==================== 断电重启状态机（由主循环分步推进）====================
// 旧版是一个从头阻塞到尾的函数（握手 + 断电重试 + 等待 REBOOT_OFF_TIME + 上电重试），
// 期间 loop 完全停住。现拆成阶段，等待阶段不阻塞：
//   RB_HANDSHAKE → RB_POWER_OFF（每次尝试一步，最多 3 次）→ RB_WAIT_OFF（非阻塞等待）
//   → RB_POWER_ON（同样每次尝试一步）→ 收尾
// 自动触发与"手动重启光猫"走同一个状态机，行为一致；手动触发不计入熔断计数。
void rebootStart(bool fromManual) {
    if (rebootPhase != RB_IDLE) {
        logPrintln("已有重启流程在执行，忽略本次重启请求");
        return;
    }
    rebootFromManual = fromManual;
    rebootPhase      = RB_HANDSHAKE;
    rebootPhaseStart = millis();
    rebootLastTry    = 0;
    rebootTry        = 0;
    rebootOffOK      = false;
    logPrintf(">>> 开始重启光猫流程（%s触发）\n", fromManual ? "手动" : "看门狗自动");
}

// 收尾：进入冷却期，并对"看门狗自动触发"的重启计数（+1，与动作是否真正完成无关）。
// 手动触发不计入熔断计数：熔断只约束看门狗自己的自动动作，
// 人在页面上连点几次不应该把自动保护触发掉。
// 日志明确区分"动作完成 / 动作未完成"。
void rebootFinish(bool offOK, bool onOK) {
    if (offOK && onOK) {
        logPrintln("本次重启动作完成：插板已断电并确认恢复供电");
    } else if (!offOK) {
        logPrintln("本次重启动作未完成：插板可能从未断电，光猫未真正重启");
    } else {
        logPrintln("本次重启动作未完成：已断电，但恢复供电未得到设备确认");
    }

    if (!onOK) {
        // 最坏情况：断电成功但上电命令始终没被确认 → 光猫会一直断电，必须人工介入
        powerFault = true;
        logPrintln("!!! 严重：无法确认插板已恢复供电，光猫可能仍处于断电状态，请人工检查（LED 快闪）!!!");
    }

    linkDownSince = 0;      // 重新开始断网计时
    rebooting     = true;   // 进入重启冷却期
    rebootTime    = millis();

    // ★ 计数只统计"看门狗自己触发的重启"：每次触发 +1，与动作是否真正完成无关
    //   （否则插板不可用 / Token 错误时会无限重试且永不熔断）。
    if (rebootFromManual) {
        logPrintln("本次由手动触发，不计入熔断计数");
    } else {
        rebootAttempts++;
        logPrintf("已累计 %d 次自动重启动作（上限 %d 次）\n", rebootAttempts, MAX_REBOOT_ATTEMPTS);
        if (rebootAttempts >= MAX_REBOOT_ATTEMPTS) {
            fatalLatched = true;
            logPrintln("!!! 重启动作已达上限，已熔断：只观察、不再动手，"
                       "请人工检查网络与 Ping 目标配置（LED 快闪）!!!");
        }
    }
    saveRuntimeState();     // 熔断/计数/powerFault 有变化就落盘（低频写入）
    rebootPhase = RB_IDLE;
}

void rebootStep() {
    if (rebootPhase == RB_IDLE) return;
    unsigned long now = millis();

    switch (rebootPhase) {
        case RB_HANDSHAKE:
            logPrintln("尝试重启光猫...");
            if (WiFi.status() != WL_CONNECTED) {
                logPrintln("WiFi 未连接，无法控制插板");
                rebootFinish(false, false);
                return;
            }
            if (!miio_handshake()) {
                // miio_handshake 内部已把 miIO 状态置为异常（LED 常亮）
                logPrintln("miIO 握手失败，无法控制插板");
                lastMiioCheck = millis();
                rebootFinish(false, false);
                return;
            }
            rebootTry        = 0;
            rebootLastTry    = 0;
            rebootPhase      = RB_POWER_OFF;
            rebootPhaseStart = millis();
            return;

        case RB_POWER_OFF: {
            if (rebootTry > 0 && now - rebootLastTry < 300) return;   // 重试之间留 300ms
            if (rebootTry >= 3) {
                logPrintln("无法确认插板已断电（3 次命令均未得到设备确认），仍继续断电等待");
                rebootOffOK      = false;
                rebootTry        = 0;
                rebootPhase      = RB_WAIT_OFF;
                rebootPhaseStart = millis();
                return;
            }
            rebootTry++;
            rebootLastTry = now;
            logPrintf("关闭插板电源（第 %d/3 次）...\n", rebootTry);
            if (miio_setPowerTry(false) == MIIO_REPLY_OK) {
                logPrintln("插板已断电（设备已确认）");
                rebootOffOK      = true;
                rebootTry        = 0;
                rebootPhase      = RB_WAIT_OFF;
                rebootPhaseStart = millis();
            }
            return;
        }

        case RB_WAIT_OFF:
            // 非阻塞等待：这一段时间 loop 照常处理 Web 请求、LED 与 BOOT 键
            if (now - rebootPhaseStart < REBOOT_OFF_TIME) return;
            logPrintf("断电已持续 %lu 秒，准备恢复供电\n", REBOOT_OFF_TIME / 1000);
            rebootTry     = 0;
            rebootLastTry = 0;
            rebootPhase   = RB_POWER_ON;
            return;

        case RB_POWER_ON: {
            if (rebootTry > 0 && now - rebootLastTry < 300) return;
            if (rebootTry >= 3) {
                rebootFinish(rebootOffOK, false);
                return;
            }
            rebootTry++;
            rebootLastTry = now;
            logPrintf("打开插板电源（第 %d/3 次）...\n", rebootTry);
            if (miio_setPowerTry(true) == MIIO_REPLY_OK) {
                rebootFinish(rebootOffOK, true);
            }
            return;
        }

        default:
            rebootPhase = RB_IDLE;
            return;
    }
}

void checkMiioHeartbeat() {
    if (WiFi.status() != WL_CONNECTED) return;
    if (miioOK) return;                        // 状态正常，无需重试（不再依赖 ledError 反推）
    if (rebootPhase != RB_IDLE) return;        // 重启流程自己会握手，避免争抢 UDP
    if (wifiSwitchPhase != WF_IDLE) return;

    unsigned long now = millis();
    if (now - lastMiioCheck < MIIO_RETRY_INTERVAL) return;
    lastMiioCheck = now;

    logPrintf("miIO 状态异常，尝试重新握手（重试间隔 %lu 秒）...\n", MIIO_RETRY_INTERVAL / 1000);
    if (miio_handshake()) {
        logPrintln("重新握手成功，miIO 已恢复正常");
    } else {
        logPrintf("重新握手仍失败，%lu 秒后重试\n", MIIO_RETRY_INTERVAL / 1000);
    }
}

void checkNetwork() {
    unsigned long now = millis();

    // WiFi 断开时直接返回，但不清零 linkDownSince（WiFi 中断的时间仍计入断网时长）；
    // 稳定在线计时必须清零：链路都断了当然不算"连续在线"。
    if (WiFi.status() != WL_CONNECTED) {
        onlineSince = 0;
        return;
    }

    // WiFi 切换与断电重启期间看门狗让路（重启收尾会重置断网计时并进冷却）
    if (wifiSwitchPhase != WF_IDLE) return;
    if (rebootPhase != RB_IDLE) return;

    // 冷却期检查
    if (rebooting) {
        if (now - rebootTime < REBOOT_COOLDOWN) return;
        rebooting = false;
        logPrintln("冷却期结束，恢复检测");
    }

    if (now - lastPingTime < PING_INTERVAL) return;
    lastPingTime = now;   // 计时点放在 ping 之前，节奏更准

    // 短路：第一个通就不测第二个。单次 ping 超时固定 1 秒（PING_TIMEOUT_S）
    bool online = Ping.ping(PING_IP1, PING_TIMEOUT_S);
    if (!online) {
        delay(50);
        online = Ping.ping(PING_IP2, PING_TIMEOUT_S);
    }

    if (online) {
        pingFailStreak = 0;
        if (linkDownSince != 0) {
            logPrintf("网络恢复（不可达约 %lu 秒），重置断网计时\n",
                      (now - linkDownSince) / 1000);
        }
        linkDownSince = 0;

        if (onlineSince == 0) onlineSince = now;   // 本轮"在线"的起点

        // ★ 网络恢复后不立即清零重启计数/熔断：必须"连续在线满 5 分钟"才清零，
        //   否则网络刚闪一下恢复就把熔断解除了，看门狗会陷入无限重启。
        if ((fatalLatched || powerFault || rebootAttempts > 0) &&
            (now - onlineSince >= ONLINE_STABLE_MS)) {
            clearFatalState("连续在线满 5 分钟");
        }
        return;
    }

    // 离线：稳定在线计时归零
    onlineSince = 0;

    // ★ 连续 2 次 ping 检测都失败才开始断网计时（防单次抖动误判）
    pingFailStreak++;
    if (pingFailStreak < 2) {
        logPrintf("本次检测失败（第 %d/2 次），暂不开始断网计时\n", pingFailStreak);
        return;
    }

    if (linkDownSince == 0) {
        linkDownSince = now;
        logPrintln("连续 2 次检测均失败，开始断网计时");
        return;
    }

    unsigned long offlineDuration = now - linkDownSince;
    logPrintf("断网已持续 %lu 秒（连续失败 %d 次）\n", offlineDuration / 1000, pingFailStreak);

    // 已熔断则只观察、不再动手，等网络自己恢复或人工介入
    if (fatalLatched) return;

    if (offlineDuration < OFFLINE_THRESHOLD) return;

    logPrintln("连续断网达到阈值，触发光猫重启");
    rebootStart(false);     // 交给主循环分步执行；计数与冷却在收尾时统一处理
}

// ==================== 主程序 ====================
void setup() {
    Serial.begin(115200);
    delay(1000);
    logPrintln("\n=== 光猫看门狗启动 ===");

    // 初始化 LED（放在最前，后续流程全程可用）
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LED_OFF);

    // BOOT 键用于"运行期"长按恢复出厂（检测见 checkFactoryResetButton）。
    // ★ 这里只初始化引脚、不做开机检测：C3 的 GPIO9 是 strapping 引脚，
    //   上电瞬间按住它会直接进入 ROM 下载模式，程序根本跑不到这里。
    pinMode(BOOT_BTN_PIN, INPUT_PULLUP);
    logPrintln("离线兜底：运行中按住 BOOT 键 5 秒可恢复出厂配置");

    // ===== 从 NVS 加载已保存的配置（覆盖文件里的默认值）=====
    loadConfig();
    logPrintf("配置已加载：WiFi=\"%s\" 插板=%s siid=%d/piid=%d Ping=%s/%s\n",
              WIFI_SSID, DEVICE_IP, SIID, PIID, PING_IP1, PING_IP2);
    logPrintf("看门狗阈值：检测 %lus / 断网 %lus / 冷却 %lus / 断电 %lus / miIO重试 %lus / 最大重启 %d 次\n",
              PING_INTERVAL / 1000, OFFLINE_THRESHOLD / 1000, REBOOT_COOLDOWN / 1000,
              REBOOT_OFF_TIME / 1000, MIIO_RETRY_INTERVAL / 1000, MAX_REBOOT_ATTEMPTS);
    logPrintf("稳定在线期：连续在线 %lu 分钟才清零重启计数与熔断\n", ONLINE_STABLE_MS / 60000);

    // ★ Token 只解析一次（严格十六进制），握手校验与命令 checksum 复用同一份字节；
    //   插板 IP/Token/siid/piid 变更时会在 handleConfigSave() 中重新解析。
    if (!parseToken()) {
        logPrintln("!!! DEVICE_TOKEN 格式错误（应为 32 个十六进制字符），无法控制插板 !!!");
        powerFault = true;      // 硬故障 → LED 快闪，提示人工检查配置
    }

    if (!fatalActive()) ledStartBlink();

    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    // 等待 WiFi：期间仍然响应 BOOT 键长按（离线兜底）并刷新 LED；
    // ★ 不要每 50ms 打一个点：那会把 16KB 环形日志瞬间刷满，改为每 5 秒打一行进度。
    logPrintf("开始连接 WiFi \"%s\"...\n", WIFI_SSID);
    unsigned long connectStart  = millis();
    unsigned long lastProgress  = connectStart;
    uint32_t      connectRetry  = 0;
    while (WiFi.status() != WL_CONNECTED) {
        ledUpdate();
        checkFactoryResetButton();     // 连不上网时也能长按 BOOT 恢复出厂
        delay(50);

        unsigned long now = millis();
        if (now - lastProgress >= 5000) {
            lastProgress = now;
            logPrintf("等待 WiFi 连接...已等 %lu 秒（状态=%d，RSSI=%d dBm）\n",
                      (now - connectStart) / 1000, (int)WiFi.status(), (int)WiFi.RSSI());
        }
        if (now - connectStart > 30000) {
            connectRetry++;
            logPrintf("连接超时（30 秒），第 %lu 次重新尝试...\n", (unsigned long)connectRetry);
            WiFi.disconnect();
            delay(100);
            WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
            connectStart = millis();
            lastProgress = connectStart;
        }
    }
    logPrintln("\nWiFi connected: " + WiFi.localIP().toString());
    logPrintf("信号强度 RSSI: %d dBm\n", WiFi.RSSI());

    wifiWasConnected = true;
    ledStopBlink();

    udp.stop();
    if (udp.begin(LOCAL_PORT) != 1) {
        logPrintln("!!! UDP 端口绑定失败，miIO 将无法工作 !!!");
    }

    // ===== 远程管理 Web 服务（WiFi 就绪后启动）=====
    // 此后浏览器访问 http://<设备IP>/ 即可查看日志、控制插板、修改配置；
    // WiFi 重连后无需重启服务，IP 变化时按新 IP 访问即可。
    webServerSetup();
    if (webReady) {
        const char* authState = webPasswordHash[0] ? "已启用访问鉴权（用户名 admin）"
                                                   : "无鉴权，仅限可信局域网";
        if (activeWebPort == 80) {
            logPrintf("远程管理已开启: http://%s/（%s）\n",
                      WiFi.localIP().toString().c_str(), authState);
        } else {
            logPrintf("远程管理已开启: http://%s:%u/（%s）\n",
                      WiFi.localIP().toString().c_str(), (unsigned)activeWebPort, authState);
        }
    }

    // 初次握手：成功 → miioOK=true、LED 熄灭；失败 → 常亮（提示 Token/IP/插板问题）
    if (miio_handshake()) {
        logPrintln("初始握手成功，LED 熄灭");
    } else {
        logPrintf("初始握手失败（%lu 秒后自动重试）\n", MIIO_RETRY_INTERVAL / 1000);
    }

    lastPingTime  = millis();
    lastMiioCheck = millis();
    linkDownSince = 0;
    onlineSince   = 0;
}

// 说明：这里刻意不挂 esp_task_wdt —— Ping.ping() 是不可干预的阻塞调用，
// 一旦阻塞超过看门狗超时就会复位设备，反而制造重启循环。
// 阻塞情况（如实描述）：单次 ping ≤1s（最多两次）、miIO 握手 ≤3s、等一条命令确认 ≤2s、
// NVS 读写毫秒级、重启/恢复出厂前 3 秒延迟；WiFi 切换与断电重启已改为状态机分步推进，
// 单步最长约 3 秒，管理页最多短暂变慢，不会再整段无响应。
void loop() {
    if (webReady) webServer.handleClient();          // 远程管理页（非阻塞）
    if (pendingAction != PA_NONE) handlePendingAction();  // 执行远程控制任务
    checkFactoryResetButton();  // BOOT 键长按 5 秒 → 恢复出厂（运行期检测）
    wifiSwitchStep();       // WiFi 切换状态机（非阻塞分步）
    rebootStep();           // 断电重启状态机（非阻塞分步）
    ensureWifiConnected();  // WiFi 管理与重连（不再影响断网计时）
    ledUpdate();            // LED 状态处理
    checkNetwork();         // 外网看门狗
    checkMiioHeartbeat();   // 握手管理
    delay(50);
}
