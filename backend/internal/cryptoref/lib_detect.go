package cryptoref

import (
	"regexp"
	"strings"
)

// 进程×加密库映射：把主机上某进程加载的密码库（soname / 版本串 / 包名）判成
// 「是什么库 + 是否具备后量子能力 + 从哪个版本起」。数据来源与逐条核实见
// docs/superpowers/specs/2026-07-11-pqc-crypto-lib-research.md（§B lib_detection_table）。
//
// 主机 Agent 读 /proc/<pid>/maps 拿到 so 路径，OS 面拿到 dpkg/rpm 包名与版本串，
// 交由本模块判定。判定保守：soname 有歧义（如 libcrypto.so.3 = OpenSSL 或 铜锁）时，
// 需版本串/符号佐证才升 PQC 结论，否则只报「疑似、需佐证」。

// LibInfo 一个被识别的密码库的画像。
type LibInfo struct {
	Library     string // 规范库名（OpenSSL / 铜锁 Tongsuo / openHiTLS / BoringSSL / AWS-LC / SymCrypt / GmSSL / PQMagic / liboqs ...）
	PQCCapable  bool   // 该库（在识别到的版本下）是否具备后量子能力
	SinceNote   string // PQC 起始版本/条件说明
	Ambiguous   bool   // soname 有歧义（需版本串/符号佐证才能定库与 PQC 结论）
	Note        string // 消歧/使用提示
	IsGM        bool   // 是否国密系（含 SM 或中国自研 PQC）
}

// libRule 一条 soname/包名匹配规则。matchRe 命中 so 路径或包名即判。
type libRule struct {
	re   *regexp.Regexp
	info LibInfo
}

// libRules 按优先级排列的匹配规则（越靠前越具体）。基名匹配，大小写不敏感。
var libRules = []libRule{
	// —— 明确 soname（无歧义）——
	{regexp.MustCompile(`(?i)libhitls_(crypto|tls|pki|bsl|auth)`), LibInfo{
		Library: "openHiTLS", PQCCapable: true, IsGM: true,
		SinceNote: "≥0.3.x 含 ML-KEM/ML-DSA/SLH-DSA + 国密 SM2/3/4/9 与 TLCP；不实现 0x11EE",
		Note:      "符号 CRYPT_PKEY_ML_KEM/CRYPT_HYBRID_*；TLS 仅 IANA 混合组 0x11EB/EC/ED"}},
	{regexp.MustCompile(`(?i)libpqmagic`), LibInfo{
		Library: "PQMagic", PQCCapable: true, IsGM: true,
		SinceNote: "全版本（纯 PQC 算法库）",
		Note:      "含中国自研 Aigis-enc/Aigis-sig/SPHINCS-Alpha，全算法可选 SM3 哈希；本身不做 TLS，无版本可判"}},
	{regexp.MustCompile(`(?i)liboqs`), LibInfo{
		Library: "liboqs", PQCCapable: true,
		SinceNote: "全版本（纯 PQC 算法库）",
		Note:      "soname 随 minor 递增(0.8→so.3/0.12→so.7/0.16→so.9)；官方声明勿用于生产"}},
	{regexp.MustCompile(`(?i)oqsprovider`), LibInfo{
		Library: "oqs-provider (OQS)", PQCCapable: true,
		SinceNote: "全版本；ML-KEM final 自 0.8.0",
		Note:      "常静态内嵌 liboqs；经 openssl.cnf 激活，装了≠启用；私有码点可被 OQS_CODEPOINT_* 改写"}},
	{regexp.MustCompile(`(?i)libsymcrypt`), LibInfo{
		Library: "SymCrypt (微软)", PQCCapable: true,
		SinceNote: "v103.5.0 起 ML-KEM；ML-DSA 自 103.7；SLH-DSA 未实现",
		Note:      "soname 主版本 103 即 ABI；无 SM 系、无中国 PQC——命中即可排除国密栈"}},
	{regexp.MustCompile(`(?i)libcrypto-awslc|libssl-awslc|awslc`), LibInfo{
		Library: "AWS-LC", PQCCapable: true,
		SinceNote: "≈v1.30 起 ML-KEM 入 FIPS 边界",
		Note:      "符号 AWS_LC_*；组 0x11EB/EC/ED+0x0200-02；无国密、无 0x11EE"}},
	{regexp.MustCompile(`(?i)libgmssl`), LibInfo{
		Library: "GmSSL (关志/北大)", PQCCapable: true, IsGM: true,
		SinceNote: "3.2.0 起加 PQC（Kyber768/SM3 方言 SPHINCS+/XMSS/LMS）",
		Ambiguous: true,
		Note:      "⚠SOVERSION 恒 3：3.1.x 无 PQC 与 3.2+ 同名，须读版本串 'GmSSL 3.2+' 或符号 kyber_encap；TLS 只协商 0x0029 curveSM2 不发 PQC 组"}},
	{regexp.MustCompile(`(?i)libconscrypt_jni`), LibInfo{
		Library: "Conscrypt (内嵌 BoringSSL)", PQCCapable: true,
		SinceNote: "随内嵌 BoringSSL 快照",
		Note:      "Java/Android TLS provider"}},
	{regexp.MustCompile(`(?i)libs2n\b|/libs2n`), LibInfo{
		Library: "s2n-tls (AWS)", PQCCapable: true,
		SinceNote: "随底层 AWS-LC",
		Note:      "常伴随 aws-lc；AWS KMS/ACM 端点已启用 X25519MLKEM768"}},
	// —— 有歧义的 soname（须版本串/符号佐证）——
	{regexp.MustCompile(`(?i)libcrypto\.so\.3|libssl\.so\.3`), LibInfo{
		Library: "OpenSSL 3.x / 铜锁 Tongsuo（同 soname 歧义）", PQCCapable: false,
		Ambiguous: true,
		SinceNote: "OpenSSL 3.5.0 起原生 PQC；铜锁 8.5.0 起（OpenSSL 3.5.4 底座）",
		Note:      "⚠必须读版本串消歧：'OpenSSL 3.5'+ → PQC 是；'Tongsuo 8.5'/TONGSUO_* 符号 → 铜锁(国密+PQC+唯一默认 0x11EE)；3.0-3.4 无原生 PQC"}},
	{regexp.MustCompile(`(?i)libcrypto\.so\.1|libssl\.so\.1`), LibInfo{
		Library: "OpenSSL 1.x / AWS-LC（歧义）", PQCCapable: false,
		Ambiguous: true,
		SinceNote: "OpenSSL 1.x 无原生 PQC；AWS-LC(SOVERSION 1) 有",
		Note:      "读版本串：'AWS-LC' → PQC 是；'OpenSSL 1.1.1' → 否（除非外挂 provider）"}},
	{regexp.MustCompile(`(?i)/libcrypto\.so$|/libssl\.so$`), LibInfo{
		Library: "BoringSSL（无版本后缀）/ 未版本化 OpenSSL（歧义）", PQCCapable: false,
		Ambiguous: true,
		SinceNote: "BoringSSL rolling：0x11EC 默认 Chrome131",
		Note:      "无 SOVERSION 常是 BoringSSL(Android/system 或静态)；读符号 MLKEM768_encap/版本串 '(compatible; BoringSSL)'"}},
	// —— 经典库（明确无 PQC，报出来供建档）——
	{regexp.MustCompile(`(?i)libgnutls`), LibInfo{Library: "GnuTLS", PQCCapable: false, Note: "经典库，PQC 支持有限/滞后"}},
	{regexp.MustCompile(`(?i)libgcrypt`), LibInfo{Library: "libgcrypt", PQCCapable: false, Note: "GnuPG 密码库，经典"}},
	{regexp.MustCompile(`(?i)libnss3|libnspr4|libsoftokn`), LibInfo{Library: "NSS (Mozilla)", PQCCapable: false, Note: "经典；PQC 逐步引入，须版本佐证"}},
	{regexp.MustCompile(`(?i)libmbedtls|libmbedcrypto`), LibInfo{Library: "mbedTLS", PQCCapable: false, Note: "嵌入式，经典"}},
	{regexp.MustCompile(`(?i)libwolfssl`), LibInfo{Library: "wolfSSL", PQCCapable: false, Ambiguous: true, Note: "较新版本有 PQC，须版本佐证"}},
}

// 版本串消歧模式：从 so 文件/包元数据的可读字符串里认库与版本。
var (
	reTongsuo    = regexp.MustCompile(`(?i)Tongsuo[ /]?(\d+\.\d+\.\d+)|TONGSUO_VERSION`)
	reOpenSSLVer = regexp.MustCompile(`(?i)OpenSSL\s+(\d+)\.(\d+)\.(\d+)`)
	reAWSLC      = regexp.MustCompile(`(?i)AWS-LC`)
	reBoringSSL  = regexp.MustCompile(`(?i)BoringSSL`)
	reGmSSLVer   = regexp.MustCompile(`(?i)GmSSL\s+(\d+)\.(\d+)`)
)

// LookupLib 由 so 路径/包名基础判定库画像（不含版本消歧，Ambiguous 需再调 RefineByVersionString）。
func LookupLib(sonameOrPath string) (LibInfo, bool) {
	base := sonameOrPath
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	for _, r := range libRules {
		if r.re.MatchString(sonameOrPath) || r.re.MatchString(base) {
			return r.info, true
		}
	}
	return LibInfo{}, false
}

// RefineByVersionString 用从 so/包里 strings 出来的可读文本对歧义库做二次消歧，
// 定库名与 PQC 能力。text 可为整个 `strings <so>` 输出或包版本字段。
// 返回精化后的画像；非歧义库原样返回。
func RefineByVersionString(base LibInfo, text string) LibInfo {
	if !base.Ambiguous || text == "" {
		return base
	}
	out := base
	switch {
	case reTongsuo.MatchString(text):
		out.Library = "铜锁 Tongsuo (BabaSSL)"
		out.IsGM = true
		out.Ambiguous = false
		if m := reTongsuo.FindStringSubmatch(text); len(m) > 1 && m[1] != "" {
			out.PQCCapable = versionAtLeast(m[1], 8, 5, 0)
			out.Note = "铜锁 " + m[1] + "：国密 SM 全家桶 + PQC(8.5+)+唯一默认 SM2-ML-KEM 混合组 0x11EE"
		} else {
			out.PQCCapable = true
			out.Note = "铜锁（TONGSUO_* 符号）"
		}
	case reAWSLC.MatchString(text):
		out.Library = "AWS-LC"
		out.Ambiguous = false
		out.PQCCapable = true
		out.Note = "AWS-LC：ML-KEM/X25519MLKEM768；无国密"
	case reBoringSSL.MatchString(text):
		out.Library = "BoringSSL (Google)"
		out.Ambiguous = false
		out.PQCCapable = true // 现代 BoringSSL 默认含 X25519MLKEM768
		out.Note = "BoringSSL：0x11EC 默认(Chrome131+)；无国密"
	case reGmSSLVer.MatchString(text):
		out.Library = "GmSSL (关志/北大)"
		out.IsGM = true
		out.Ambiguous = false
		if m := reGmSSLVer.FindStringSubmatch(text); len(m) > 2 {
			out.PQCCapable = versionAtLeast(m[1]+"."+m[2]+".0", 3, 2, 0)
			out.Note = "GmSSL " + m[1] + "." + m[2] + "：3.2+ 有 PQC(Kyber768/SM3 方言)；TLS 只协商 curveSM2"
		}
	case reOpenSSLVer.MatchString(text):
		m := reOpenSSLVer.FindStringSubmatch(text)
		out.Library = "OpenSSL " + m[1] + "." + m[2] + "." + m[3]
		out.Ambiguous = false
		out.PQCCapable = versionAtLeast(m[1]+"."+m[2]+"."+m[3], 3, 5, 0)
		if out.PQCCapable {
			out.Note = "OpenSSL ≥3.5：原生 ML-KEM/ML-DSA/SLH-DSA，默认组 X25519MLKEM768"
		} else {
			out.Note = "OpenSSL <3.5：无原生 PQC（可外挂 oqs-provider）"
		}
	}
	return out
}

// versionAtLeast 判 "a.b.c" 版本 >= (maj,min,pat)。解析失败按 false（保守）。
func versionAtLeast(v string, maj, min, pat int) bool {
	var a, b, c int
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return false
	}
	a = atoiSafe(parts[0])
	b = atoiSafe(parts[1])
	if len(parts) > 2 {
		c = atoiSafe(parts[2])
	}
	if a != maj {
		return a > maj
	}
	if b != min {
		return b > min
	}
	return c >= pat
}

func atoiSafe(s string) int {
	n := 0
	for _, ch := range strings.TrimSpace(s) {
		if ch < '0' || ch > '9' {
			break
		}
		n = n*10 + int(ch-'0')
	}
	return n
}
