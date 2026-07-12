# M-A：PQC 识别引擎 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让烛龙 PQM 在被动流量、主动扫描、评分、CBOM 全链路正确识别并正面建档后量子（PQC）与国密混合密钥交换（X25519MLKEM768、curveSM2MLKEM768 等），验收锚点为 `~/Desktop/VPN客户端后量子抓包.pcapng`。

**Architecture:** 新增纯函数包 `internal/cryptoref/`（TLS 命名组码点表 + PQC 算法表 + 分类逻辑），被 `pcap_tls.go`（被动解析扩展）、新 `pqc_probe.go`（主动枚举）、`scoring`、`cbom` 复用。`CryptoAsset` 增 `KexGroup/KexSafety/AuthSafety/ReportedBy` 四字段做「密钥交换维 × 认证维」双维量子安全建模；评分 `deriveD1` 加 PQC 分支，HNDL 在 runner 层按 KexSafety 清除。

**Tech Stack:** Go 1.24（纯 Go 免 CGO）、GORM + glebarez SQLite、Vue3 + Arco（前端展示）。测试用 `go test`。

## Global Constraints

- **纯 Go 免 CGO 硬约束**：不得引入任何 CGO 依赖（信创鲲鹏/飞腾交叉编译）。
- **新模型字段必须加进 `internal/db/db.go` 的 `AutoMigrate` 清单**，否则 SQLite 不建列。
- commit 前缀：功能用 `feat(scope):`，安全用 `security:`；全程中文提交信息。
- 后端端口 :8099；不可改动 `frontend/dist`、`deploy/dist`、`*.tar.gz`、`backend/zhulong-pqm.db` 等生成物。
- 判定优先级铁律：**TLS 命名组码点本体是权威判据，key_share 尺寸只作未知码点兜底**（0x11EB 与 0x11EE 尺寸相同，必须靠码点区分）。
- GREASE 码点（形如 `0x?A?A`）一律当噪声，绝不记为未知 PQC 组。
- 不改动 `scoring.Score`/`ScoreWith` 的 HNDL 公式（`D2>=60 && D3>=60`）——它被 7 条预设画像单测锁定；HNDL 的「KEX 已迁移则清除」逻辑放在 runner 层。
- 验收数据源 `~/Desktop/VPN客户端后量子抓包.pcapng` 属用户私有抓包，**不入库**（不 commit 进 testdata）；自动化测试用合成字节，真机验收用运行中的 app 上传该文件人工核对。
- 所有对不可信字节（pcap/握手）的解析必须严格守界、遇截断安全返回、绝不 panic（沿用 `pcap_tls.go` 既有风格）。

## 参考：完整引擎字典

三张字典全表见 `docs/superpowers/specs/2026-07-11-pqc-crypto-lib-research.md`。本计划在 Go 表里落地其**核心子集 + 分类逻辑**；OQS 私有段全表、XMSS/LMS/Composite 等可后续补录，不阻塞 M-A。

## 本计划范围外（明确不做）

- `cryptoref/lib_detect.go`（进程×加密库映射表）→ 归 M-C（主机 Agent），M-A 无消费方。
- 新增 `R-*-PQC` 正面 seed 规则 → 需重设 `seed_rules.go` 的 total=30/critical=7/P1=14 自检基线，风险大；M-A 只让 `rules.go` 既有排除滤镜正确识别更全的 PQC 组集合。正面事实已由资产级 `KexSafety`/D1/HNDL/CBOM 表达。
- 真实 PQC 密码运算（密钥封装完整握手）→ 主动探测用枚举式 HRR 反射，无需算 KEM。

---

## File Structure

- **Create** `backend/internal/cryptoref/named_groups.go` — TLS 命名组码点表 + `ClassifyGroup`/`IsGREASEGroup`/`KexSafetyForGroup`（含尺寸兜底）。
- **Create** `backend/internal/cryptoref/named_groups_test.go`
- **Create** `backend/internal/cryptoref/algorithms.go` — PQC 算法表 + `AuthSafetyForAlgo`/`AlgoInfo`/`KexMitigatesHNDL`/`SafetyFromKind`。
- **Create** `backend/internal/cryptoref/algorithms_test.go`
- **Create** `backend/internal/scan/pqc_probe.go` — 主动枚举探针（raw ClientHello 构造 + HRR 组解析）。
- **Create** `backend/internal/scan/pqc_probe_test.go`
- **Modify** `backend/internal/model/model.go` — `CryptoAsset` 加 4 字段 + 安全态枚举常量；`ScanResult` 加 `KexGroup`。
- **Modify** `backend/internal/db/db.go` — 确认 `CryptoAsset` 已在 `AutoMigrate`（加字段无需改清单，但要验证）。
- **Modify** `backend/internal/scoring/scoring.go` — `DeriveInput` 加 `KexSafety/AuthSafety`；`deriveD1` 加 PQC 分支；`optionsD1` 加两档。
- **Modify** `backend/internal/scoring/scoring_test.go`
- **Modify** `backend/internal/scan/pcap_tls.go` — `tlsHandshake` 加组字段；解析 `supported_groups`/`key_share`。
- **Modify** `backend/internal/scan/pcap.go` — `TLSObservation` 加 `KexGroup/KexSafety`；`ParsePCAP` 循环回填。
- **Modify** `backend/internal/scan/pcap_test.go`
- **Modify** `backend/internal/api/import.go` — `TLSObservation`→`ScanResult` 映射带 `KexGroup`。
- **Modify** `backend/internal/scan/runner.go` — `upsertAsset`/`upsertImportedAsset` 经 `cryptoref` 算双维安全态、喂 `DeriveInput`、清 HNDL、写资产字段。
- **Modify** `backend/internal/cbom/cbom.go` — `primitiveOf`/`cryptoFunctions` 加 PQC 分支；填 `NISTQuantumSecurityLevel`/`ClassicalSecurityLevel`/`OID`/`parameterSetIdentifier`。
- **Modify** `backend/internal/cbom/cbom.go`（同文件测试新增 `cbom_test.go`）。
- **Modify** `backend/internal/scan/rules.go` — `isClassicKEX`/`isClassicSig` 经 `cryptoref` 识别更全 PQC 组集。
- **Modify** `frontend/src/api/types.ts` + `frontend/src/views/Assets.vue`/`RiskAssessment.vue`/`BigScreen.vue` — 展示 KexGroup/双维安全态/迁移分布。

---

## Task 1: cryptoref 命名组码点表与分类

**Files:**
- Create: `backend/internal/cryptoref/named_groups.go`
- Test: `backend/internal/cryptoref/named_groups_test.go`

**Interfaces:**
- Produces:
  - `const SafetySafe="safe"; SafetyHybrid="hybrid"; SafetyClassical="classical"; SafetyNA="na"`
  - `func ClassifyGroup(codepoint int) (name string, kind string, isIANA bool, known bool)` — kind ∈ {"classical","hybrid","pqc"}
  - `func IsGREASEGroup(codepoint int) bool`
  - `func KexSafetyForGroup(codepoint int, clientKeyShareLen int) (group string, safety string)` — safety ∈ {safe,hybrid,classical}；GREASE 返回 `("","")`

- [ ] **Step 1: Write the failing test**

Create `backend/internal/cryptoref/named_groups_test.go`:

```go
package cryptoref

import "testing"

func TestClassifyGroup_KnownCodepoints(t *testing.T) {
	cases := []struct {
		cp    int
		name  string
		kind  string
		iana  bool
	}{
		{0x11EC, "X25519MLKEM768", "hybrid", true},
		{0x11EE, "curveSM2MLKEM768", "hybrid", true},
		{0x11EB, "SecP256r1MLKEM768", "hybrid", true},
		{0x0201, "MLKEM768", "pqc", true},
		{0x001D, "x25519", "classical", true},
		{0x0029, "curveSM2", "classical", true},
		{0x6399, "X25519Kyber768Draft00", "hybrid", true},
	}
	for _, c := range cases {
		name, kind, iana, known := ClassifyGroup(c.cp)
		if !known {
			t.Fatalf("0x%04X should be known", c.cp)
		}
		if name != c.name || kind != c.kind || iana != c.iana {
			t.Errorf("0x%04X = (%q,%q,%v), want (%q,%q,%v)", c.cp, name, kind, iana, c.name, c.kind, c.iana)
		}
	}
}

func TestIsGREASEGroup(t *testing.T) {
	for _, g := range []int{0x0A0A, 0x1A1A, 0x2A2A, 0xFAFA} {
		if !IsGREASEGroup(g) {
			t.Errorf("0x%04X should be GREASE", g)
		}
	}
	for _, ng := range []int{0x11EC, 0x001D, 0x0201} {
		if IsGREASEGroup(ng) {
			t.Errorf("0x%04X should NOT be GREASE", ng)
		}
	}
}

func TestKexSafetyForGroup(t *testing.T) {
	// 已知码点：直接取 kind→safety
	if g, s := KexSafetyForGroup(0x11EE, 1249); g != "curveSM2MLKEM768" || s != SafetyHybrid {
		t.Errorf("0x11EE = (%q,%q), want (curveSM2MLKEM768,hybrid)", g, s)
	}
	if g, s := KexSafetyForGroup(0x0201, 1184); g != "MLKEM768" || s != SafetySafe {
		t.Errorf("0x0201 = (%q,%q), want (MLKEM768,safe)", g, s)
	}
	if _, s := KexSafetyForGroup(0x001D, 32); s != SafetyClassical {
		t.Errorf("0x001D safety = %q, want classical", s)
	}
	// GREASE：噪声
	if g, s := KexSafetyForGroup(0x1A1A, 1); g != "" || s != "" {
		t.Errorf("GREASE = (%q,%q), want empty", g, s)
	}
	// 未知码点 + 大 key_share → 尺寸兜底 hybrid（保守判含 PQC）
	if _, s := KexSafetyForGroup(0x9ABC, 1249); s != SafetyHybrid {
		t.Errorf("unknown big = %q, want hybrid", s)
	}
	// 未知码点 + 小 key_share → classical
	if _, s := KexSafetyForGroup(0x9ABC, 65); s != SafetyClassical {
		t.Errorf("unknown small = %q, want classical", s)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/cryptoref/ -v`
Expected: FAIL — 编译错误 `undefined: ClassifyGroup` 等。

- [ ] **Step 3: Write minimal implementation**

Create `backend/internal/cryptoref/named_groups.go`:

```go
// Package cryptoref 集中 TLS 命名组码点、PQC 算法与量子安全态分类，
// 供被动解析、主动探针、评分、CBOM 复用。全部为纯函数、无副作用、无 CGO。
//
// 数据来源与逐条 IANA 校验见 docs/superpowers/specs/2026-07-11-pqc-crypto-lib-research.md。
package cryptoref

import "fmt"

// 量子安全态三分类 + 不适用。
const (
	SafetySafe      = "safe"      // 纯 PQC
	SafetyHybrid    = "hybrid"    // 经典+PQC 混合
	SafetyClassical = "classical" // 纯经典
	SafetyNA        = "na"        // 该维不适用
)

// group 一个命名组的静态元信息。
type group struct {
	name string
	kind string // classical / hybrid / pqc
	iana bool
}

// namedGroups TLS supported_groups/key_share 码点核心表。
// 完整表（含全部 OQS 私有段）见 spec 附录；此处覆盖驱动 M-A 的核心码点。
var namedGroups = map[int]group{
	// 经典基线
	0x0017: {"secp256r1", "classical", true},
	0x0018: {"secp384r1", "classical", true},
	0x0019: {"secp521r1", "classical", true},
	0x001D: {"x25519", "classical", true},
	0x001E: {"x448", "classical", true},
	0x0029: {"curveSM2", "classical", true}, // IANA#41 RFC8998 国密经典指纹
	// 纯 ML-KEM（IANA#512-514）
	0x0200: {"MLKEM512", "pqc", true},
	0x0201: {"MLKEM768", "pqc", true},
	0x0202: {"MLKEM1024", "pqc", true},
	// IANA 混合组（RFC-ietf-tls-ecdhe-mlkem）
	0x11EB: {"SecP256r1MLKEM768", "hybrid", true},
	0x11EC: {"X25519MLKEM768", "hybrid", true},   // 唯一 Rec=Y，互联网主流
	0x11ED: {"SecP384r1MLKEM1024", "hybrid", true},
	0x11EE: {"curveSM2MLKEM768", "hybrid", true}, // 国密 SM2+ML-KEM，铜锁 Tongsuo 8.5+
	// 已废弃/历史（识别旧流量）
	0x6399: {"X25519Kyber768Draft00", "hybrid", true},
	0x639A: {"SecP256r1Kyber768Draft00", "hybrid", true},
	0x4138: {"CECPQ2", "hybrid", false},
	0xFEFE: {"curveSM2MLKEM768(draft-02)", "hybrid", false}, // 旧版铜锁时间指纹
}

// ClassifyGroup 查表：返回组名、kind、是否 IANA、是否已知。GREASE 视为未知（交由上层丢弃）。
func ClassifyGroup(codepoint int) (name string, kind string, isIANA bool, known bool) {
	if g, ok := namedGroups[codepoint]; ok {
		return g.name, g.kind, g.iana, true
	}
	return "", "", false, false
}

// IsGREASEGroup 判断是否 GREASE 占位（0x0A0A、0x1A1A…0xFAFA；RFC 8701）。
func IsGREASEGroup(codepoint int) bool {
	return (codepoint&0x0f0f) == 0x0a0a && (codepoint>>8) == (codepoint&0xff)
}

// SafetyFromKind 组 kind → 量子安全态（pqc→safe，hybrid→hybrid，classical→classical）。
func SafetyFromKind(kind string) string {
	switch kind {
	case "pqc":
		return SafetySafe
	case "hybrid":
		return SafetyHybrid
	default:
		return SafetyClassical
	}
}

// KexSafetyForGroup 由码点（+客户端 key_share 字节数兜底）判密钥交换维安全态。
//
// 判定优先级：① GREASE→噪声（返回空）；② 命中表→按 kind；
// ③ 未知码点→尺寸兜底：client key_share >1000B 基本必是格基 KEM（经典组最大 P-521=133B），
// 保守判 hybrid（含 PQC 成分即可缓解 HNDL），否则 classical。
func KexSafetyForGroup(codepoint int, clientKeyShareLen int) (groupName string, safety string) {
	if IsGREASEGroup(codepoint) {
		return "", ""
	}
	if name, kind, _, known := ClassifyGroup(codepoint); known {
		return name, SafetyFromKind(kind)
	}
	if clientKeyShareLen > 1000 {
		return fmt.Sprintf("unknown-0x%04X", codepoint), SafetyHybrid
	}
	return fmt.Sprintf("unknown-0x%04X", codepoint), SafetyClassical
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/cryptoref/ -v`
Expected: PASS（3 个测试全绿）。

- [ ] **Step 5: Commit**

```bash
cd backend && git add internal/cryptoref/named_groups.go internal/cryptoref/named_groups_test.go
git commit -m "feat(cryptoref): TLS 命名组码点表 + 量子安全态分类(码点权威·尺寸兜底·GREASE 丢弃)"
```

---

## Task 2: cryptoref 算法表与认证维安全态

**Files:**
- Create: `backend/internal/cryptoref/algorithms.go`
- Test: `backend/internal/cryptoref/algorithms_test.go`

**Interfaces:**
- Consumes: `SafetySafe/SafetyHybrid/SafetyClassical/SafetyNA`（Task 1）
- Produces:
  - `func AuthSafetyForAlgo(algo string) string` — 认证/签名算法 → safety；`""→na`
  - `func KexMitigatesHNDL(kexSafety string) bool` — safe/hybrid 返回 true
  - `type AlgoInfo struct { Primitive, OID, ParamSet string; QuantumLevel int }`
  - `func LookupAlgo(algo string) (AlgoInfo, bool)` — CBOM 用（primitive/oid/nist 量子等级）

- [ ] **Step 1: Write the failing test**

Create `backend/internal/cryptoref/algorithms_test.go`:

```go
package cryptoref

import "testing"

func TestAuthSafetyForAlgo(t *testing.T) {
	cases := map[string]string{
		"":                 SafetyNA,
		"RSA":              SafetyClassical,
		"ECDSA":            SafetyClassical,
		"SM2":              SafetyClassical,
		"ML-DSA-65":        SafetySafe,
		"Dilithium3":       SafetySafe,
		"SLH-DSA-SHA2-128s": SafetySafe,
		"Aigis-sig":        SafetySafe,
		"ECDSA+ML-DSA-65":  SafetyHybrid, // 经典+PQC 组合串
	}
	for algo, want := range cases {
		if got := AuthSafetyForAlgo(algo); got != want {
			t.Errorf("AuthSafetyForAlgo(%q) = %q, want %q", algo, got, want)
		}
	}
}

func TestKexMitigatesHNDL(t *testing.T) {
	if !KexMitigatesHNDL(SafetySafe) || !KexMitigatesHNDL(SafetyHybrid) {
		t.Error("safe/hybrid should mitigate HNDL")
	}
	if KexMitigatesHNDL(SafetyClassical) || KexMitigatesHNDL("") {
		t.Error("classical/empty should NOT mitigate HNDL")
	}
}

func TestLookupAlgo(t *testing.T) {
	mlkem, ok := LookupAlgo("ML-KEM-768")
	if !ok || mlkem.Primitive != "kem" || mlkem.QuantumLevel != 3 {
		t.Errorf("ML-KEM-768 = %+v ok=%v, want kem/level3", mlkem, ok)
	}
	mldsa, ok := LookupAlgo("ML-DSA-65")
	if !ok || mldsa.Primitive != "signature" {
		t.Errorf("ML-DSA-65 primitive = %q, want signature", mldsa.Primitive)
	}
	if _, ok := LookupAlgo("RSA"); ok {
		t.Error("RSA should not be in PQC algo table")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/cryptoref/ -run 'TestAuthSafety|TestKexMitigates|TestLookupAlgo' -v`
Expected: FAIL — `undefined: AuthSafetyForAlgo` 等。

- [ ] **Step 3: Write minimal implementation**

Create `backend/internal/cryptoref/algorithms.go`:

```go
package cryptoref

import "strings"

// pqcTokens 认证/签名维判为纯 PQC 的算法名子串（大写匹配）。
var pqcSigTokens = []string{"ML-DSA", "MLDSA", "DILITHIUM", "SLH-DSA", "SLHDSA", "SPHINCS", "FALCON", "AIGIS-SIG", "AIGIS_SIG"}

// classicalSigTokens 认证维判为纯经典的算法名子串。
var classicalSigTokens = []string{"RSA", "ECDSA", "ED25519", "EDDSA", "SM2", "DSA", "ECC"}

// AuthSafetyForAlgo 由认证/签名算法名判认证维量子安全态。
// 组合串同时含经典与 PQC 子串 → hybrid；仅 PQC → safe；仅经典 → classical；空 → na。
func AuthSafetyForAlgo(algo string) string {
	a := strings.ToUpper(strings.TrimSpace(algo))
	if a == "" {
		return SafetyNA
	}
	hasPQC, hasClassical := false, false
	for _, t := range pqcSigTokens {
		if strings.Contains(a, t) {
			hasPQC = true
			break
		}
	}
	for _, t := range classicalSigTokens {
		if strings.Contains(a, t) {
			hasClassical = true
			break
		}
	}
	switch {
	case hasPQC && hasClassical:
		return SafetyHybrid
	case hasPQC:
		return SafetySafe
	case hasClassical:
		return SafetyClassical
	default:
		return SafetyClassical // 未知保守按经典（与 scoring.deriveD1 默认口径一致）
	}
}

// KexMitigatesHNDL 密钥交换维是否已缓解「先抓后解」（safe/hybrid 均可，混合的 PQC 分量足以抵御）。
func KexMitigatesHNDL(kexSafety string) bool {
	return kexSafety == SafetySafe || kexSafety == SafetyHybrid
}

// AlgoInfo PQC 算法的 CBOM 标识信息。
type AlgoInfo struct {
	Primitive    string // kem / signature / hash
	OID          string
	ParamSet     string
	QuantumLevel int // NIST PQC 安全等级 1/3/5，0=非 PQC
}

// pqcAlgoTable PQC 算法核心表（键为大写规范前缀，前缀匹配）。全表见 spec 附录。
var pqcAlgoTable = []struct {
	prefix string
	info   AlgoInfo
}{
	{"ML-KEM-1024", AlgoInfo{"kem", "2.16.840.1.101.3.4.4.3", "ML-KEM-1024", 5}},
	{"ML-KEM-768", AlgoInfo{"kem", "2.16.840.1.101.3.4.4.2", "ML-KEM-768", 3}},
	{"ML-KEM-512", AlgoInfo{"kem", "2.16.840.1.101.3.4.4.1", "ML-KEM-512", 1}},
	{"ML-DSA-87", AlgoInfo{"signature", "2.16.840.1.101.3.4.3.19", "ML-DSA-87", 5}},
	{"ML-DSA-65", AlgoInfo{"signature", "2.16.840.1.101.3.4.3.18", "ML-DSA-65", 3}},
	{"ML-DSA-44", AlgoInfo{"signature", "2.16.840.1.101.3.4.3.17", "ML-DSA-44", 2}},
	{"SLH-DSA", AlgoInfo{"signature", "2.16.840.1.101.3.4.3.20", "SLH-DSA", 1}},
	{"AIGIS-SIG", AlgoInfo{"signature", "", "Aigis-sig", 2}}, // OID 缺口，待真机补录
	{"AIGIS-ENC", AlgoInfo{"kem", "", "Aigis-enc", 2}},
}

// LookupAlgo 前缀匹配 PQC 算法表；命中返回 CBOM 标识信息。
func LookupAlgo(algo string) (AlgoInfo, bool) {
	a := strings.ToUpper(strings.TrimSpace(algo))
	for _, e := range pqcAlgoTable {
		if strings.Contains(a, e.prefix) {
			return e.info, true
		}
	}
	return AlgoInfo{}, false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/cryptoref/ -v`
Expected: PASS（Task 1 + Task 2 全绿）。

- [ ] **Step 5: Commit**

```bash
cd backend && git add internal/cryptoref/algorithms.go internal/cryptoref/algorithms_test.go
git commit -m "feat(cryptoref): PQC 算法表 + 认证维安全态 + HNDL 缓解判定"
```

---

## Task 3: CryptoAsset/ScanResult 双维字段与迁移

**Files:**
- Modify: `backend/internal/model/model.go`（`CryptoAsset` 结构 631-679 内；安全态枚举加在暴露面常量后 ~55 行；`ScanResult` 结构内）
- Verify: `backend/internal/db/db.go`（确认 `CryptoAsset` 在 AutoMigrate）

**Interfaces:**
- Produces: `CryptoAsset.KexGroup/KexSafety/AuthSafety/ReportedBy string`；`ScanResult.KexGroup string`；`model.KexSafetySafe/Hybrid/Classical/NA` 常量。

- [ ] **Step 1: 加安全态枚举常量**

在 `backend/internal/model/model.go` 的「暴露面」常量块（`ExposurePublic = "public"` 之后）插入：

```go
// 量子安全态（KexSafety/AuthSafety 取值）：纯 PQC / 经典+PQC 混合 / 纯经典 / 不适用。
const (
	KexSafetySafe      = "safe"
	KexSafetyHybrid    = "hybrid"
	KexSafetyClassical = "classical"
	KexSafetyNA        = "na"
)
```

- [ ] **Step 2: CryptoAsset 加四字段**

在 `CryptoAsset` 结构里，`SuggestedAlgo` 字段之后、`CreatedAt` 之前插入：

```go
	// 后量子双维建模（KEX 维 × 认证维），来源 cryptoref 分类。
	KexGroup   string `json:"kexGroup"`   // 协商的密钥交换组规范名（X25519MLKEM768/curveSM2MLKEM768/x25519...）
	KexSafety  string `json:"kexSafety"`  // 交换维安全态 safe/hybrid/classical/na
	AuthSafety string `json:"authSafety"` // 认证维安全态 safe/hybrid/classical/na
	ReportedBy string `json:"reportedBy"` // 上报来源 Agent/探针 ID（M-B 起用；本轮默认空）
```

- [ ] **Step 3: ScanResult 加 KexGroup**

在 `ScanResult` 结构里 `SigAlgo` 字段之后插入：

```go
	KexGroup    string `json:"kexGroup"` // 被动/主动观测到的密钥交换组规范名
```

- [ ] **Step 4: 验证 AutoMigrate 覆盖 CryptoAsset**

Run: `cd backend && grep -n "CryptoAsset\b" internal/db/db.go`
Expected: 输出含 `&model.CryptoAsset{}`（说明已在 AutoMigrate 清单；加字段会自动建列，无需改清单）。若无输出则须把 `&model.CryptoAsset{}` 加进 `AutoMigrate(...)` 调用。

- [ ] **Step 5: 编译验证**

Run: `cd backend && go build ./... && go vet ./...`
Expected: 无错误。

- [ ] **Step 6: Commit**

```bash
cd backend && git add internal/model/model.go
git commit -m "feat(model): CryptoAsset 双维量子安全字段(KexGroup/KexSafety/AuthSafety/ReportedBy) + ScanResult.KexGroup"
```

---

## Task 4: 评分 deriveD1 PQC 分支 + optionsD1

**Files:**
- Modify: `backend/internal/scoring/scoring.go`（`DeriveInput` 224-232、`deriveD1` 248-271、`optionsD1` 118-124）
- Test: `backend/internal/scoring/scoring_test.go`

**Interfaces:**
- Consumes: 无（scoring 不 import cryptoref，避免包环；安全态以字符串传入）
- Produces: `DeriveInput.KexSafety/AuthSafety string`；`deriveD1` 识别双维安全态。

- [ ] **Step 1: Write the failing test**

在 `backend/internal/scoring/scoring_test.go` 末尾追加：

```go
func TestDeriveD1_PQCBranch(t *testing.T) {
	cases := []struct {
		name string
		in   DeriveInput
		want int
	}{
		{"纯PQC双safe", DeriveInput{KexSafety: "safe", AuthSafety: "safe"}, 10},
		{"混合KEX+safe认证", DeriveInput{KexSafety: "hybrid", AuthSafety: "safe"}, 15},
		{"混合KEX+经典ECDSA认证", DeriveInput{KexSafety: "hybrid", AuthSafety: "classical", Algorithm: "ECDSA"}, 70},
		{"混合KEX+经典RSA认证", DeriveInput{KexSafety: "hybrid", AuthSafety: "classical", Algorithm: "RSA"}, 90},
		{"无安全态回退RSA", DeriveInput{Algorithm: "RSA"}, 90},
		{"无安全态回退弱RSA", DeriveInput{Algorithm: "RSA", KeySize: 1024}, 100},
	}
	for _, c := range cases {
		if got := deriveD1(c.in); got != c.want {
			t.Errorf("%s: deriveD1 = %d, want %d", c.name, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/scoring/ -run TestDeriveD1_PQCBranch -v`
Expected: FAIL — `DeriveInput` 无 `KexSafety` 字段（编译错误）。

- [ ] **Step 3: DeriveInput 加字段**

在 `scoring.go` 的 `DeriveInput` 结构里追加两字段：

```go
	KexSafety  string // 密钥交换维安全态 safe/hybrid/classical/na（cryptoref 给出）
	AuthSafety string // 认证维安全态 safe/hybrid/classical/na
```

- [ ] **Step 4: deriveD1 加 PQC 前置分支**

把现有 `func deriveD1(in DeriveInput) int { ... }` 整体重命名为 `deriveD1Classic`，并新增包装 `deriveD1`：

```go
// deriveD1 算法脆弱性：优先用双维量子安全态（cryptoref 分类），回退到经典算法名启发式。
func deriveD1(in DeriveInput) int {
	// 取两维安全态里更脆弱者；safe→10、hybrid→15、classical→按经典基线（≥70）。
	d := 0
	for _, s := range []string{in.KexSafety, in.AuthSafety} {
		switch s {
		case "safe":
			if d < 10 {
				d = 10
			}
		case "hybrid":
			if d < 15 {
				d = 15
			}
		case "classical":
			if d < 70 {
				d = 70
			}
		}
	}
	if d == 0 { // 两维都未提供 → 纯经典算法名路径
		return deriveD1Classic(in)
	}
	if d >= 70 { // 存在经典维：用经典启发式细化（弱 RSA/TLS1.0 可拔到 90/100）
		if legacy := deriveD1Classic(in); legacy > d {
			return legacy
		}
	}
	return d
}
```

（`deriveD1Classic` 保持原 248-271 的函数体不变，仅改名。）

- [ ] **Step 5: optionsD1 加两档**

把 `optionsD1` 改为（在表首加两档 PQC 选项）：

```go
var optionsD1 = []Option{
	{"后量子KEM/签名(ML-KEM/ML-DSA)", 10},
	{"混合(X25519+ML-KEM / SM2+ML-KEM)", 15},
	{"不受量子影响(AES-256/SHA-3/SM4)", 10},
	{"AES-128(量子下强度减半)", 40},
	{"经典ECC/ECDSA/EdDSA", 70},
	{"RSA/经典DH/SM2", 90},
	{"弱RSA≤1024/DES/RC4", 100},
}
```

- [ ] **Step 6: Run tests to verify pass（含既有画像断言不回归）**

Run: `cd backend && go test ./internal/scoring/ -v`
Expected: PASS — 新 `TestDeriveD1_PQCBranch` 绿，且 7 条预设画像断言（`TestPresets*`）不变（预设走 `Score` 不走 `Derive`，未受影响）。

- [ ] **Step 7: Commit**

```bash
cd backend && git add internal/scoring/scoring.go internal/scoring/scoring_test.go
git commit -m "feat(scoring): deriveD1 双维量子安全态分支(safe→10/hybrid→15) + optionsD1 加 PQC 档"
```

---

## Task 5: 被动解析补齐 supported_groups / key_share

**Files:**
- Modify: `backend/internal/scan/pcap_tls.go`（`tlsHandshake` 18-29；`parseHello` 108-156）
- Test: `backend/internal/scan/pcap_test.go`

**Interfaces:**
- Consumes: `cryptoref.KexSafetyForGroup`（Task 1）、`cryptoref.IsGREASEGroup`
- Produces: `tlsHandshake.negotiatedGroup int`（ServerHello/HRR 权威组，0=无）、`tlsHandshake.offeredGroups []int`（ClientHello 提供组）、`tlsHandshake.clientKeyShareMax int`（客户端最大 key_share 字节数，尺寸兜底用）。

- [ ] **Step 1: Write the failing test**

在 `backend/internal/scan/pcap_test.go` 末尾追加（合成一个含 supported_groups+key_share 的最小 ClientHello 与一个含 key_share 的 ServerHello）：

```go
func TestParseHello_KeyExchangeGroups(t *testing.T) {
	// ---- 合成 ServerHello：key_share 扩展选中 0x11EC (X25519MLKEM768) ----
	// ServerHello body: version(2)=0303 random(32) sid_len(1)=0 cipher(2)=1301 comp(1)=0 ext_len(2) exts...
	sh := []byte{0x03, 0x03}
	sh = append(sh, make([]byte, 32)...) // random
	sh = append(sh, 0x00)                // sid_len
	sh = append(sh, 0x13, 0x01)          // cipher TLS_AES_128_GCM_SHA256
	sh = append(sh, 0x00)                // compression
	// 扩展：key_share(0x0033) len=2, group=0x11EC（HRR 布局：只含 selected_group 2 字节）
	ksExt := []byte{0x00, 0x33, 0x00, 0x02, 0x11, 0xEC}
	extLen := len(ksExt)
	sh = append(sh, byte(extLen>>8), byte(extLen))
	sh = append(sh, ksExt...)

	out := &tlsHandshake{}
	parseHello(sh, out, false)
	if out.negotiatedGroup != 0x11EC {
		t.Errorf("ServerHello negotiatedGroup = 0x%04X, want 0x11EC", out.negotiatedGroup)
	}

	// ---- 合成 ClientHello：supported_groups 提供 [0x001D, 0x11EE] ----
	ch := []byte{0x03, 0x03}
	ch = append(ch, make([]byte, 32)...) // random
	ch = append(ch, 0x00)                // sid_len
	ch = append(ch, 0x00, 0x02, 0x13, 0x01) // cipher_suites_len=2 + TLS_AES_128_GCM
	ch = append(ch, 0x01, 0x00)          // compression_len=1 + null
	// 扩展区：supported_groups(0x000a): ext_data = list_len(2)=4 + [001D,11EE]
	sgExt := []byte{0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1D, 0x11, 0xEE}
	el := len(sgExt)
	ch = append(ch, byte(el>>8), byte(el))
	ch = append(ch, sgExt...)

	out2 := &tlsHandshake{}
	parseHello(ch, out2, true)
	if len(out2.offeredGroups) != 2 || out2.offeredGroups[0] != 0x001D || out2.offeredGroups[1] != 0x11EE {
		t.Errorf("ClientHello offeredGroups = %v, want [0x1D 0x11EE]", out2.offeredGroups)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/scan/ -run TestParseHello_KeyExchangeGroups -v`
Expected: FAIL — `tlsHandshake` 无 `negotiatedGroup`/`offeredGroups` 字段。

- [ ] **Step 3: tlsHandshake 加字段**

在 `pcap_tls.go` 的 `tlsHandshake` 结构里追加：

```go
	negotiatedGroup   int   // ServerHello/HRR key_share 选中的组码点（0=无）
	offeredGroups     []int // ClientHello supported_groups 提供的组码点
	clientKeyShareMax int   // ClientHello 各组 key_share 里最大字节数（尺寸兜底用）
```

- [ ] **Step 4: parseHello 解析扩展区的组信息**

在 `parseHello` 里，client 分支末尾（`out.sni = parseSNI(b, i)` 这一行**之后**）追加：

```go
		parseClientGroups(b, i, out)
```

在 server 分支里，`if v := parseSupportedVersion(b, i); v != "" {...}` 之后追加：

```go
		out.negotiatedGroup = parseServerKeyShareGroup(b, i)
```

然后在文件末尾（`certKeyBits` 之后）新增两个解析函数：

```go
// parseClientGroups 从 ClientHello 扩展区抽 supported_groups(0x000a) 与各组 key_share(0x0033) 尺寸。
// 严格守界；GREASE 组跳过；截断即安全停止。
func parseClientGroups(b []byte, i int, out *tlsHandshake) {
	exts := walkExtensions(b, i)
	for _, e := range exts {
		switch e.typ {
		case 0x000a: // supported_groups: list_len(2) + groups
			d := e.data
			if len(d) < 2 {
				continue
			}
			ll := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if ll > len(d) {
				ll = len(d)
			}
			for j := 0; j+2 <= ll; j += 2 {
				g := int(d[j])<<8 | int(d[j+1])
				if isGREASE(g) {
					continue
				}
				out.offeredGroups = append(out.offeredGroups, g)
			}
		case 0x0033: // key_share (client): client_shares_len(2) + entries{group(2)+len(2)+key}
			d := e.data
			if len(d) < 2 {
				continue
			}
			total := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if total > len(d) {
				total = len(d)
			}
			k := 0
			for k+4 <= total {
				klen := int(d[k+2])<<8 | int(d[k+3])
				if klen > out.clientKeyShareMax {
					out.clientKeyShareMax = klen
				}
				k += 4 + klen
			}
		}
	}
}

// parseServerKeyShareGroup 从 ServerHello/HelloRetryRequest 扩展区取 key_share(0x0033) 的 selected_group。
// ServerHello 的 key_share = group(2)+len(2)+key；HRR 的 key_share 仅 selected_group(2)。两者都取前 2 字节。
func parseServerKeyShareGroup(b []byte, i int) int {
	for _, e := range walkExtensions(b, i) {
		if e.typ == 0x0033 && len(e.data) >= 2 {
			return int(e.data[0])<<8 | int(e.data[1])
		}
	}
	return 0
}

// tlsExt 一条 TLS 扩展（类型 + 数据）。
type tlsExt struct {
	typ  int
	data []byte
}

// walkExtensions 从偏移 i 处（extensions_len(2)+entries）切出所有扩展，严格守界。
func walkExtensions(b []byte, i int) []tlsExt {
	var out []tlsExt
	if i+2 > len(b) {
		return out
	}
	extLen := int(b[i])<<8 | int(b[i+1])
	i += 2
	end := i + extLen
	if end > len(b) {
		end = len(b)
	}
	for i+4 <= end {
		etype := int(b[i])<<8 | int(b[i+1])
		elen := int(b[i+2])<<8 | int(b[i+3])
		i += 4
		if i+elen > end {
			break
		}
		out = append(out, tlsExt{typ: etype, data: b[i : i+elen]})
		i += elen
	}
	return out
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd backend && go test ./internal/scan/ -run TestParseHello_KeyExchangeGroups -v`
Expected: PASS。

- [ ] **Step 6: 全包回归**

Run: `cd backend && go test ./internal/scan/ -v`
Expected: PASS（既有 pcap/scanner/retry 测试不回归）。

- [ ] **Step 7: Commit**

```bash
cd backend && git add internal/scan/pcap_tls.go internal/scan/pcap_test.go
git commit -m "feat(scan): 被动解析 TLS supported_groups/key_share(含 HRR 权威组 + GREASE 跳过)"
```

---

## Task 6: TLSObservation 回填 KexGroup/KexSafety

**Files:**
- Modify: `backend/internal/scan/pcap.go`（`TLSObservation` 16-26；`ParsePCAP` 组装循环 92-129）
- Test: `backend/internal/scan/pcap_test.go`

**Interfaces:**
- Consumes: `tlsHandshake.negotiatedGroup/offeredGroups/clientKeyShareMax`（Task 5）、`cryptoref.KexSafetyForGroup`
- Produces: `TLSObservation.KexGroup string`、`TLSObservation.KexSafety string`

- [ ] **Step 1: Write the failing test**

在 `backend/internal/scan/pcap_test.go` 追加一个端到端小测（构造含 ServerHello key_share=0x11EE 的最小 pcapng 太重；改为直接测组装辅助函数）。先在 pcap.go 抽出可测的映射逻辑，测试如下：

```go
func TestObservationFromNegotiatedGroup(t *testing.T) {
	o := &TLSObservation{}
	applyKexGroup(o, 0x11EE, 0) // 服务端选中 curveSM2MLKEM768
	if o.KexGroup != "curveSM2MLKEM768" || o.KexSafety != "hybrid" {
		t.Errorf("got (%q,%q), want (curveSM2MLKEM768,hybrid)", o.KexGroup, o.KexSafety)
	}
	// GREASE 不应写入
	o2 := &TLSObservation{}
	applyKexGroup(o2, 0x1A1A, 0)
	if o2.KexGroup != "" || o2.KexSafety != "" {
		t.Errorf("GREASE wrote (%q,%q), want empty", o2.KexGroup, o2.KexSafety)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/scan/ -run TestObservationFromNegotiatedGroup -v`
Expected: FAIL — `TLSObservation` 无 `KexGroup` 字段、`applyKexGroup` 未定义。

- [ ] **Step 3: TLSObservation 加字段 + 映射函数**

在 `pcap.go` 的 `TLSObservation` 结构追加：

```go
	KexGroup  string `json:"kexGroup"`  // 协商的密钥交换组规范名
	KexSafety string `json:"kexSafety"` // safe/hybrid/classical
```

并新增（放在 `ParsePCAP` 之前）：

```go
// applyKexGroup 把观测到的密钥交换组码点（+客户端 key_share 尺寸兜底）分类写入观测。
// GREASE 或空码点不写。
func applyKexGroup(o *TLSObservation, codepoint, clientKeyShareMax int) {
	if codepoint == 0 {
		return
	}
	name, safety := cryptoref.KexSafetyForGroup(codepoint, clientKeyShareMax)
	if name == "" { // GREASE/噪声
		return
	}
	o.KexGroup, o.KexSafety = name, safety
}
```

在 `pcap.go` 的 import 块加入 `"zhulong-pqm/internal/cryptoref"`。

- [ ] **Step 4: ParsePCAP 循环里回填**

在 `ParsePCAP` 的握手组装 `switch` 中，`case hs.isServerHello:` 分支末尾（`o.Version = hs.version` 之后）追加：

```go
			applyKexGroup(o, hs.negotiatedGroup, 0)
```

在 `case hs.isClientHello:` 分支末尾（`if o.Version == "" {...}` 之后）追加（客户端提供 PQC 但尚未见服务端选择时，用最强提供组兜底展示 + 记录尺寸）：

```go
			if o.KexGroup == "" && len(hs.offeredGroups) > 0 {
				for _, g := range hs.offeredGroups {
					if name, kind, _, known := cryptoref.ClassifyGroup(g); known && kind != "classical" {
						o.KexGroup, o.KexSafety = name, cryptoref.SafetyFromKind(kind)
						break
					}
					_ = g
				}
				if o.KexGroup == "" && hs.clientKeyShareMax > 1000 {
					applyKexGroup(o, hs.offeredGroups[0], hs.clientKeyShareMax)
				}
			}
```

（服务端 ServerHello 分支覆盖客户端兜底：ServerHello 的权威组会在其分支无条件覆盖 `o.KexGroup`。为保证权威优先，`applyKexGroup` 在 ServerHello 分支写入前不检查 `o.KexGroup==""`——已如 Step 4 第一段无条件调用。）

- [ ] **Step 5: Run tests to verify pass**

Run: `cd backend && go test ./internal/scan/ -v`
Expected: PASS。

- [ ] **Step 6: Commit**

```bash
cd backend && git add internal/scan/pcap.go internal/scan/pcap_test.go
git commit -m "feat(scan): TLSObservation 回填 KexGroup/KexSafety(服务端权威组优先·客户端提供兜底)"
```

---

## Task 7: runner 与 import 串联双维安全态到资产

**Files:**
- Modify: `backend/internal/api/import.go`（importPcap 的 res 构造 72-84）
- Modify: `backend/internal/scan/runner.go`（`upsertAsset` 403-463、`upsertImportedAsset` 332-393）
- Test: `backend/internal/scan/runner` 无独立测试基建时，用 `pcap_test.go` 的既有 DB 测式或新增 `runner_pqc_test.go`（见步骤）

**Interfaces:**
- Consumes: `ScanResult.KexGroup`（Task 3）、`cryptoref.AuthSafetyForAlgo`/`KexSafetyForGroup`(按 group 名反查略——此处 KexSafety 由 observation 已定，见下)、`cryptoref.KexMitigatesHNDL`
- Produces: 资产落 `KexGroup/KexSafety/AuthSafety`；HNDL 在 KEX 已迁移时清除。

> 说明：`TLSObservation.KexSafety` 已在 Task 6 定好，但 `ScanResult` 只带 `KexGroup`。为让 runner 不重复分类，在 import.go 把 observation 的 `KexSafety` 也带进来——最简做法：`ScanResult.KexGroup` 存**组名**，runner 用 `cryptoref` 由组名反查 kind。因此 Task 1 需补一个按名反查的辅助。若不想扩接口，改为在 import.go 直接把 `o.KexSafety` 存入一个 res 字段。本计划采用**按组名反查**，Task 7 Step 1 先给 cryptoref 补 `SafetyForGroupName`。

- [ ] **Step 1: cryptoref 补按组名反查（TDD）**

在 `backend/internal/cryptoref/named_groups_test.go` 追加：

```go
func TestSafetyForGroupName(t *testing.T) {
	if s := SafetyForGroupName("X25519MLKEM768"); s != SafetyHybrid {
		t.Errorf("X25519MLKEM768 = %q, want hybrid", s)
	}
	if s := SafetyForGroupName("MLKEM768"); s != SafetySafe {
		t.Errorf("MLKEM768 = %q, want safe", s)
	}
	if s := SafetyForGroupName("x25519"); s != SafetyClassical {
		t.Errorf("x25519 = %q, want classical", s)
	}
	if s := SafetyForGroupName(""); s != SafetyNA {
		t.Errorf("empty = %q, want na", s)
	}
	if s := SafetyForGroupName("unknown-0x9ABC"); s != SafetyHybrid {
		t.Errorf("unknown- prefix = %q, want hybrid(保守)", s)
	}
}
```

Run: `cd backend && go test ./internal/cryptoref/ -run TestSafetyForGroupName -v` → FAIL（未定义）。

在 `named_groups.go` 追加：

```go
// SafetyForGroupName 由组规范名反查安全态（runner 用，避免重复按码点分类）。
// "unknown-0x..." 前缀（尺寸兜底命名）保守判 hybrid；空名 na。
func SafetyForGroupName(name string) string {
	if name == "" {
		return SafetyNA
	}
	for _, g := range namedGroups {
		if g.name == name {
			return SafetyFromKind(g.kind)
		}
	}
	if len(name) >= 8 && name[:8] == "unknown-" {
		return SafetyHybrid
	}
	return SafetyClassical
}
```

Run: `cd backend && go test ./internal/cryptoref/ -v` → PASS。

- [ ] **Step 2: import.go 把 KexGroup 带进 ScanResult**

在 `backend/internal/api/import.go` 的 `res := &model.ScanResult{...}` 里加一行（`KeyAlgo: o.Algo,` 之后）：

```go
			KexGroup:        o.KexGroup,
```

- [ ] **Step 3: runner upsertAsset 写双维安全态 + 清 HNDL**

在 `backend/internal/scan/runner.go` 顶部 import 块加 `"zhulong-pqm/internal/cryptoref"`。

在 `upsertAsset` 里，`dims := scoring.Derive(scoring.DeriveInput{...})` 改为先算安全态再喂入：

```go
	kexSafety := cryptoref.SafetyForGroupName(res.KexGroup)
	authSafety := cryptoref.AuthSafetyForAlgo(res.KeyAlgo)
	dims := scoring.Derive(scoring.DeriveInput{
		Algorithm:  res.KeyAlgo,
		KeySize:    res.KeySize,
		TLSVersion: res.TLSVersion,
		Exposure:   exposure,
		Layer:      model.LayerL1,
		LongLived:  certLongLived(res.CertNotAfter),
		KexSafety:  kexSafety,
		AuthSafety: authSafety,
	})
	result := scoring.Score(dims)
```

在同函数的 `apply := func(a *model.CryptoAsset) {...}` 里，`a.HNDL = result.HNDL` 改为：

```go
		a.KexGroup = res.KexGroup
		a.KexSafety = kexSafety
		a.AuthSafety = authSafety
		a.HNDL = result.HNDL && !cryptoref.KexMitigatesHNDL(kexSafety) // KEX 已迁移→清 HNDL
```

- [ ] **Step 4: upsertImportedAsset 同样处理（证书导入无 KEX，KexSafety=na 不清 HNDL）**

在 `upsertImportedAsset` 的 `dims := scoring.Derive(...)` 前加：

```go
	authSafety := cryptoref.AuthSafetyForAlgo(res.KeyAlgo)
```

`DeriveInput` 里加 `AuthSafety: authSafety`（无 KexSafety，证书导入无密钥交换）。在其 `apply` 里 `a.HNDL = result.HNDL` 之前加：

```go
		a.AuthSafety = authSafety
```

（证书导入不设 KexSafety，HNDL 维持原逻辑。）

- [ ] **Step 5: 写集成测试（内存 DB 走一次被动导入）**

Create `backend/internal/scan/runner_pqc_test.go`：

```go
package scan

import (
	"testing"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

func TestUpsertAsset_PQCClearsHNDL(t *testing.T) {
	gdb, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	r := NewRunner(gdb, nil)
	// 长效敏感数据（HNDL 易感）+ 已迁移 KEX（hybrid）→ HNDL 应被清除
	res := &model.ScanResult{
		Host: "10.0.0.1", Port: 1443,
		TLSVersion: "TLS1.3", KeyAlgo: "ECDSA",
		KexGroup: "curveSM2MLKEM768",
	}
	a := r.upsertAsset(res, model.ExposurePublic)
	if a == nil {
		t.Fatal("upsertAsset returned nil")
	}
	if a.KexSafety != model.KexSafetyHybrid {
		t.Errorf("KexSafety = %q, want hybrid", a.KexSafety)
	}
	if a.HNDL {
		t.Error("HNDL should be cleared when KEX is hybrid")
	}
	// 对照：纯经典 KEX → 不清 HNDL（若 D2/D3 达阈值）
	res2 := &model.ScanResult{Host: "10.0.0.2", Port: 443, TLSVersion: "TLS1.2", KeyAlgo: "RSA", KexGroup: "x25519"}
	a2 := r.upsertAsset(res2, model.ExposurePublic)
	if a2.KexSafety != model.KexSafetyClassical {
		t.Errorf("classical KexSafety = %q, want classical", a2.KexSafety)
	}
}
```

（确认 `db.Open(":memory:")` 签名——若签名不同，Run `grep -n "func Open" internal/db/db.go` 并按实际签名调整；若 `db.Open` 需额外参数，改用现有测试里建库的方式，参考 `pcap_test.go` 是否已有 DB 建法。）

- [ ] **Step 6: Run tests**

Run: `cd backend && go test ./internal/scan/ -run TestUpsertAsset_PQCClearsHNDL -v`
Expected: PASS（KexSafety=hybrid 且 HNDL=false）。

- [ ] **Step 7: 全后端回归**

Run: `cd backend && go build ./... && go vet ./... && go test ./...`
Expected: 全 PASS。

- [ ] **Step 8: Commit**

```bash
cd backend && git add internal/api/import.go internal/scan/runner.go internal/scan/runner_pqc_test.go internal/cryptoref/named_groups.go internal/cryptoref/named_groups_test.go
git commit -m "feat(scan): 双维安全态串联资产 + KEX 已迁移自动清 HNDL"
```

---

## Task 8: CBOM 补全量子安全等级与 PQC primitive

**Files:**
- Modify: `backend/internal/cbom/cbom.go`（`assetToComponent` 111-157、`primitiveOf` 170-188、`cryptoFunctions` 197-210）
- Test: `backend/internal/cbom/cbom_test.go`（新建）

**Interfaces:**
- Consumes: `cryptoref.LookupAlgo`、`model.CryptoAsset.KexSafety/AuthSafety/KexGroup`
- Produces: CBOM 组件带 `nistQuantumSecurityLevel`、PQC `primitive`/`cryptoFunctions`、PQC `oid`/`parameterSetIdentifier`。

- [ ] **Step 1: Write the failing test**

Create `backend/internal/cbom/cbom_test.go`:

```go
package cbom

import (
	"testing"

	"zhulong-pqm/internal/model"
)

func TestAssetToComponent_PQC(t *testing.T) {
	a := model.CryptoAsset{
		Name: "gw-1443", Algorithm: "ML-DSA-65", Protocol: "TLS1.3",
		KexGroup: "curveSM2MLKEM768", KexSafety: "hybrid", AuthSafety: "safe",
	}
	c := assetToComponent(a)
	ap := c.CryptoProperties.AlgorithmProperties
	if ap.Primitive != "signature" {
		t.Errorf("primitive = %q, want signature", ap.Primitive)
	}
	if ap.NISTQuantumSecurityLevel != 3 { // ML-DSA-65 = level 3
		t.Errorf("nistQuantumSecurityLevel = %d, want 3", ap.NISTQuantumSecurityLevel)
	}
	if c.CryptoProperties.OID != "2.16.840.1.101.3.4.3.18" {
		t.Errorf("oid = %q, want ML-DSA-65 oid", c.CryptoProperties.OID)
	}
	// 双维安全态应作为 properties 暴露
	if !hasProp(c, "zhulong:kexSafety", "hybrid") {
		t.Error("missing zhulong:kexSafety=hybrid property")
	}
}

func TestPrimitiveOf_PQC(t *testing.T) {
	if primitiveOf("ML-KEM-768") != "kem" {
		t.Errorf("ML-KEM primitive = %q, want kem", primitiveOf("ML-KEM-768"))
	}
	if primitiveOf("ML-DSA-65") != "signature" {
		t.Errorf("ML-DSA primitive = %q, want signature", primitiveOf("ML-DSA-65"))
	}
}

func hasProp(c Component, name, val string) bool {
	for _, p := range c.Properties {
		if p.Name == name && p.Value == val {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/cbom/ -v`
Expected: FAIL — primitive 对 ML-KEM 返回 "unknown"、nistQuantumSecurityLevel=0、无 kexSafety property。

- [ ] **Step 3: primitiveOf/cryptoFunctions 加 PQC 分支**

在 `cbom.go` 顶部 import 加 `"zhulong-pqm/internal/cryptoref"`。

`primitiveOf` 在 `switch` 首部（`case strings.Contains(a, "RSA"):` 之前）加：

```go
	case strings.Contains(a, "ML-KEM"), strings.Contains(a, "MLKEM"), strings.Contains(a, "KYBER"), strings.Contains(a, "AIGIS-ENC"):
		return "kem"
	case strings.Contains(a, "ML-DSA"), strings.Contains(a, "MLDSA"), strings.Contains(a, "DILITHIUM"),
		strings.Contains(a, "SLH-DSA"), strings.Contains(a, "SPHINCS"), strings.Contains(a, "FALCON"), strings.Contains(a, "AIGIS-SIG"):
		return "signature"
```

`cryptoFunctions` 在 `switch` 首部加：

```go
	case strings.Contains(a, "ML-KEM"), strings.Contains(a, "MLKEM"), strings.Contains(a, "KYBER"), strings.Contains(a, "AIGIS-ENC"):
		return []string{"encapsulate", "decapsulate"}
	case strings.Contains(a, "ML-DSA"), strings.Contains(a, "MLDSA"), strings.Contains(a, "DILITHIUM"),
		strings.Contains(a, "SLH-DSA"), strings.Contains(a, "SPHINCS"), strings.Contains(a, "FALCON"), strings.Contains(a, "AIGIS-SIG"):
		return []string{"sign", "verify"}
```

- [ ] **Step 4: assetToComponent 填量子等级/OID + 双维 properties**

在 `assetToComponent` 里，构造 `cp` 之后（`c.CryptoProperties = cp` 之前）加：

```go
	// PQC 算法：填 NIST 量子安全等级、OID、参数集（来自 cryptoref）。
	if info, ok := cryptoref.LookupAlgo(a.Algorithm); ok {
		cp.AlgorithmProperties.NISTQuantumSecurityLevel = info.QuantumLevel
		if info.OID != "" {
			cp.OID = info.OID
		}
		if info.ParamSet != "" {
			cp.AlgorithmProperties.ParameterSetIdentifier = info.ParamSet
		}
	}
	// 经典算法：经典安全等级粗估（RSA-2048≈112、P-256≈128），量子等级 0。
	if cp.AlgorithmProperties.NISTQuantumSecurityLevel == 0 {
		cp.AlgorithmProperties.ClassicalSecurityLevel = classicalLevel(a)
	}
```

在 `c.Properties = []Property{...}` 列表里追加三行（双维安全态可消费）：

```go
		{"zhulong:kexGroup", a.KexGroup},
		{"zhulong:kexSafety", a.KexSafety},
		{"zhulong:authSafety", a.AuthSafety},
```

并新增辅助（文件末尾）：

```go
// classicalLevel 经典公钥算法的粗略经典安全强度（bits），仅供 CBOM 参考。
func classicalLevel(a model.CryptoAsset) int {
	switch {
	case strings.Contains(strings.ToUpper(a.Algorithm), "RSA"):
		if a.KeySize >= 3072 {
			return 128
		}
		return 112
	case strings.Contains(strings.ToUpper(a.Algorithm), "ECDSA"), strings.Contains(strings.ToUpper(a.Algorithm), "SM2"):
		return 128
	default:
		return 0
	}
}
```

- [ ] **Step 5: Run tests to verify pass**

Run: `cd backend && go test ./internal/cbom/ -v`
Expected: PASS。

- [ ] **Step 6: Commit**

```bash
cd backend && git add internal/cbom/cbom.go internal/cbom/cbom_test.go
git commit -m "feat(cbom): 补 PQC primitive/cryptoFunctions + NIST 量子安全等级/OID/参数集 + 双维 properties"
```

---

## Task 9: 主动 PQC 枚举探针

**Files:**
- Create: `backend/internal/scan/pqc_probe.go`
- Test: `backend/internal/scan/pqc_probe_test.go`

**Interfaces:**
- Consumes: `parseServerKeyShareGroup`（Task 5，同包可直接调）、`cryptoref.KexSafetyForGroup`
- Produces:
  - `func buildPQCClientHello(sni string, groups []int) []byte` — 构造只提供指定组、不带匹配 key_share 的 raw TLS1.3 ClientHello 记录
  - `func ProbePQCGroups(host string, port int, groups []int, timeout time.Duration) (supported []int, err error)` — 逐组枚举服务端支持的 PQC 组

- [ ] **Step 1: Write the failing test（先测 ClientHello 构造，纯离线可测）**

Create `backend/internal/scan/pqc_probe_test.go`:

```go
package scan

import "testing"

func TestBuildPQCClientHello(t *testing.T) {
	ch := buildPQCClientHello("example.com", []int{0x11EC, 0x11EE})
	// 记录层：type=0x16 handshake, version=0x0301, len(2)
	if len(ch) < 9 || ch[0] != 0x16 || ch[1] != 0x03 {
		t.Fatalf("bad record header: % X", ch[:9])
	}
	recLen := int(ch[3])<<8 | int(ch[4])
	if recLen != len(ch)-5 {
		t.Errorf("record len %d != body %d", recLen, len(ch)-5)
	}
	// 握手消息：type=0x01 ClientHello
	if ch[5] != 0x01 {
		t.Errorf("handshake type = 0x%02X, want 0x01 ClientHello", ch[5])
	}
	// supported_groups 应包含 0x11EC 与 0x11EE（原始字节里能找到这两个大端码点）
	if !containsBE16(ch, 0x11EC) || !containsBE16(ch, 0x11EE) {
		t.Error("ClientHello missing target groups in supported_groups")
	}
}

func containsBE16(b []byte, v int) bool {
	hi, lo := byte(v>>8), byte(v)
	for i := 0; i+1 < len(b); i++ {
		if b[i] == hi && b[i+1] == lo {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/scan/ -run TestBuildPQCClientHello -v`
Expected: FAIL — `buildPQCClientHello` 未定义。

- [ ] **Step 3: Implement pqc_probe.go**

Create `backend/internal/scan/pqc_probe.go`:

```go
package scan

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"zhulong-pqm/internal/cryptoref"
)

// 主动 PQC 枚举探针：构造只提供目标组、不带匹配 key_share 的 ClientHello，
// 逼服务端用 HelloRetryRequest（或 ServerHello）报出它选中的组——无需任何 PQC 密码运算。
//
// 全程只发一条 ClientHello、读一条响应记录，不完成握手。仅对授权目标使用。

// buildPQCClientHello 构造一条 TLS1.3 ClientHello 记录：supported_groups 放入 groups，
// key_share 只放一个 x25519 空壳（32 字节零），使服务端若选中某 PQC 组必回 HRR 报组。
func buildPQCClientHello(sni string, groups []int) []byte {
	var body []byte
	// legacy_version TLS1.2
	body = append(body, 0x03, 0x03)
	// random(32)
	body = append(body, make([]byte, 32)...)
	// legacy_session_id: 32 字节（兼容中间盒）
	body = append(body, 0x20)
	body = append(body, make([]byte, 32)...)
	// cipher_suites: TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384
	body = append(body, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02)
	// compression: null
	body = append(body, 0x01, 0x00)

	// ---- extensions ----
	var ext []byte
	ext = append(ext, extServerName(sni)...)
	ext = append(ext, extSupportedVersionsTLS13()...)
	ext = append(ext, extSupportedGroups(groups)...)
	ext = append(ext, extKeyShareX25519Empty()...)
	ext = append(ext, extSignatureAlgorithms()...)

	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	// 握手消息头 type(1)=ClientHello + len(3)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// 记录层 type(1)=handshake + version(2)=0x0301 + len(2)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

func extServerName(sni string) []byte {
	if sni == "" {
		return nil
	}
	name := []byte(sni)
	// server_name_list: name_type(1)=0 + host_name_len(2) + host
	entry := append([]byte{0x00, byte(len(name) >> 8), byte(len(name))}, name...)
	list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	return extWrap(0x0000, list)
}

func extSupportedVersionsTLS13() []byte {
	// supported_versions: list_len(1)=2 + 0x0304
	return extWrap(0x002b, []byte{0x02, 0x03, 0x04})
}

func extSupportedGroups(groups []int) []byte {
	var list []byte
	for _, g := range groups {
		list = append(list, byte(g>>8), byte(g))
	}
	data := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	return extWrap(0x000a, data)
}

func extKeyShareX25519Empty() []byte {
	// key_share (client): client_shares_len(2) + [group=0x001D + len(2)=32 + 32 零字节]
	entry := append([]byte{0x00, 0x1D, 0x00, 0x20}, make([]byte, 32)...)
	data := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	return extWrap(0x0033, data)
}

func extSignatureAlgorithms() []byte {
	// 覆盖经典 + PQC sigalg：ecdsa_secp256r1_sha256(0x0403)/rsa_pss(0x0804)/ed25519(0x0807)/ml-dsa-65(0x0905)
	sig := []byte{0x04, 0x03, 0x08, 0x04, 0x08, 0x07, 0x09, 0x05}
	data := append([]byte{byte(len(sig) >> 8), byte(len(sig))}, sig...)
	return extWrap(0x000d, data)
}

// extWrap 用 ext_type(2)+ext_len(2) 包一段扩展数据。
func extWrap(etype int, data []byte) []byte {
	out := []byte{byte(etype >> 8), byte(etype), byte(len(data) >> 8), byte(len(data))}
	return append(out, data...)
}

// ProbePQCGroups 逐组枚举：对每个目标组单独发一条只提供该组的 ClientHello，
// 若服务端 ServerHello/HRR 选中该组则计入 supported。返回服务端支持的 PQC/混合组码点。
func ProbePQCGroups(host string, port int, groups []int, timeout time.Duration) ([]int, error) {
	var supported []int
	for _, g := range groups {
		ok, err := probeOneGroup(host, port, g, timeout)
		if err != nil {
			continue // 单组失败不终止枚举（连接被拒/超时视为不支持）
		}
		if ok {
			supported = append(supported, g)
		}
	}
	return supported, nil
}

// probeOneGroup 发一条只提供组 g 的 ClientHello，读响应首条握手记录，判服务端是否选中 g。
func probeOneGroup(host string, port, g int, timeout time.Duration) (bool, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	ch := buildPQCClientHello(host, []int{g})
	if _, err := conn.Write(ch); err != nil {
		return false, err
	}

	// 读一条 TLS 记录头(5) + 体，尽量读满一条握手记录。
	hdr := make([]byte, 5)
	if _, err := readFull(conn, hdr); err != nil {
		return false, err
	}
	if hdr[0] != 0x16 { // 非 handshake（Alert=0x15 → 不支持）
		return false, nil
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen <= 0 || recLen > 16384 {
		return false, nil
	}
	rec := make([]byte, recLen)
	if _, err := readFull(conn, rec); err != nil {
		return false, err
	}
	// rec 是握手消息流：type(1)+len(3)+body；ServerHello=0x02。复用 handshakeMessages 逻辑解 body。
	for _, m := range handshakeMessages(prependRecordFrame(rec)) {
		if m.typ != 0x02 { // 只看 ServerHello/HRR
			continue
		}
		out := &tlsHandshake{}
		parseHello(m.body, out, false)
		return out.negotiatedGroup == g, nil
	}
	return false, nil
}

// readFull 从 conn 读满 buf（DialTimeout 已设 deadline）。
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// prependRecordFrame 把裸握手记录体重新套上 handshake 记录头，喂给 handshakeMessages（它按记录切分）。
func prependRecordFrame(rec []byte) []byte {
	frame := []byte{0x16, 0x03, 0x03, byte(len(rec) >> 8), byte(len(rec))}
	return append(frame, rec...)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/scan/ -run TestBuildPQCClientHello -v`
Expected: PASS。

- [ ] **Step 5: 全包回归 + vet**

Run: `cd backend && go vet ./internal/scan/ && go test ./internal/scan/ -v`
Expected: PASS。

- [ ] **Step 6: Commit**

```bash
cd backend && git add internal/scan/pqc_probe.go internal/scan/pqc_probe_test.go
git commit -m "feat(scan): 主动 PQC 枚举探针(raw ClientHello + HRR 组反射，无需 PQC 运算)"
```

---

## Task 10: rules.go 排除滤镜对齐 cryptoref

**Files:**
- Modify: `backend/internal/scan/rules.go`（`isClassicKEX` 81-95、`isClassicSig` 175-187）
- Test: `backend/internal/scan/rules` 无独立测试文件时新建 `rules_pqc_test.go`

**Interfaces:**
- Consumes: `cryptoref.AuthSafetyForAlgo`、组名判定
- Produces: `isClassicKEX`/`isClassicSig` 对更全的 PQC/混合组名不误报为经典。

- [ ] **Step 1: Write the failing test**

Create `backend/internal/scan/rules_pqc_test.go`:

```go
package scan

import "testing"

func TestIsClassicKEX_ExcludesHybrids(t *testing.T) {
	// 经典应命中
	if !isClassicKEX("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "RSA") {
		t.Error("classic ECDHE_RSA should be classic KEX")
	}
	// 混合/PQC 组名不应判为经典 KEX
	for _, s := range []string{"curveSM2MLKEM768", "X25519MLKEM768", "SecP256r1MLKEM768"} {
		if isClassicKEX(s, "") {
			t.Errorf("%q should NOT be classic KEX", s)
		}
	}
}

func TestIsClassicSig_ExcludesPQC(t *testing.T) {
	if isClassicSig("ML-DSA-65") {
		t.Error("ML-DSA-65 should not be classic sig")
	}
	if !isClassicSig("ECDSA") {
		t.Error("ECDSA should be classic sig")
	}
}
```

- [ ] **Step 2: Run test to verify current state**

Run: `cd backend && go test ./internal/scan/ -run 'TestIsClassicKEX_ExcludesHybrids|TestIsClassicSig_ExcludesPQC' -v`
Expected: `curveSM2MLKEM768` 分支 FAIL（现有排除表只列了 `MLKEM`/`ML-KEM` 子串，`curveSM2MLKEM768` 含 `MLKEM` 应已命中——若已通过则本任务只加回归保护）。若通过则记录为「回归护栏」，仍执行 Step 3 收敛实现。

- [ ] **Step 3: 让排除判定走 cryptoref（收敛真源）**

在 `rules.go` 顶部 import 加 `"zhulong-pqm/internal/cryptoref"`。把 `isClassicKEX` 的 PQC 排除循环替换为对组名/套件的安全态判定（保留原经典匹配）：

在 `isClassicKEX` 函数开头（现有 `for _, pq := range []string{...}` 之前）加一句：

```go
	// 组名本身是混合/PQC（cryptoref 认识的规范名）→ 直接非经典。
	if s := cryptoref.SafetyForGroupName(cipher); s == cryptoref.SafetyHybrid || s == cryptoref.SafetySafe {
		return false
	}
```

在 `isClassicSig` 函数开头加：

```go
	if cryptoref.AuthSafetyForAlgo(sig) != cryptoref.SafetyClassical {
		return false
	}
```

（保留原有子串排除表作为兜底，不删除。）

- [ ] **Step 4: Run tests to verify pass**

Run: `cd backend && go test ./internal/scan/ -run 'TestIsClassicKEX_ExcludesHybrids|TestIsClassicSig_ExcludesPQC' -v`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
cd backend && git add internal/scan/rules.go internal/scan/rules_pqc_test.go
git commit -m "feat(scan): 规则排除滤镜对齐 cryptoref(混合/PQC 组不再误报经典 KEX/签名)"
```

---

## Task 11: 前端展示双维安全态与迁移分布

**Files:**
- Modify: `frontend/src/api/types.ts`（CryptoAsset 类型镜像）
- Modify: `frontend/src/views/Assets.vue`（列表加 KexGroup / 安全态列）
- Modify: `frontend/src/views/RiskAssessment.vue`（详情展示双维 + HNDL 已缓解徽标）
- Modify: `frontend/src/views/BigScreen.vue`（加「经典/半迁移/全迁移」分布）

**Interfaces:**
- Consumes: 后端 `CryptoAsset.kexGroup/kexSafety/authSafety`（JSON 字段）

- [ ] **Step 1: types.ts 镜像新字段**

Run: `cd frontend && grep -n "interface CryptoAsset\|kexGroup\|suggestedAlgo" src/api/types.ts`
在 `CryptoAsset` 接口的 `suggestedAlgo` 字段附近追加：

```ts
  kexGroup?: string
  kexSafety?: 'safe' | 'hybrid' | 'classical' | 'na'
  authSafety?: 'safe' | 'hybrid' | 'classical' | 'na'
  reportedBy?: string
```

- [ ] **Step 2: Assets.vue 加安全态列**

在 `Assets.vue` 的资产表格列定义里，加一列展示密钥交换态（用 Arco `a-tag`，颜色映射 safe=green/hybrid=arcoblue/classical=orange）。定位表格 `<a-table-column>` 群，在算法列后插入：

```vue
        <a-table-column title="密钥交换" :width="180">
          <template #cell="{ record }">
            <a-tag v-if="record.kexGroup" :color="kexTagColor(record.kexSafety)">
              {{ record.kexGroup }}
            </a-tag>
            <span v-else style="color: var(--color-text-3)">—</span>
          </template>
        </a-table-column>
```

在该组件 `<script setup>` 里加：

```ts
function kexTagColor(s?: string) {
  return s === 'safe' ? 'green' : s === 'hybrid' ? 'arcoblue' : s === 'classical' ? 'orange' : 'gray'
}
```

- [ ] **Step 3: RiskAssessment.vue 详情展示双维 + HNDL 已缓解**

在资产详情描述区（`<a-descriptions>`）加两项 KexSafety/AuthSafety，并在 HNDL 展示处：当 `kexSafety` ∈ {safe,hybrid} 且原 HNDL 易感时显示「HNDL 已缓解（KEX 已迁移）」绿色徽标。定位现有 HNDL 展示，改为条件渲染：

```vue
      <a-descriptions-item label="HNDL">
        <a-tag v-if="asset.kexSafety === 'safe' || asset.kexSafety === 'hybrid'" color="green">已缓解（KEX 已迁移）</a-tag>
        <a-tag v-else-if="asset.hndl" color="red">易受先抓后解</a-tag>
        <span v-else>—</span>
      </a-descriptions-item>
      <a-descriptions-item label="认证维">{{ safetyText(asset.authSafety) }}</a-descriptions-item>
```

加辅助：

```ts
function safetyText(s?: string) {
  return { safe: '后量子安全', hybrid: '混合过渡', classical: '经典（待迁移）', na: '不适用' }[s || 'na'] || '—'
}
```

- [ ] **Step 4: BigScreen.vue 加迁移分布**

在大屏加一个统计块，按 `kexSafety` 聚合「经典/半迁移(hybrid)/全迁移(safe)」占比。用现有资产列表数据前端聚合（若大屏走独立统计 API，则该聚合留后端 M-A 尾补；本步先用已加载资产做前端聚合）。加一个计算属性：

```ts
const migrationDist = computed(() => {
  const all = assets.value || []
  const safe = all.filter(a => a.kexSafety === 'safe').length
  const hybrid = all.filter(a => a.kexSafety === 'hybrid').length
  const classical = all.length - safe - hybrid
  return { safe, hybrid, classical, total: all.length }
})
```

并在模板里渲染三个数字块（沿用大屏既有卡片样式类）。

- [ ] **Step 5: 构建验证**

Run: `cd frontend && npm run build`
Expected: `vue-tsc --noEmit` 无 TS 错误，构建成功。

- [ ] **Step 6: Commit**

```bash
cd frontend && git add src/api/types.ts src/views/Assets.vue src/views/RiskAssessment.vue src/views/BigScreen.vue
git commit -m "feat(ui): 展示密钥交换组/双维量子安全态 + HNDL 已缓解徽标 + 大屏迁移分布"
```

---

## Task 12: 端到端验收（真机 pcap）

**Files:** 无（人工/运行时验收）

- [ ] **Step 1: 起后端**

Run: `cd backend && go run ./cmd/zhulong-pqm`（:8099，首启建库+种子）

- [ ] **Step 2: 起前端预览**

用 preview_start（`zhulong-pqm-frontend`）或 `cd frontend && npm run dev`（:5390）。登录 admin/admin@1234。

- [ ] **Step 3: 上传验收 pcap**

在「发现」页上传 `~/Desktop/VPN客户端后量子抓包.pcapng`（M2 被动导入）。

- [ ] **Step 4: 核对识别结果**

在「资产」页确认：
- `:443` 端点：`kexGroup=X25519MLKEM768`、`kexSafety=hybrid`、HNDL 显示「已缓解」、D1≤15。
- `:1443` 端点：`kexGroup=curveSM2MLKEM768`、`kexSafety=hybrid`、详情归因铜锁（IANA#4590）。
- 纯经典 x25519 端点：`kexSafety=classical`。

- [ ] **Step 5: 核对 CBOM 导出**

导出 CBOM，确认 PQC 组件带 `nistQuantumSecurityLevel>0`、`primitive=kem/signature`、`zhulong:kexSafety` property。

- [ ] **Step 6: 全量测试收尾**

Run: `cd backend && go build ./... && go vet ./... && go test ./...` 全绿。
截图/记录识别结果，M-A 完成。

---

## Self-Review

**1. Spec coverage（对照设计 §1-§2.6 + §8）：**
- §1.1 双维数据模型 → Task 3 ✓
- §1.2 deriveD1/optionsD1 → Task 4 ✓
- §1.3 HNDL 精准化 → Task 7（runner 层清除，保住预设画像断言）✓
- §1.4 CBOM 补全 → Task 8 ✓
- §2.1 三字典 → Task 1/2（named_group_table + pqc_algo_table；lib_detection_table 明确移交 M-C）✓
- §2.2 码点权威·尺寸兜底 → Task 1 `KexSafetyForGroup` ✓
- §2.3 被动解析补齐 → Task 5 + Task 6 ✓
- §2.4 主动枚举探针 → Task 9 ✓
- §2.5 评分/CBOM/正面规则 → Task 4/8/10（正面 seed 规则明确移出 M-A，理由已记）✓
- §2.6 验收 → Task 12 ✓
- §8 前端 → Task 11 ✓

**2. Placeholder scan：** 无 TBD/TODO；每个代码步给了完整代码。Task 7 Step 5 与 Task 10 Step 2 含「按实际签名核对」的自适应说明（因 `db.Open` 签名、既有排除表现状未逐字读），非占位符而是显式核对指令。

**3. Type consistency：** `KexSafety` 常量在 model（`model.KexSafety*`）与 cryptoref（`cryptoref.Safety*`）各一套，值字符串一致（"safe"/"hybrid"/"classical"/"na"）——scoring 不 import cryptoref（避免包环），以字符串传递，一致。`TLSObservation.KexGroup`→`ScanResult.KexGroup`→`CryptoAsset.KexGroup` 全链路字段名一致。`buildPQCClientHello`/`parseServerKeyShareGroup`/`handshakeMessages` 同包调用签名一致。

**已核实（写计划时确认）：**
- `db.Open(path string) (*gorm.DB, error)`（db.go:21）——Task 7 Step 5 的 `db.Open(":memory:")` 调用正确；glebarez sqlite 支持 `:memory:`，Open 内会跑 AutoMigrate + 种子（可接受）。
- `&model.CryptoAsset{}` 已在 AutoMigrate 清单（db.go:31）——Task 3 加字段自动建列，无需改清单。

**执行时按实际 DOM 微调（非阻塞）：**
- `Assets.vue`/`RiskAssessment.vue`/`BigScreen.vue` 的表格列/描述区/大屏卡片确切结构（Task 11）——按实际模板插入。
