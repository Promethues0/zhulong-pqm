# 主动 PQC 枚举探针接线（tls-pqc 扫描器）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 M-A 遗留的无调用方死代码 `ProbePQCGroups` 接线进新的 opt-in 组合扫描器 `tls-pqc`，让主动扫描既拿证书（认证维）又枚举 PQC 组（密钥交换维），补齐主动发现能力。

**Architecture:** 新增 `TLSPQCScanner` 组合式扫描器：委托现有 `TLSScanner` 做真握手拿证书，再调 `ProbePQCGroups` 逐组枚举，把结果经纯函数 `applyProbeResult` 合并进同一 `ScanResult`。cryptoref 新增枚举白名单 `PQCGroupCodepoints`。默认 `tls` 扫描零改动、零回归。

**Tech Stack:** Go 1.24+（纯 Go 免 CGO）、Gin、GORM；前端 Vue3 + Arco + TypeScript。

## Global Constraints

- **纯 Go 免 CGO 硬约束**：不得引入 CGO 依赖（探针仅 `net.Dial` + 手搓字节，无新依赖）。
- commit 用 `feat(scope):` 前缀，全程中文。
- 后端改动跑 `go build ./... && go vet ./... && go test ./...` 全绿，**7 预设画像断言不动**。
- 前端 `npm run build`（先 vue-tsc --noEmit）绿。
- 前端主题字节蓝，本次不碰样式；不覆写 Arco 的 `--color-*`。
- 默认 `tls` 扫描器行为/速度不变（tls-pqc 是 opt-in 增量）。

---

### Task 1: cryptoref 枚举白名单 `PQCGroupCodepoints`

**Files:**
- Modify: `backend/internal/cryptoref/named_groups.go`
- Test: `backend/internal/cryptoref/named_groups_test.go`

**Interfaces:**
- Consumes: 包内 `namedGroups` 表、常量 `SafetyHybrid`/`SafetySafe`。
- Produces: `func PQCGroupCodepoints() []int` — 返回可主动枚举的 PQC/混合组码点白名单，
  顺序即枚举顺序也即命中后选主组的优先序（互联网主流 0x11EC、国密 0x11EE 靠前）。

- [ ] **Step 1: Write the failing test**

在 `named_groups_test.go` 末尾追加：

```go
func TestPQCGroupCodepoints(t *testing.T) {
	got := PQCGroupCodepoints()

	// 必须精确等于这份白名单（顺序敏感：主流/国密靠前决定选主组优先序）
	want := []int{
		0x11EC, // X25519MLKEM768（互联网主流 Rec=Y）
		0x11EE, // curveSM2MLKEM768（国密 铜锁 Tongsuo 8.5+）
		0x11EB, // SecP256r1MLKEM768
		0x11ED, // SecP384r1MLKEM1024
		0x6399, // X25519Kyber768Draft00
		0x0200, // MLKEM512
		0x0201, // MLKEM768
		0x0202, // MLKEM1024
	}
	if len(got) != len(want) {
		t.Fatalf("PQCGroupCodepoints len = %d, want %d: %#x", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("PQCGroupCodepoints[%d] = 0x%04X, want 0x%04X", i, got[i], want[i])
		}
	}

	// 反向不变量：不得含仅作时间指纹的 0xFEFE、任一 GREASE、任一经典组
	for _, cp := range got {
		if cp == 0xFEFE {
			t.Error("白名单不得含 0xFEFE(draft-02 时间指纹，非真实可协商)")
		}
		if IsGREASEGroup(cp) {
			t.Errorf("白名单不得含 GREASE 组 0x%04X", cp)
		}
		if _, kind, _, known := ClassifyGroup(cp); !known || (kind != "pqc" && kind != "hybrid") {
			t.Errorf("0x%04X kind=%q known=%v，白名单只应含真实 pqc/hybrid 组", cp, kind, known)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/cryptoref/ -run TestPQCGroupCodepoints -v`
Expected: FAIL，编译错误 `undefined: PQCGroupCodepoints`。

- [ ] **Step 3: Write minimal implementation**

在 `named_groups.go` 末尾追加（curated 显式清单，不靠 kind 自动推导——因为 0xFEFE 也是 hybrid kind 但必须排除）：

```go
// PQCGroupCodepoints 返回可主动枚举的 PQC/混合密钥交换组码点白名单。
// 显式 curated（非按 kind 自动推导）：排除仅作时间指纹的 0xFEFE(draft-02)。
// 顺序即枚举顺序，也即命中多组时的选主组优先序——互联网主流与国密排在前。
func PQCGroupCodepoints() []int {
	return []int{
		0x11EC, // X25519MLKEM768（互联网主流，唯一 Rec=Y）
		0x11EE, // curveSM2MLKEM768（国密 SM2+ML-KEM，铜锁 Tongsuo 8.5+）
		0x11EB, // SecP256r1MLKEM768
		0x11ED, // SecP384r1MLKEM1024
		0x6399, // X25519Kyber768Draft00
		0x0200, // MLKEM512
		0x0201, // MLKEM768
		0x0202, // MLKEM1024
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/cryptoref/ -run TestPQCGroupCodepoints -v`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/zhulong-pqm
git add backend/internal/cryptoref/named_groups.go backend/internal/cryptoref/named_groups_test.go
git commit -m "feat(cryptoref): PQCGroupCodepoints 主动枚举组白名单(含国密 0x11EE，排除时间指纹 0xFEFE)"
```

---

### Task 2: `TLSPQCScanner` 组合扫描器 + `applyProbeResult` 纯合并函数

**Files:**
- Create: `backend/internal/scan/tls_pqc_scanner.go`
- Test: `backend/internal/scan/tls_pqc_scanner_test.go`

**Interfaces:**
- Consumes:
  - `NewTLSScanner() *TLSScanner` 及其 `Scan(ctx, host, port) (*model.ScanResult, error)`（现有）
  - `ProbePQCGroups(host string, port int, groups []int, timeout time.Duration) ([]int, error)`（现有）
  - `cryptoref.PQCGroupCodepoints() []int`（Task 1）
  - `cryptoref.ClassifyGroup(cp int) (name, kind string, isIANA, known bool)`、`cryptoref.SafetyFromKind(kind string) string`（现有）
  - 包级 `dialTimeout time.Duration`（现有，`ZPQM_SCAN_TIMEOUT_MS` 可配）
  - `model.MethodM1ActiveTLS`、`model.ScannerTLSPQC`（Task 3 定义；本任务测试用字面量 "tls-pqc" 不依赖它）
- Produces:
  - `type TLSPQCScanner struct{}` 实现 `Scanner` 接口（`Scan`/`Method`/`Name`）
  - `func NewTLSPQCScanner() *TLSPQCScanner`
  - `func applyProbeResult(res *model.ScanResult, supported []int)` — 纯函数：把枚举到的
    支持组合并进 res（取 supported[0] 为主组填 KexGroup/KexSafety，全部支持组记进 EvidenceNote）。
    supported 空则不动 res（KexGroup 留空）。

- [ ] **Step 1: Write the failing test**

创建 `backend/internal/scan/tls_pqc_scanner_test.go`：

```go
package scan

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"zhulong-pqm/internal/model"
)

// applyProbeResult：命中多组时取表序第一个为主组，写 KexGroup/KexSafety + 证据。
func TestApplyProbeResult_PrimaryAndSafety(t *testing.T) {
	res := &model.ScanResult{}
	applyProbeResult(res, []int{0x11EE, 0x11EC}) // 国密在前 → 主组国密
	if res.KexGroup != "curveSM2MLKEM768" {
		t.Errorf("KexGroup = %q, want curveSM2MLKEM768", res.KexGroup)
	}
	if res.KexSafety != model.KexSafetyHybrid {
		t.Errorf("KexSafety = %q, want hybrid", res.KexSafety)
	}
	// 全部支持组应记进证据，便于审计（含次组码点文本）
	if !strings.Contains(res.EvidenceNote, "0x11EC") {
		t.Errorf("EvidenceNote 应记录全部支持组，缺 0x11EC: %q", res.EvidenceNote)
	}
}

// 纯 ML-KEM 组 → safe。
func TestApplyProbeResult_PureMLKEMSafe(t *testing.T) {
	res := &model.ScanResult{}
	applyProbeResult(res, []int{0x0201}) // MLKEM768 纯 PQC
	if res.KexGroup != "MLKEM768" || res.KexSafety != model.KexSafetySafe {
		t.Errorf("got %q/%q, want MLKEM768/safe", res.KexGroup, res.KexSafety)
	}
}

// 空枚举结果不动 res（经典目标不误判）。
func TestApplyProbeResult_EmptyLeavesUntouched(t *testing.T) {
	res := &model.ScanResult{KexGroup: "", KexSafety: ""}
	applyProbeResult(res, nil)
	if res.KexGroup != "" || res.KexSafety != "" {
		t.Errorf("空枚举不应写 KexGroup/KexSafety，得 %q/%q", res.KexGroup, res.KexSafety)
	}
}

// 扫描器对真 TLS 服务：委托真握手拿到证书字段；经典服务探针枚举全不支持 → KexGroup 空（不误判）。
func TestTLSPQCScanner_RealHandshakeCarriesCertClassicalNotMisjudged(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	// httptest 用经典 TLS（RSA/ECDSA），Go 服务端不会选中我们枚举的 PQC 组
	u := strings.TrimPrefix(srv.URL, "https://")
	host := u[:strings.LastIndex(u, ":")]
	port, _ := strconv.Atoi(u[strings.LastIndex(u, ":")+1:])

	sc := NewTLSPQCScanner()
	res, err := sc.Scan(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Scan 真 TLS 服务失败: %v", err)
	}
	if res.CertFingerprint == "" || res.KeyAlgo == "" {
		t.Errorf("委托真握手应带证书字段，得 keyAlgo=%q fp=%q", res.KeyAlgo, res.CertFingerprint)
	}
	if res.KexGroup != "" {
		t.Errorf("经典 TLS 目标 KexGroup 应空(枚举全不支持)，得 %q", res.KexGroup)
	}
	if sc.Name() != "tls-pqc" || sc.Method() != model.MethodM1ActiveTLS {
		t.Errorf("Name/Method = %q/%q, want tls-pqc/M1", sc.Name(), sc.Method())
	}
	_ = tls.VersionTLS13 // 保留 tls 导入（httptest 已用）
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/scan/ -run 'TestApplyProbeResult|TestTLSPQCScanner' -v`
Expected: FAIL，编译错误 `undefined: applyProbeResult` / `undefined: NewTLSPQCScanner`。

- [ ] **Step 3: Write minimal implementation**

创建 `backend/internal/scan/tls_pqc_scanner.go`：

```go
package scan

import (
	"context"
	"fmt"
	"strings"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/model"
)

// TLSPQCScanner 组合式主动扫描器：先委托 TLSScanner 真握手拿证书/认证维，
// 再用 ProbePQCGroups 逐组枚举补密钥交换维，合并进同一 ScanResult。opt-in（scannerType=tls-pqc）。
type TLSPQCScanner struct {
	tls *TLSScanner
}

// NewTLSPQCScanner 构造组合扫描器。
func NewTLSPQCScanner() *TLSPQCScanner {
	return &TLSPQCScanner{tls: NewTLSScanner()}
}

// Method 仍是 M1（主动 TLS 握手）——枚举探针不改变发现方式语义。
func (s *TLSPQCScanner) Method() string { return model.MethodM1ActiveTLS }

// Name 返回扫描器名。
func (s *TLSPQCScanner) Name() string { return "tls-pqc" }

// Scan 真握手拿证书 + 逐组枚举 PQC 组，合并成一条结果。
func (s *TLSPQCScanner) Scan(ctx context.Context, host string, port int) (*model.ScanResult, error) {
	res, err := s.tls.Scan(ctx, host, port)
	if err != nil {
		return nil, err // 无证书=无资产，与现有语义一致（Runner 记 failed 结果）
	}
	// 逐组枚举；单组失败探针内部已 continue 容错，返回服务端支持的 PQC/混合组码点。
	supported, _ := ProbePQCGroups(host, port, cryptoref.PQCGroupCodepoints(), dialTimeout)
	applyProbeResult(res, supported)
	return res, nil
}

// applyProbeResult 把枚举到的支持组合并进 res：取表序第一个为主组填 KexGroup/KexSafety，
// 全部支持组记进 EvidenceNote 留证。supported 空则不动 res（经典目标 KexGroup 留空，不误判）。
func applyProbeResult(res *model.ScanResult, supported []int) {
	if len(supported) == 0 {
		return
	}
	primary := supported[0]
	name, kind, _, _ := cryptoref.ClassifyGroup(primary)
	res.KexGroup = name
	res.KexSafety = cryptoref.SafetyFromKind(kind)

	codes := make([]string, len(supported))
	for i, cp := range supported {
		codes[i] = fmt.Sprintf("0x%04X", cp)
	}
	note := fmt.Sprintf("主动枚举 PQC 支持组: %s（主组 %s/%s）",
		strings.Join(codes, " "), name, res.KexSafety)
	if res.EvidenceNote == "" {
		res.EvidenceNote = note
	} else {
		res.EvidenceNote += "; " + note
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/scan/ -run 'TestApplyProbeResult|TestTLSPQCScanner' -v`
Expected: PASS（4 个子测试全过）。

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/zhulong-pqm
git add backend/internal/scan/tls_pqc_scanner.go backend/internal/scan/tls_pqc_scanner_test.go
git commit -m "feat(scan): TLSPQCScanner 组合扫描器——真握手拿证书+逐组枚举 PQC 组合并进同一结果"
```

---

### Task 3: `NewScanner` 分发接线 + `ScannerTLSPQC` 常量

**Files:**
- Modify: `backend/internal/model/model.go`（扫描器常量块，约 93-98 行）
- Modify: `backend/internal/scan/scanner.go`（`NewScanner` switch）
- Test: `backend/internal/scan/scanner_test.go`（新建或追加）

**Interfaces:**
- Consumes: `NewTLSPQCScanner() *TLSPQCScanner`（Task 2）
- Produces: `model.ScannerTLSPQC = "tls-pqc"`；`NewScanner("tls-pqc")` 返回 `*TLSPQCScanner`。

- [ ] **Step 1: Write the failing test**

创建/追加 `backend/internal/scan/scanner_test.go`：

```go
package scan

import (
	"testing"

	"zhulong-pqm/internal/model"
)

func TestNewScanner_TLSPQC(t *testing.T) {
	sc := NewScanner(model.ScannerTLSPQC)
	if sc.Name() != "tls-pqc" {
		t.Errorf("NewScanner(tls-pqc).Name() = %q, want tls-pqc", sc.Name())
	}
	if _, ok := sc.(*TLSPQCScanner); !ok {
		t.Errorf("NewScanner(tls-pqc) 类型 = %T, want *TLSPQCScanner", sc)
	}
	// 默认 tls 仍是 TLSScanner（无回归）
	if _, ok := NewScanner(model.ScannerTLS).(*TLSScanner); !ok {
		t.Error("NewScanner(tls) 应仍返回 *TLSScanner")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/scan/ -run TestNewScanner_TLSPQC -v`
Expected: FAIL，编译错误 `undefined: model.ScannerTLSPQC`。

- [ ] **Step 3: Write minimal implementation**

`model.go` 扫描器常量块加一行：

```go
const (
	ScannerTLS    = "tls"
	ScannerTLSPQC = "tls-pqc" // 主动 TLS 握手 + PQC 组枚举（opt-in 深挖）
	ScannerSSH    = "ssh"
	ScannerIKE    = "ike" // 占位（元数据可见，未实现）
	ScannerRDP    = "rdp" // 占位（元数据可见，未实现）
)
```

`scanner.go` 的 `NewScanner` switch 增 case（放在 `case model.ScannerSSH:` 之前）：

```go
	case model.ScannerTLSPQC:
		return NewTLSPQCScanner()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/scan/ -run TestNewScanner_TLSPQC -v`
Expected: PASS。

- [ ] **Step 5: 全量回归 + Commit**

```bash
cd ~/Projects/zhulong-pqm/backend && go build ./... && go vet ./... && go test ./...
```
Expected: 全绿，7 预设画像断言不受影响。

```bash
cd ~/Projects/zhulong-pqm
git add backend/internal/model/model.go backend/internal/scan/scanner.go backend/internal/scan/scanner_test.go
git commit -m "feat(scan): NewScanner 分发 tls-pqc → TLSPQCScanner + ScannerTLSPQC 常量"
```

---

### Task 4: 前端扫描器类型下拉（Discovery 建任务可选 tls-pqc）

**Files:**
- Modify: `frontend/src/api/types.ts`（`ScanInput` 约 126-130 行）
- Modify: `frontend/src/views/Discovery.vue`（form 约 162-166 行、submit 约 266-270 行、模板扫描表单约 367-372 行）

**Interfaces:**
- Consumes: 后端 `createScanReq.ScannerType`（已现成接受，默认 tls）。
- Produces: `ScanInput.scannerType?: string`；Discovery 表单 scannerType 下拉透传。

- [ ] **Step 1: 加类型字段**

`types.ts` 的 `ScanInput` 加可选字段：

```ts
export interface ScanInput {
  name: string
  targets: string[]
  exposure: string
  scannerType?: string
}
```

- [ ] **Step 2: 表单 state + 提交透传**

`Discovery.vue` 的 `form` reactive 加字段：

```ts
const form = reactive({
  name: '',
  targetsText: '',
  exposure: 'internal' as 'internal' | 'dmz' | 'public',
  scannerType: 'tls',
})
```

`submit()` 的 `scanApi.create({...})` 调用加 `scannerType` 透传：

```ts
    await scanApi.create({
      name: form.name.trim(),
      targets,
      exposure: form.exposure,
      scannerType: form.scannerType,
    })
```

并在 submit 成功重置里加一行 `form.scannerType = 'tls'`（紧随 `form.targetsText = ''` 之后）。

- [ ] **Step 3: 模板加下拉**

在「暴露面」`a-form-item` 之后、发起按钮之前，插入扫描器选择：

```html
            <a-form-item label="扫描器">
              <a-select v-model="form.scannerType">
                <a-option value="tls">TLS 快扫（证书 + 套件）</a-option>
                <a-option value="tls-pqc">TLS + PQC 深挖（枚举后量子组，较慢）</a-option>
              </a-select>
              <div class="field-hint">
                tls-pqc 会对每个目标逐组主动枚举后量子/混合密钥交换组，连接开销更大。
              </div>
            </a-form-item>
```

- [ ] **Step 4: 构建校验**

Run: `cd frontend && npm run build`
Expected: vue-tsc 无类型错误，vite 构建成功。

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/zhulong-pqm
git add frontend/src/api/types.ts frontend/src/views/Discovery.vue
git commit -m "feat(ui): Discovery 建扫描任务可选扫描器 tls / tls-pqc(PQC 深挖)"
```

---

## 验收（全部任务完成后）

- [ ] 本地起后端（`cd backend && go run ./cmd/zhulong-pqm`）+ 前端（`npm run dev`），登录 admin/admin@1234。
- [ ] Discovery 建一个 `scannerType=tls-pqc` 任务，目标填一个已知支持 PQC 的公网端点或本地罐装服务；
      任务完成后资产/结果出现 KexGroup（如 X25519MLKEM768）+ KexSafety=hybrid。
- [ ] 建一个 tls-pqc 任务扫纯经典目标（如 httptest 或普通 https 站点），KexGroup 空、
      D1 由证书算法决定，不误判 hybrid。
- [ ] 默认 tls 任务行为、耗时与改动前一致。
- [ ] `go build ./... && go vet ./... && go test ./...` 全绿；`npm run build` 绿。

## Self-Review 记录

- **Spec 覆盖**：§3.1 白名单→Task 1；§3.2 扫描器+合并→Task 2；§3.3 分发+常量→Task 3；§3.4 前端→Task 4。§4 数据流经 Task 2/3 后由现有 runner.upsertAsset 承接（无需改动，spec 已注明 res.KexSafety 观测层权威路径现成）。§6 测试分布到各任务 TDD 步。
- **占位符**：无 TBD/TODO；每个代码步给出完整代码。
- **类型一致**：`applyProbeResult(res *model.ScanResult, supported []int)`、`NewTLSPQCScanner() *TLSPQCScanner`、`PQCGroupCodepoints() []int`、`ScannerTLSPQC="tls-pqc"` 跨任务签名一致。
- **决策记录**：合并逻辑抽为纯函数 `applyProbeResult` 便于无网络单测；正例（选主组/证据）纯函数测，扫描器集成仅测 httptest 经典路径（避免手搓脆弱 HRR 字节）——真·PQC 命中在最终验收用真实目标端到端验证。
