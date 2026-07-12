// Package db 负责数据库的打开、迁移与种子数据初始化。
package db

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/remediate"
	"zhulong-pqm/internal/scoring"
)

// Open 打开 SQLite 数据库，执行 AutoMigrate，并按需植入种子数据。
func Open(path string) (*gorm.DB, error) {
	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := gdb.AutoMigrate(
		&model.User{},
		&model.CryptoAsset{},
		&model.ScanJob{},
		&model.ScanResult{},
		// ① 发现深化（Wave B-1）
		&model.ScanRule{},
		&model.RuleHit{},
		// ② 建档深化（Wave B-1）
		&model.AssetEvidence{},
		&model.CbomSnapshot{},
		&model.Report{},
		&model.Device{},
		&model.RemediationTask{},
		// M-B 主机 Agent / 探针身份
		&model.Agent{},
		&model.ScoreProfile{},
		&model.ScoreHistory{},
		&model.RescoreRun{},
		&model.AuditLog{},
		// ⑤ 持续监测（A5-1）
		&model.MonitorPolicy{},
		&model.SLOMetric{},
		&model.MonitorEvent{},
		&model.LegacyRisk{},
		&model.ThreatIntel{},
		// ④ 验收自动化（A4-1）
		&model.AcceptanceRun{},
		&model.TestResult{},
		&model.AcceptanceReport{},
		// ⑥ 平台横切（Wave C）：系统设置 / 仪表板趋势 / 资产分组
		&model.Setting{},
		&model.MetricSnapshot{},
		&model.AssetGroup{},
	); err != nil {
		return nil, fmt.Errorf("automigrate: %w", err)
	}

	// ② 建档去重（#7）：先幂等去重，再补 CryptoAsset 锚点唯一索引，防重复入库。
	migrateAssetDedup(gdb)

	if err := seed(gdb); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	return gdb, nil
}

// migrateAssetDedup 收敛资产去重锚点并建部分唯一索引（#7 数据完整性）。
//
// 锚点与两条 upsert 路径一致：有 endpoint 者以 endpoint 为准（扫描发现），
// 无 endpoint 但有 cert 者以 cert 指纹为准（PEM/SBOM 导入）；两者皆空的手动资产不去重。
// 步骤：① 幂等软合并同锚点重复行（保留最小 id，其余置 merged_into+status=merged，
// 与 ② 建档合并语义一致、数据不删）；② 建【部分】唯一索引（排除空锚点与已合并行，
// 故手动资产可任意重名、被合并行不冲突）。索引创建失败仅告警不致命，绝不阻断启动。
func migrateAssetDedup(gdb *gorm.DB) {
	// ① 软合并：按 endpoint 去重（扫描路径）。
	if err := gdb.Exec(`
		UPDATE crypto_assets
		SET merged_into = (SELECT MIN(a2.id) FROM crypto_assets a2
		                   WHERE a2.endpoint = crypto_assets.endpoint AND a2.merged_into IS NULL),
		    status = 'merged'
		WHERE endpoint != '' AND merged_into IS NULL
		  AND id > (SELECT MIN(a2.id) FROM crypto_assets a2
		            WHERE a2.endpoint = crypto_assets.endpoint AND a2.merged_into IS NULL)`).Error; err != nil {
		log.Printf("db: 资产 endpoint 去重失败: %v", err)
	}
	// ① 软合并：无 endpoint 者按 cert 指纹去重（导入路径）。
	if err := gdb.Exec(`
		UPDATE crypto_assets
		SET merged_into = (SELECT MIN(a2.id) FROM crypto_assets a2
		                   WHERE a2.cert_fingerprint = crypto_assets.cert_fingerprint AND a2.endpoint = '' AND a2.merged_into IS NULL),
		    status = 'merged'
		WHERE endpoint = '' AND cert_fingerprint != '' AND merged_into IS NULL
		  AND id > (SELECT MIN(a2.id) FROM crypto_assets a2
		            WHERE a2.cert_fingerprint = crypto_assets.cert_fingerprint AND a2.endpoint = '' AND a2.merged_into IS NULL)`).Error; err != nil {
		log.Printf("db: 资产 cert 指纹去重失败: %v", err)
	}
	// ② 部分唯一索引（IF NOT EXISTS 幂等；失败仅告警，不阻断启动）。
	for _, ddl := range []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_ca_endpoint ON crypto_assets(endpoint) WHERE endpoint != '' AND merged_into IS NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_ca_certfp ON crypto_assets(cert_fingerprint) WHERE cert_fingerprint != '' AND endpoint = '' AND merged_into IS NULL`,
	} {
		if err := gdb.Exec(ddl).Error; err != nil {
			log.Printf("db: 建资产唯一索引失败（可能仍有残留重复，已跳过不阻断启动）: %v", err)
		}
	}
}

// seed 在空库时植入默认管理员、内置权重方案、示例资产、改造设备与示例工单。
func seed(gdb *gorm.DB) error {
	if err := seedAdmin(gdb); err != nil {
		return err
	}
	if err := seedScoreProfile(gdb); err != nil {
		return err
	}
	if err := seedAssets(gdb); err != nil {
		return err
	}
	if err := seedDevices(gdb); err != nil {
		return err
	}
	if err := seedRemediations(gdb); err != nil {
		return err
	}
	if err := seedLegacyRisks(gdb); err != nil {
		return err
	}
	if err := seedScanRules(gdb); err != nil {
		return err
	}
	if err := seedMonitorPolicy(gdb); err != nil {
		return err
	}
	return seedSettings(gdb)
}

// seedSettings 在设置表为空时植入默认配置项（PRD 默认口径，C3：scoring.weights 仅展示/回退）。
func seedSettings(gdb *gorm.DB) error {
	var count int64
	gdb.Model(&model.Setting{}).Count(&count)
	if count > 0 {
		return nil
	}
	now := time.Now()
	defaults := []struct {
		Key, Category, Value string
	}{
		{model.SettingScanDefaults, "scan",
			`{"exposure":"internal","ports":[443,8443],"timeoutSec":5,"concurrency":16}`},
		{model.SettingSLOThresholds, "slo",
			`{"handshakeFailRate":0.1,"latencyP99CeilMs":46.2,"throughputDropCeilPct":6.5,"ikev2EstablishCeilMs":437,"cbomFreshnessDays":90,"caCertWarnDays":180,"serverCertWarnDays":30,"iotCertWarnDays":365}`},
		{model.SettingScoringWeights, "scoring",
			`{"preset":"default","readOnly":true,"d1":30,"d2":25,"d3":20,"d4":15,"d5":10,"p1Threshold":75,"hndlD2":60,"hndlD3":60,"note":"权重唯一真相源为 ScoreProfile，此项仅展示/回退默认（C3）"}`},
		{model.SettingThreatIntelSrc, "threatintel",
			`[{"name":"NIST PQC","url":"https://csrc.nist.gov/projects/post-quantum-cryptography","enabled":true,"kind":"standard_update"},{"name":"国密局","url":"","enabled":true,"kind":"algo_deprecate"}]`},
		{model.SettingRetention, "retention",
			`{"auditDays":365,"eventDays":180,"snapshotDays":730,"metricDays":365}`},
	}
	for _, d := range defaults {
		rec := model.Setting{Key: d.Key, Category: d.Category, Value: d.Value, UpdatedBy: "system", UpdatedAt: now}
		if err := gdb.Create(&rec).Error; err != nil {
			return err
		}
	}
	log.Printf("seed: 已创建 %d 项默认系统设置（扫描默认/SLO 阈值/权重展示/情报源/保存期）", len(defaults))
	return nil
}

// seedLegacyRisk 描述一条初始遗留风险登记项（PRD 行 1019-1022 R-001..004）。
type seedLegacyRisk struct {
	Code        string
	Description string
	Level       string
	Disposition string
	AlwaysOnSLO bool
	RecheckDays int // 自创建起的复检间隔天数
}

// seedLegacyRisks_ 初始 R-00x 台账（C4 唯一种子源；④ 验收有条件项挂接、⑤ 看板常显复用）。
// R-003「高」级纳入 SLO 看板常显（AlwaysOnSLO=true，FR-7.10 完成定义）。
var seedLegacyRisks_ = []seedLegacyRisk{
	{"R-001", "TLS 1.2 遗留 Java 无法混合握手", "中", "P3 专项工单 #2341", false, 90},
	{"R-002", "TSA 供应商升级（时间戳）", "中", "待供应商升级", false, 90},
	{"R-003", "IoT/工控 47 台 5–10 年证书无 OTA（需现场检修替换）", "高", "年度检修替换", true, 180},
	{"R-004", "iOS ML-KEM 原生支持待 Apple", "中", "等待上游", false, 90},
}

// seedLegacyRisks 在台账为空时植入 R-001..R-004。
func seedLegacyRisks(gdb *gorm.DB) error {
	var count int64
	gdb.Model(&model.LegacyRisk{}).Count(&count)
	if count > 0 {
		return nil
	}
	now := time.Now()
	for _, r := range seedLegacyRisks_ {
		recheck := now.AddDate(0, 0, r.RecheckDays)
		risk := model.LegacyRisk{
			Code:        r.Code,
			Description: r.Description,
			Level:       r.Level,
			Disposition: r.Disposition,
			Status:      model.RiskTracking,
			Owner:       "安全部",
			RecheckDate: &recheck,
			AlwaysOnSLO: r.AlwaysOnSLO,
		}
		if err := gdb.Create(&risk).Error; err != nil {
			return err
		}
	}
	log.Printf("seed: 已创建 %d 条遗留风险登记（R-001..R-004）", len(seedLegacyRisks_))
	return nil
}

// seedMonitorPolicy 在策略表为空时植入 1 条默认季度复扫策略（阈值=PRD SLO 默认）。
func seedMonitorPolicy(gdb *gorm.DB) error {
	var count int64
	gdb.Model(&model.MonitorPolicy{}).Count(&count)
	if count > 0 {
		return nil
	}
	p := model.MonitorPolicy{
		Name:                   "核心区季度复扫",
		Enabled:                true,
		ScopeKind:              model.ScopeAll,
		RescanCron:             "0 0 3 1 */3 *", // 每季度（PRD 文件1-2）
		HandshakeFailThreshold: 0.1,
		LatencyP99CeilMs:       46.2,
		ThroughputDropCeilPct:  6.5,
		IKEv2EstablishCeilMs:   437,
		CBOMFreshnessDays:      90,
		CACertWarnDays:         180,
		ServerCertWarnDays:     30,
		IoTCertWarnDays:        365,
	}
	if err := gdb.Create(&p).Error; err != nil {
		return err
	}
	log.Println("seed: 已创建默认监测策略「核心区季度复扫」(0.1%/46.2/6.5%/437/90/180/30/365)")
	return nil
}

// MarshalMonEvidence 将监测事件证据 map 序列化为 JSON（供 MonitorEvent.Evidence 存储）。
func MarshalMonEvidence(m map[string]string) string {
	if m == nil {
		m = map[string]string{}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// UnmarshalMonEvidence 反序列化 MonitorEvent.Evidence。
func UnmarshalMonEvidence(s string) map[string]string {
	out := map[string]string{}
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// seedScoreProfile 在方案表为空时植入唯一内置「标准权重」方案（30/25/20/15/10，
// IsActive+IsBuiltin），保证空库即有生效方案（权重唯一真相源 C3）。
func seedScoreProfile(gdb *gorm.DB) error {
	var count int64
	gdb.Model(&model.ScoreProfile{}).Count(&count)
	if count > 0 {
		return nil
	}
	now := time.Now()
	p := model.ScoreProfile{
		Name:        "标准权重",
		Description: "PRD DP-11 标准锁定权重 D1×30/D2×25/D3×20/D4×15/D5×10（内置只读基线）",
		W1:          scoring.StandardWeights.W1,
		W2:          scoring.StandardWeights.W2,
		W3:          scoring.StandardWeights.W3,
		W4:          scoring.StandardWeights.W4,
		W5:          scoring.StandardWeights.W5,
		IsActive:    true,
		IsBuiltin:   true,
		Version:     1,
		CreatedBy:   "system",
		AppliedBy:   "system",
		AppliedAt:   &now,
	}
	if err := gdb.Create(&p).Error; err != nil {
		return err
	}
	log.Println("seed: 已创建内置权重方案「标准权重」(30/25/20/15/10, active)")
	return nil
}

// ActiveWeights 返回当前生效（IsActive）权重方案的权重；无生效方案则回退 StandardWeights。
// 单资产手工评分与批量复算共用此口径（C3）。
func ActiveWeights(gdb *gorm.DB) scoring.Weights {
	var p model.ScoreProfile
	if err := gdb.Where("is_active = ?", true).First(&p).Error; err != nil {
		return scoring.StandardWeights
	}
	w := scoring.Weights{W1: p.W1, W2: p.W2, W3: p.W3, W4: p.W4, W5: p.W5}
	if w.Sum() != 100 {
		return scoring.StandardWeights
	}
	return w
}

// ActiveProfile 返回当前生效权重方案（无则返回 ok=false）。供写 ScoreHistory 快照取 ProfileID/Name。
func ActiveProfile(gdb *gorm.DB) (model.ScoreProfile, bool) {
	var p model.ScoreProfile
	if err := gdb.Where("is_active = ?", true).First(&p).Error; err != nil {
		return model.ScoreProfile{}, false
	}
	return p, true
}

func seedAdmin(gdb *gorm.DB) error {
	var count int64
	gdb.Model(&model.User{}).Count(&count)
	if count > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin@1234"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	admin := model.User{
		Username:     "admin",
		PasswordHash: string(hash),
		Role:         model.RoleAdmin,
		DisplayName:  "系统管理员",
		Status:       model.UserActive,
	}
	if err := gdb.Create(&admin).Error; err != nil {
		return err
	}
	log.Println("seed: 已创建默认管理员 admin/admin@1234")
	return nil
}

// seedAsset 描述一条示例资产的可读属性，其五维分用于实时评分。
type seedAsset struct {
	Name       string
	System     string
	Layer      string
	Algorithm  string
	KeySize    int
	Protocol   string
	Exposure   string
	Department string
	Dims       [5]int
}

var seedAssets_ = []seedAsset{
	{"内部根CA", "PKI 信任体系", model.LayerL4, "RSA", 4096, "", model.ExposureInternal, "安全部", [5]int{90, 100, 100, 85, 10}},
	{"SSL VPN网关", "远程接入", model.LayerL2, "ECDSA", 256, "TLS 1.2", model.ExposurePublic, "网络部", [5]int{90, 85, 60, 85, 90}},
	{"对外TLS证书", "门户网站", model.LayerL1, "RSA", 2048, "TLS 1.3", model.ExposurePublic, "运维部", [5]int{70, 30, 10, 10, 90}},
	{"长期合规档案", "档案归档系统", model.LayerL3, "AES", 128, "", model.ExposureInternal, "合规部", [5]int{90, 85, 100, 35, 10}},
	{"IoT设备证书", "物联网平台", model.LayerL1, "ECDSA", 256, "TLS 1.2", model.ExposureDMZ, "物联网部", [5]int{70, 60, 100, 100, 40}},
	{"数据库静态加密", "核心数据库", model.LayerL3, "AES", 256, "", model.ExposureInternal, "数据部", [5]int{40, 85, 60, 35, 10}},
	{"代码签名证书", "软件供应链", model.LayerL1, "RSA", 3072, "", model.ExposureDMZ, "研发部", [5]int{90, 85, 85, 10, 70}},
}

func seedAssets(gdb *gorm.DB) error {
	var count int64
	gdb.Model(&model.CryptoAsset{}).Count(&count)
	if count > 0 {
		return nil
	}
	for _, s := range seedAssets_ {
		dims := scoring.Dimensions{D1: s.Dims[0], D2: s.Dims[1], D3: s.Dims[2], D4: s.Dims[3], D5: s.Dims[4]}
		r := scoring.Score(dims)
		a := model.CryptoAsset{
			Name:          s.Name,
			System:        s.System,
			Layer:         s.Layer,
			Department:    s.Department,
			Algorithm:     s.Algorithm,
			KeySize:       s.KeySize,
			Protocol:      s.Protocol,
			Exposure:      s.Exposure,
			Source:        model.SourceManual,
			Confidence:    100,
			Status:        model.StatusConfirmed,
			D1:            dims.D1,
			D2:            dims.D2,
			D3:            dims.D3,
			D4:            dims.D4,
			D5:            dims.D5,
			RiskScore:     r.Score,
			RawScore:      r.RawScore,
			RiskLevel:     r.Level,
			RiskLevelText: r.LevelText,
			HNDL:          r.HNDL,
			SuggestedAlgo: scoring.SuggestAlgo(s.Algorithm),
			RiskHint: fmt.Sprintf("%s 综合风险 %d(%s) 建议迁移窗口 %s",
				s.Algorithm, r.Score, r.LevelText, r.Window),
		}
		if err := gdb.Create(&a).Error; err != nil {
			return err
		}
	}
	log.Printf("seed: 已创建 %d 条示例资产", len(seedAssets_))
	return nil
}

// seedDevice 描述一台示例改造设备。
type seedDevice struct {
	Name     string
	Type     string
	Vendor   string
	Endpoint string
	Username string // 网关真机联调登录用户名（仅 gateway 用）
	Token    string // 接入凭据/网关登录口令（明文存，绝不出响应）
	Caps     []string
}

var seedDevices_ = []seedDevice{
	{"烛龙IPSEC网关-核心区", model.DeviceGateway, "烛龙", "http://localhost:8088", "sysadmin", "admin123", []string{"ke1_mlkem", "x25519mlkem768", "sm2-hybrid"}},
	{"加密机 HSM-01", model.DeviceHSM, "国密HSM", "http://localhost:9000", "", "", []string{"ml-dsa", "ml-kem", "root-ca"}},
	{"内部CA", model.DeviceCA, "internal", "http://localhost:8080", "", "", []string{"ml-dsa", "dual-sign"}},
}

// seedDevices 在设备表为空时植入 3 台示例改造设备。
func seedDevices(gdb *gorm.DB) error {
	var count int64
	gdb.Model(&model.Device{}).Count(&count)
	if count > 0 {
		return nil
	}
	for _, d := range seedDevices_ {
		dev := model.Device{
			Name:             d.Name,
			Type:             d.Type,
			Vendor:           d.Vendor,
			Endpoint:         d.Endpoint,
			Username:         d.Username,
			Token:            d.Token,
			CapabilitiesJSON: MarshalStrings(d.Caps),
			Status:           model.DeviceStatusUnknown,
		}
		if err := gdb.Create(&dev).Error; err != nil {
			return err
		}
	}
	log.Printf("seed: 已创建 %d 台示例改造设备", len(seedDevices_))
	return nil
}

// seedRemediations 在工单表为空时，对一个 P1 资产建一条 root-ca-hybrid 示例工单（planned，不自动执行）。
func seedRemediations(gdb *gorm.DB) error {
	var count int64
	gdb.Model(&model.RemediationTask{}).Count(&count)
	if count > 0 {
		return nil
	}

	pb, ok := remediate.PlaybookByKey("root-ca-hybrid")
	if !ok {
		return nil
	}

	// 取一个适配 HSM 的资产（优先“内部根CA”）作为示例工单的资产；缺失则跳过。
	var asset model.CryptoAsset
	if err := gdb.Where("name = ?", "内部根CA").First(&asset).Error; err != nil {
		return nil // 没有合适资产就不强行造工单，保持种子幂等且诚实。
	}

	// 取一台 HSM 设备作为执行设备。
	var device model.Device
	if err := gdb.Where("type = ?", model.DeviceHSM).First(&device).Error; err != nil {
		return nil
	}

	steps := make([]model.Step, 0, len(pb.Steps))
	for _, name := range pb.Steps {
		steps = append(steps, model.Step{Name: name, Status: model.StepPending})
	}

	assetID := asset.ID
	deviceID := device.ID
	task := model.RemediationTask{
		AssetID:      &assetID,
		AssetName:    asset.Name,
		Track:        pb.Key,
		TrackName:    pb.Name,
		TargetAlgo:   pb.TargetAlgo,
		DeviceID:     &deviceID,
		DeviceName:   device.Name,
		DeviceType:   device.Type,
		Status:       model.RemPlanned,
		Progress:     0,
		StepsJSON:    MarshalSteps(steps),
		Deliverable:  pb.Deliverable,
		Acceptance:   pb.Acceptance,
		EvidenceJSON: MarshalEvidence(nil),
	}
	if err := gdb.Create(&task).Error; err != nil {
		return err
	}
	log.Println("seed: 已创建 1 条示例改造工单（root-ca-hybrid，planned）")
	return nil
}

// MarshalTargets 将目标切片序列化为 JSON 字符串（供 ScanJob.Targets 存储）。
func MarshalTargets(targets []string) string {
	b, _ := json.Marshal(targets)
	return string(b)
}

// UnmarshalTargets 反序列化 ScanJob.Targets。
func UnmarshalTargets(s string) []string {
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// MarshalStrings 将字符串切片序列化为 JSON（供 Device.Capabilities 存储）。
func MarshalStrings(in []string) string {
	if in == nil {
		in = []string{}
	}
	b, _ := json.Marshal(in)
	return string(b)
}

// UnmarshalStrings 反序列化字符串切片 JSON 字段。
func UnmarshalStrings(s string) []string {
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// MarshalIntMap 将 map[string]int 序列化为 JSON（供 CbomSnapshot.AlgoDist/Digest 存储）。
func MarshalIntMap(m map[string]int) string {
	if m == nil {
		m = map[string]int{}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// UnmarshalIntMap 反序列化 map[string]int JSON 字段。
func UnmarshalIntMap(s string) map[string]int {
	out := map[string]int{}
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// MarshalStrMap 将 map[string]string 序列化为 JSON（供快照 digest 索引存储）。
func MarshalStrMap(m map[string]string) string {
	if m == nil {
		m = map[string]string{}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// UnmarshalStrMap 反序列化 map[string]string JSON 字段。
func UnmarshalStrMap(s string) map[string]string {
	out := map[string]string{}
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// MarshalSteps 将步骤切片序列化为 JSON（供 RemediationTask.Steps 存储）。
func MarshalSteps(steps []model.Step) string {
	if steps == nil {
		steps = []model.Step{}
	}
	b, _ := json.Marshal(steps)
	return string(b)
}

// UnmarshalSteps 反序列化 RemediationTask.Steps。
func UnmarshalSteps(s string) []model.Step {
	var out []model.Step
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// MarshalEvidence 将证据 map 序列化为 JSON（供 RemediationTask.Evidence 存储）。
func MarshalEvidence(m map[string]string) string {
	if m == nil {
		m = map[string]string{}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// UnmarshalEvidence 反序列化 RemediationTask.Evidence。
func UnmarshalEvidence(s string) map[string]string {
	out := map[string]string{}
	_ = json.Unmarshal([]byte(s), &out)
	return out
}
