package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/cbom"
	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

// ---- ② 建档深化：CBOM 快照 + diff（C2 唯一实现，⑤ 监测域复用）----

// scopeAssets 按 scope 描述取资产集合（"" / "all" = 全量；"layer=L1"；"system=xxx"）。
// 排除 merged 终态资产。
func (s *Server) scopeAssets(scope string) []model.CryptoAsset {
	q := s.db.Where("status <> ?", model.StatusMerged)
	scope = strings.TrimSpace(scope)
	if scope != "" && scope != "all" {
		if kv := strings.SplitN(scope, "=", 2); len(kv) == 2 {
			switch strings.TrimSpace(kv[0]) {
			case "layer":
				q = q.Where("layer = ?", strings.TrimSpace(kv[1]))
			case "system":
				q = q.Where("system = ?", strings.TrimSpace(kv[1]))
			case "exposure":
				q = q.Where("exposure = ?", strings.TrimSpace(kv[1]))
			}
		}
	}
	var assets []model.CryptoAsset
	q.Order("risk_score desc").Find(&assets)
	return assets
}

// buildDigestIndex 计算 map[fingerprintKey]assetDigest（跨快照配对锚点）+ 携带资产快照镜像。
func buildDigestIndex(assets []model.CryptoAsset) (map[string]string, map[string]model.CryptoAsset) {
	digests := map[string]string{}
	mirror := map[string]model.CryptoAsset{}
	for i := range assets {
		key := assetFingerprint(&assets[i])
		digests[key] = assetDigest(&assets[i])
		mirror[key] = assets[i]
	}
	return digests, mirror
}

// createSnapshotReq 创建快照请求体。
type createSnapshotReq struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
}

// createSnapshot POST /snapshots：冻结当前 CBOM 为命名快照。
func (s *Server) createSnapshot(c *gin.Context) {
	var req createSnapshotReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = fmt.Sprintf("snapshot-%s", time.Now().Format("20060102-150405"))
	}
	var exist int64
	s.db.Model(&model.CbomSnapshot{}).Where("name = ?", name).Count(&exist)
	if exist > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "快照名已存在"})
		return
	}

	assets := s.scopeAssets(req.Scope)
	bom := cbom.Build(assets)
	bomJSON, _ := json.Marshal(bom)
	digests, _ := buildDigestIndex(assets)
	algoDist := cbom.AlgoDist(assets)

	var maxVer int
	s.db.Model(&model.CbomSnapshot{}).Select("COALESCE(MAX(version),0)").Scan(&maxVer)

	snap := model.CbomSnapshot{
		Name:         name,
		Version:      maxVer + 1,
		Scope:        req.Scope,
		AssetCount:   len(assets),
		BOMJSON:      string(bomJSON),
		DigestJSON:   db.MarshalStrMap(digests),
		AlgoDistJSON: db.MarshalIntMap(algoDist),
		TriggeredBy:  "manual",
		CreatedBy:    actorName(c),
		CreatedAt:    time.Now(),
	}
	if err := s.db.Create(&snap).Error; err != nil {
		serverError(c, err)
		return
	}
	snap.AlgoDist = algoDist
	s.audit(c, "cbom", "cbom.snapshot.create", auditTarget("CbomSnapshot", snap.ID, snap.Name), model.AuditSuccess,
		fmt.Sprintf("资产数=%d 版本=%d", snap.AssetCount, snap.Version))
	c.JSON(http.StatusCreated, snap)
}

// listSnapshots GET /snapshots：列快照（不含大 JSON），按时间倒序。
func (s *Server) listSnapshots(c *gin.Context) {
	var rows []model.CbomSnapshot
	s.db.Order("created_at desc").Find(&rows)
	for i := range rows {
		rows[i].AlgoDist = db.UnmarshalIntMap(rows[i].AlgoDistJSON)
	}
	c.JSON(http.StatusOK, rows)
}

// exportSnapshot GET /snapshots/:id/export：下载该快照冻结的 CBOM JSON。
func (s *Server) exportSnapshot(c *gin.Context) {
	var snap model.CbomSnapshot
	if err := s.db.First(&snap, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "快照不存在"})
		return
	}
	s.audit(c, "cbom", "cbom.snapshot.export",
		auditTarget("CbomSnapshot", snap.ID, snap.Name), model.AuditSuccess, "")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="cbom-%s.json"`, snap.Name))
	c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(snap.BOMJSON))
}

// deleteSnapshot DELETE /snapshots/:id。
func (s *Server) deleteSnapshot(c *gin.Context) {
	var snap model.CbomSnapshot
	if err := s.db.First(&snap, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "快照不存在"})
		return
	}
	if err := s.db.Delete(&model.CbomSnapshot{}, snap.ID).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "cbom", "cbom.snapshot.delete",
		auditTarget("CbomSnapshot", snap.ID, snap.Name), model.AuditSuccess, "")
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// ---- diff ----

// pqAlgos 标记「迁移进展」的后量子/混合目标算法（命中即 isProgress=true）。
var pqAlgos = []string{
	"ML-KEM", "ML-DSA", "SLH-DSA", "X25519+ML-KEM", "X25519MLKEM", "KYBER", "DILITHIUM",
}

// isProgressAlgo 判定从 from→to 的算法变更是否为后量子迁移进展。
func isProgressAlgo(to string) bool {
	u := strings.ToUpper(strings.ReplaceAll(to, " ", ""))
	for _, p := range pqAlgos {
		if strings.Contains(u, strings.ToUpper(strings.ReplaceAll(p, " ", ""))) {
			return true
		}
	}
	return false
}

// diffChange 一条变更项。
type diffChange struct {
	Name       string `json:"name"`
	Key        string `json:"key"`
	Type       string `json:"type"` // algo_changed/cert_rotated/status_changed/level_changed
	From       string `json:"from"`
	To         string `json:"to"`
	IsProgress bool   `json:"isProgress,omitempty"`
	Direction  string `json:"direction,omitempty"` // level_changed：↑恶化/↓改善
}

// diffItem 新增/移除项（轻量）。
type diffItem struct {
	Name      string `json:"name"`
	Key       string `json:"key"`
	Algorithm string `json:"algorithm"`
}

// snapshotSide 一侧快照的归一化数据。
type snapshotSide struct {
	id       uint
	name     string
	digests  map[string]string
	mirror   map[string]model.CryptoAsset
	algoDist map[string]int
}

// loadSnapshotSide 据快照 id（0=实时资产集）装配 diff 一侧。
func (s *Server) loadSnapshotSide(idStr string) (*snapshotSide, error) {
	if idStr == "" || idStr == "0" {
		assets := s.scopeAssets("all")
		digests, mirror := buildDigestIndex(assets)
		return &snapshotSide{id: 0, name: "实时", digests: digests, mirror: mirror, algoDist: cbom.AlgoDist(assets)}, nil
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return nil, fmt.Errorf("非法快照 id %q", idStr)
	}
	var snap model.CbomSnapshot
	if err := s.db.First(&snap, id).Error; err != nil {
		return nil, fmt.Errorf("快照 %d 不存在", id)
	}
	digestMap := db.UnmarshalStrMap(snap.DigestJSON)
	// 从 BOMJSON 还原资产镜像（用于变更字段比对）。
	mirror := map[string]model.CryptoAsset{}
	if bom, perr := cbom.Parse([]byte(snap.BOMJSON)); perr == nil {
		for _, comp := range bom.Components {
			a, ok := cbom.ComponentToAsset(comp)
			if !ok {
				continue
			}
			mirror[assetFingerprint(&a)] = a
		}
	}
	return &snapshotSide{
		id: snap.ID, name: snap.Name,
		digests: digestMap, mirror: mirror,
		algoDist: db.UnmarshalIntMap(snap.AlgoDistJSON),
	}, nil
}

// diffSnapshots GET /snapshots/diff?base=&target=：在线计算结构化 diff（C2 唯一实现）。
//
// target 缺省=实时资产集。归类：added/removed/algo_changed/cert_rotated/status_changed/level_changed
// + 算法分布环比 algoDistDelta（FR-4.6.2 完成定义）。
func (s *Server) diffSnapshots(c *gin.Context) {
	base, err := s.loadSnapshotSide(c.Query("base"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	target, err := s.loadSnapshotSide(c.Query("target"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	added := []diffItem{}
	removed := []diffItem{}
	changed := []diffChange{}

	// added / changed：遍历 target。
	for key, tDigest := range target.digests {
		ta := target.mirror[key]
		bDigest, inBase := base.digests[key]
		if !inBase {
			added = append(added, diffItem{Name: ta.Name, Key: key, Algorithm: ta.Algorithm})
			continue
		}
		if bDigest == tDigest {
			continue // 无内容变更
		}
		ba := base.mirror[key]
		if !strings.EqualFold(ba.Algorithm, ta.Algorithm) {
			changed = append(changed, diffChange{
				Name: ta.Name, Key: key, Type: "algo_changed",
				From: ba.Algorithm, To: ta.Algorithm, IsProgress: isProgressAlgo(ta.Algorithm),
			})
		}
		if ba.CertFingerprint != ta.CertFingerprint {
			changed = append(changed, diffChange{
				Name: ta.Name, Key: key, Type: "cert_rotated",
				From: ba.CertFingerprint, To: ta.CertFingerprint,
			})
		}
		if ba.Status != ta.Status && ba.Status != "" && ta.Status != "" {
			changed = append(changed, diffChange{
				Name: ta.Name, Key: key, Type: "status_changed", From: ba.Status, To: ta.Status,
			})
		}
		if ba.RiskLevel != ta.RiskLevel && ba.RiskLevel != "" && ta.RiskLevel != "" {
			changed = append(changed, diffChange{
				Name: ta.Name, Key: key, Type: "level_changed",
				From: ba.RiskLevel, To: ta.RiskLevel, Direction: levelDirection(ba.RiskLevel, ta.RiskLevel),
			})
		}
	}

	// removed：在 base 不在 target。
	for key := range base.digests {
		if _, ok := target.digests[key]; !ok {
			ba := base.mirror[key]
			removed = append(removed, diffItem{Name: ba.Name, Key: key, Algorithm: ba.Algorithm})
		}
	}

	// 算法分布环比 delta = target - base。
	delta := map[string]int{}
	for k, v := range target.algoDist {
		delta[k] += v
	}
	for k, v := range base.algoDist {
		delta[k] -= v
	}
	for k, v := range delta {
		if v == 0 {
			delete(delta, k)
		}
	}

	algoChanged, certRotated, statusChanged, levelChanged := 0, 0, 0, 0
	for _, ch := range changed {
		switch ch.Type {
		case "algo_changed":
			algoChanged++
		case "cert_rotated":
			certRotated++
		case "status_changed":
			statusChanged++
		case "level_changed":
			levelChanged++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"base":   gin.H{"id": base.id, "name": base.name},
		"target": gin.H{"id": target.id, "name": target.name},
		"summary": gin.H{
			"added":         len(added),
			"removed":       len(removed),
			"algoChanged":   algoChanged,
			"certRotated":   certRotated,
			"statusChanged": statusChanged,
			"levelChanged":  levelChanged,
		},
		"added":         added,
		"removed":       removed,
		"changed":       changed,
		"algoDistDelta": delta,
	})
}

// levelDirection 据风险等级判定方向（P1 最高危）。
func levelDirection(from, to string) string {
	rank := map[string]int{model.LevelP1: 4, model.LevelP2: 3, model.LevelP3: 2, model.LevelP4: 1}
	if rank[to] > rank[from] {
		return "↑恶化"
	}
	if rank[to] < rank[from] {
		return "↓改善"
	}
	return ""
}
