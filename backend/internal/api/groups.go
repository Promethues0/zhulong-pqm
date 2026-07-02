package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
)

// ---- ② 资产分组（Wave C）：AssetGroup 受控词表 + group_tags 标签式多对多 ----

// loadAssetGroupTags 反序列化资产分组标签镜像（响应/筛选用，仿 Device.Capabilities）。
func loadAssetGroupTags(a *model.CryptoAsset) {
	a.GroupTags = db.UnmarshalStrings(a.GroupTagsJSON)
}

// listAssetGroups GET /asset-groups → 分组词表 + 每组资产计数（JSON LIKE 匹配 group_tags）。
func (s *Server) listAssetGroups(c *gin.Context) {
	var groups []model.AssetGroup
	if err := s.db.Order("kind asc, name asc").Find(&groups).Error; err != nil {
		serverError(c, err)
		return
	}
	type groupOut struct {
		model.AssetGroup
		Count int `json:"count"`
	}
	out := make([]groupOut, 0, len(groups))
	for _, g := range groups {
		var cnt int64
		// group_tags 存的是 JSON 数组字符串，用 LIKE 匹配带引号的精确成员，避免子串误匹配。
		s.db.Model(&model.CryptoAsset{}).
			Where("status <> ? AND group_tags LIKE ?", model.StatusMerged, `%"`+g.Name+`"%`).
			Count(&cnt)
		out = append(out, groupOut{AssetGroup: g, Count: int(cnt)})
	}
	c.JSON(http.StatusOK, out)
}

// assetGroupReq 分组创建/更新请求体。
type assetGroupReq struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// validGroupKind 校验分组维度。
func validGroupKind(k string) bool {
	switch k {
	case model.GroupBusiness, model.GroupRegion, model.GroupCompliance, model.GroupCustom, "":
		return true
	}
	return false
}

// createAssetGroup POST /asset-groups → 新建分组词条（writer 组）。
func (s *Server) createAssetGroup(c *gin.Context) {
	var req assetGroupReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name 必填"})
		return
	}
	if !validGroupKind(req.Kind) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "kind 非法（business/region/compliance/custom）"})
		return
	}
	if req.Kind == "" {
		req.Kind = model.GroupCustom
	}
	var exist int64
	s.db.Model(&model.AssetGroup{}).Where("name = ?", req.Name).Count(&exist)
	if exist > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "分组名已存在"})
		return
	}
	g := model.AssetGroup{Name: req.Name, Kind: req.Kind, Description: req.Description, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.db.Create(&g).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "asset", "group.create", auditTarget("AssetGroup", g.ID, g.Name), model.AuditSuccess, g.Kind)
	c.JSON(http.StatusCreated, g)
}

// updateAssetGroup PUT /asset-groups/:id → 更新词条（writer 组）。
func (s *Server) updateAssetGroup(c *gin.Context) {
	var g model.AssetGroup
	if err := s.db.First(&g, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "分组不存在"})
		return
	}
	var req assetGroupReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !validGroupKind(req.Kind) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "kind 非法"})
		return
	}
	if req.Name != "" {
		req.Name = strings.TrimSpace(req.Name)
		if req.Name != g.Name {
			var exist int64
			s.db.Model(&model.AssetGroup{}).Where("name = ? AND id <> ?", req.Name, g.ID).Count(&exist)
			if exist > 0 {
				c.JSON(http.StatusConflict, gin.H{"error": "分组名已存在"})
				return
			}
		}
		g.Name = req.Name
	}
	if req.Kind != "" {
		g.Kind = req.Kind
	}
	g.Description = req.Description
	g.UpdatedAt = time.Now()
	if err := s.db.Save(&g).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "asset", "group.update", auditTarget("AssetGroup", g.ID, g.Name), model.AuditSuccess, "")
	c.JSON(http.StatusOK, g)
}

// deleteAssetGroup DELETE /asset-groups/:id → 删除词条（不动资产标签，writer 组）。
func (s *Server) deleteAssetGroup(c *gin.Context) {
	var g model.AssetGroup
	if err := s.db.First(&g, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "分组不存在"})
		return
	}
	if err := s.db.Delete(&model.AssetGroup{}, g.ID).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "asset", "group.delete", auditTarget("AssetGroup", g.ID, g.Name), model.AuditSuccess, "")
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// assetsByGroup GET /assets/by-group → 按 group_tag（默认）或 system 聚合：每组 count/p1/hndl。
// ?dim=system 时按系统维度 group-by（复用现有 CryptoAsset.System，无需新模型）。
func (s *Server) assetsByGroup(c *gin.Context) {
	var assets []model.CryptoAsset
	s.db.Where("status <> ?", model.StatusMerged).Find(&assets)

	type agg struct {
		Group     string `json:"group"`
		Count     int    `json:"count"`
		P1Count   int    `json:"p1Count"`
		HNDLCount int    `json:"hndlCount"`
	}

	dim := c.Query("dim")
	order := []string{}
	buckets := map[string]*agg{}
	bump := func(key string, a *model.CryptoAsset) {
		b, ok := buckets[key]
		if !ok {
			b = &agg{Group: key}
			buckets[key] = b
			order = append(order, key)
		}
		b.Count++
		if a.RiskLevel == model.LevelP1 {
			b.P1Count++
		}
		if a.HNDL {
			b.HNDLCount++
		}
	}

	if dim == "system" {
		for i := range assets {
			key := assets[i].System
			if key == "" {
				key = "(未分类系统)"
			}
			bump(key, &assets[i])
		}
	} else {
		// group_tag 维度：一资产可属多组；无标签归入「未分组」。
		for i := range assets {
			tags := db.UnmarshalStrings(assets[i].GroupTagsJSON)
			if len(tags) == 0 {
				bump("(未分组)", &assets[i])
				continue
			}
			for _, t := range tags {
				bump(t, &assets[i])
			}
		}
	}

	out := make([]agg, 0, len(order))
	for _, k := range order {
		out = append(out, *buckets[k])
	}
	c.JSON(http.StatusOK, gin.H{"dim": dimOrDefault(dim), "groups": out})
}

func dimOrDefault(dim string) string {
	if dim == "system" {
		return "system"
	}
	return "group_tag"
}

// groupFilterClause 构造 group 筛选 where（供 listAssets 复用）：精确匹配 JSON 数组成员。
func groupFilterClause(group string) (string, string) {
	return "group_tags LIKE ?", fmt.Sprintf(`%%"%s"%%`, group)
}
