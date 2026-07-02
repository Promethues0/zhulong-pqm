package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/model"
)

// ---- ⑥ 系统设置（Wave C）：KV 配置，GET 分组返回 / PUT schema 校验 ----
//
// C3：scoring.weights 设置项仅做只读展示/回退默认，真正生效权重唯一真相源仍是 ScoreProfile；
// 此处不另开第二条写路径（PUT scoring.weights 被拒）。

// settingItem 单条设置的响应形态（Value 解析为任意 JSON 值后输出）。
type settingItem struct {
	Key       string      `json:"key"`
	Category  string      `json:"category"`
	Value     interface{} `json:"value"`
	UpdatedBy string      `json:"updatedBy"`
	UpdatedAt time.Time   `json:"updatedAt"`
	ReadOnly  bool        `json:"readOnly"`
}

// parseSettingValue 把存储的 JSON 文本解析为任意值；解析失败回退原文字符串。
func parseSettingValue(raw string) interface{} {
	var v interface{}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	return v
}

// settingReadOnly 判定该键是否为只读（C3：scoring.weights）。
func settingReadOnly(key string) bool {
	return key == model.SettingScoringWeights
}

// listSettings GET /settings → 按 category 分组返回所有配置项。
func (s *Server) listSettings(c *gin.Context) {
	var rows []model.Setting
	if err := s.db.Order("category asc, key asc").Find(&rows).Error; err != nil {
		serverError(c, err)
		return
	}
	grouped := map[string][]settingItem{}
	flat := map[string]interface{}{}
	for _, r := range rows {
		item := settingItem{
			Key:       r.Key,
			Category:  r.Category,
			Value:     parseSettingValue(r.Value),
			UpdatedBy: r.UpdatedBy,
			UpdatedAt: r.UpdatedAt,
			ReadOnly:  settingReadOnly(r.Key),
		}
		grouped[r.Category] = append(grouped[r.Category], item)
		flat[r.Key] = item.Value
	}
	c.JSON(http.StatusOK, gin.H{"categories": grouped, "values": flat})
}

// getSetting GET /settings/:key → 单条配置。
func (s *Server) getSetting(c *gin.Context) {
	var r model.Setting
	if err := s.db.First(&r, "key = ?", c.Param("key")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "配置项不存在"})
		return
	}
	c.JSON(http.StatusOK, settingItem{
		Key:       r.Key,
		Category:  r.Category,
		Value:     parseSettingValue(r.Value),
		UpdatedBy: r.UpdatedBy,
		UpdatedAt: r.UpdatedAt,
		ReadOnly:  settingReadOnly(r.Key),
	})
}

// validateSettingValue 按键做 schema/范围校验。返回规范化后的 JSON 文本。
func validateSettingValue(key string, body []byte) (string, error) {
	switch key {
	case model.SettingScanDefaults:
		var v struct {
			Exposure    string `json:"exposure"`
			Ports       []int  `json:"ports"`
			TimeoutSec  int    `json:"timeoutSec"`
			Concurrency int    `json:"concurrency"`
		}
		if err := json.Unmarshal(body, &v); err != nil {
			return "", fmt.Errorf("scan.defaults 格式错误: %w", err)
		}
		if v.TimeoutSec <= 0 || v.TimeoutSec > 600 {
			return "", fmt.Errorf("timeoutSec 须在 1..600 之间")
		}
		if v.Concurrency <= 0 || v.Concurrency > 256 {
			return "", fmt.Errorf("concurrency 须在 1..256 之间")
		}
		for _, p := range v.Ports {
			if p <= 0 || p > 65535 {
				return "", fmt.Errorf("端口 %d 非法（1..65535）", p)
			}
		}
		out, _ := json.Marshal(v)
		return string(out), nil

	case model.SettingSLOThresholds:
		var v map[string]float64
		if err := json.Unmarshal(body, &v); err != nil {
			return "", fmt.Errorf("slo.thresholds 格式错误: %w", err)
		}
		for k, val := range v {
			if val <= 0 {
				return "", fmt.Errorf("SLO 阈值 %s 须为正数", k)
			}
		}
		// CA 提前量 ≥ 服务器提前量（与 MonitorPolicy 校验同口径）。
		if ca, ok := v["caCertWarnDays"]; ok {
			if sv, ok2 := v["serverCertWarnDays"]; ok2 && ca < sv {
				return "", fmt.Errorf("caCertWarnDays 须 ≥ serverCertWarnDays")
			}
		}
		out, _ := json.Marshal(v)
		return string(out), nil

	case model.SettingThreatIntelSrc:
		var v []map[string]interface{}
		if err := json.Unmarshal(body, &v); err != nil {
			return "", fmt.Errorf("threatintel.sources 须为数组: %w", err)
		}
		out, _ := json.Marshal(v)
		return string(out), nil

	case model.SettingRetention:
		var v map[string]int
		if err := json.Unmarshal(body, &v); err != nil {
			return "", fmt.Errorf("retention 格式错误: %w", err)
		}
		for k, val := range v {
			if val <= 0 {
				return "", fmt.Errorf("保存期 %s 须为正整数（天）", k)
			}
		}
		out, _ := json.Marshal(v)
		return string(out), nil

	default:
		// 未知键：透传合法 JSON。
		var probe interface{}
		if err := json.Unmarshal(body, &probe); err != nil {
			return "", fmt.Errorf("value 须为合法 JSON")
		}
		return string(body), nil
	}
}

// updateSetting PUT /settings/:key → 更新单键（writer 组）。body 为该键的 JSON 值。
// C3：scoring.weights 只读，拒绝写入并提示走 ScoreProfile。
func (s *Server) updateSetting(c *gin.Context) {
	key := c.Param("key")
	if settingReadOnly(key) {
		s.audit(c, "setting", "setting.update", auditTargetStr("Setting", key, key), model.AuditDenied,
			"scoring.weights 为只读展示项，权重唯一真相源为 ScoreProfile（C3）")
		c.JSON(http.StatusForbidden, gin.H{"error": "scoring.weights 只读展示，请通过权重方案（ScoreProfile）调整生效权重"})
		return
	}

	var r model.Setting
	if err := s.db.First(&r, "key = ?", key).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "配置项不存在"})
		return
	}

	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	normalized, verr := validateSettingValue(key, body)
	if verr != nil {
		s.audit(c, "setting", "setting.update", auditTargetStr("Setting", key, key), model.AuditFailure, verr.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": verr.Error()})
		return
	}

	r.Value = normalized
	r.UpdatedBy = actorName(c)
	r.UpdatedAt = time.Now()
	if err := s.db.Save(&r).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "setting", "setting.update", auditTargetStr("Setting", key, key), model.AuditSuccess, "")
	c.JSON(http.StatusOK, settingItem{
		Key:       r.Key,
		Category:  r.Category,
		Value:     parseSettingValue(r.Value),
		UpdatedBy: r.UpdatedBy,
		UpdatedAt: r.UpdatedAt,
		ReadOnly:  false,
	})
}
