package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/remediate"
)

// validateEndpoint 校验设备 endpoint，缓解 SSRF。
//
// 注意：PQM 本就是面向内网的扫描/编排平台，合法目标包含 RFC1918 内网地址，
// 甚至同机网关 http://127.0.0.1:8088 —— 故【不】封禁内网/回环，只挡住真正危险且
// 无正当用途的向量：(1) 非 http/https scheme（file://、gopher:// 等）；
// (2) 链路本地/云元数据地址 169.254.0.0/16（经典 SSRF 取 metadata 目标）。
func validateEndpoint(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil // 允许留空（未配置）
	}
	host := raw
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("endpoint 不是合法 URL")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("endpoint 仅支持 http/https，已拒绝 %q", u.Scheme)
		}
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("endpoint 指向链路本地/云元数据地址（169.254.0.0/16），已拒绝")
		}
	}
	// 云元数据主机名（绕过 IP 检查的经典手法：域名解析到 169.254.169.254）。
	switch host {
	case "metadata.google.internal", "metadata", "instance-data", "metadata.goog":
		return fmt.Errorf("endpoint 指向云元数据主机名，已拒绝")
	}
	return nil
}

// deviceReq 设备增改请求体。Capabilities 以数组传入，落库前序列化。
type deviceReq struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Vendor       string   `json:"vendor"`
	Endpoint     string   `json:"endpoint"`
	Username     string   `json:"username"`
	Token        string   `json:"token"`
	Capabilities []string `json:"capabilities"`
}

// loadDeviceCaps 反序列化设备的 Capabilities，并派生 HasToken，供响应使用。
func loadDeviceCaps(d *model.Device) {
	d.Capabilities = db.UnmarshalStrings(d.CapabilitiesJSON)
	d.HasToken = d.Token != ""
}

// listDevices 列出全部改造设备（倒序）。
func (s *Server) listDevices(c *gin.Context) {
	var devices []model.Device
	if err := s.db.Order("created_at desc").Find(&devices).Error; err != nil {
		serverError(c, err)
		return
	}
	for i := range devices {
		loadDeviceCaps(&devices[i])
	}
	c.JSON(http.StatusOK, devices)
}

// createDevice 新建改造设备。
func (s *Server) createDevice(c *gin.Context) {
	var req deviceReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name 必填"})
		return
	}
	if err := validateEndpoint(req.Endpoint); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	dev := model.Device{
		Name:             req.Name,
		Type:             req.Type,
		Vendor:           req.Vendor,
		Endpoint:         req.Endpoint,
		Username:         req.Username,
		Token:            s.encToken(req.Token), // 凭据静态加密
		CapabilitiesJSON: db.MarshalStrings(req.Capabilities),
		Status:           model.DeviceStatusUnknown,
	}
	if err := s.db.Create(&dev).Error; err != nil {
		serverError(c, err)
		return
	}
	loadDeviceCaps(&dev)
	s.audit(c, "device", "device.create", auditTarget("Device", dev.ID, dev.Name), model.AuditSuccess, "类型="+dev.Type)
	c.JSON(http.StatusCreated, dev)
}

// updateDevice 全量更新设备（保留主键、创建时间与最近探测结果）。
func (s *Server) updateDevice(c *gin.Context) {
	var dev model.Device
	if err := s.db.First(&dev, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "设备不存在"})
		return
	}
	var req deviceReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateEndpoint(req.Endpoint); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name != "" {
		dev.Name = req.Name
	}
	dev.Type = req.Type
	dev.Vendor = req.Vendor
	dev.Endpoint = req.Endpoint
	dev.Username = req.Username
	if req.Token != "" {
		dev.Token = s.encToken(req.Token) // 凭据静态加密
	}
	if req.Capabilities != nil {
		dev.CapabilitiesJSON = db.MarshalStrings(req.Capabilities)
	}
	if err := s.db.Save(&dev).Error; err != nil {
		serverError(c, err)
		return
	}
	loadDeviceCaps(&dev)
	s.audit(c, "device", "device.update", auditTarget("Device", dev.ID, dev.Name), model.AuditSuccess, "")
	c.JSON(http.StatusOK, dev)
}

// deleteDevice 删除设备。
func (s *Server) deleteDevice(c *gin.Context) {
	var dev model.Device
	if err := s.db.First(&dev, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "设备不存在"})
		return
	}
	if err := s.db.Delete(&model.Device{}, dev.ID).Error; err != nil {
		serverError(c, err)
		return
	}
	s.audit(c, "device", "device.delete", auditTarget("Device", dev.ID, dev.Name), model.AuditSuccess, "")
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// testDevice 对设备 endpoint 做真实连通性探测，落库并返回 {status,latencyMs,detail}。
// 离线是正常结果而非错误：返回 200 + status=offline，绝不 500。
func (s *Server) testDevice(c *gin.Context) {
	var dev model.Device
	if err := s.db.First(&dev, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "设备不存在"})
		return
	}

	dev.Capabilities = db.UnmarshalStrings(dev.CapabilitiesJSON)
	token := s.decToken(dev.Token)
	// 按设备类型只读发现（hsm→健康+公钥盘点，sign-server→服务器证书，其余→通用连通性探测）。
	res := remediate.DiscoverDevice(context.Background(), &dev, token)

	now := time.Now()
	dev.LatencyMs = res.LatencyMs
	dev.LastCheckAt = &now
	if res.Online {
		dev.Status = model.DeviceStatusOnline
	} else {
		dev.Status = model.DeviceStatusOffline
	}
	// 只读发现到的算法能力并入 Capabilities（去重，保留用户配置的 keyslot:N）。
	if len(res.Algorithms) > 0 {
		dev.Capabilities = remediate.MergeCaps(dev.Capabilities, res.Algorithms)
		dev.CapabilitiesJSON = db.MarshalStrings(dev.Capabilities)
	}
	s.db.Save(&dev)

	// ②建档：把只读发现到的公钥/证书登记成 CBOM 资产（幂等），喂给评估/大屏真实数据流。
	registered := 0
	if len(res.Assets) > 0 {
		registered = s.registerDiscoveredAssets(&dev, res)
	}

	s.audit(c, "device", "device.test", auditTarget("Device", dev.ID, dev.Name), model.AuditSuccess, dev.Status+" "+res.Detail)
	c.JSON(http.StatusOK, gin.H{
		"status":         dev.Status,
		"latencyMs":      dev.LatencyMs,
		"detail":         res.Detail,
		"algorithms":     res.Algorithms,
		"assets":         len(res.Assets),
		"assetsNew":      registered,
		"assetsRegistered": len(res.Assets),
	})
}
