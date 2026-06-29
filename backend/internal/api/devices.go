package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/remediate"
)

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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
	dev := model.Device{
		Name:             req.Name,
		Type:             req.Type,
		Vendor:           req.Vendor,
		Endpoint:         req.Endpoint,
		Username:         req.Username,
		Token:            req.Token,
		CapabilitiesJSON: db.MarshalStrings(req.Capabilities),
		Status:           model.DeviceStatusUnknown,
	}
	if err := s.db.Create(&dev).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
	if req.Name != "" {
		dev.Name = req.Name
	}
	dev.Type = req.Type
	dev.Vendor = req.Vendor
	dev.Endpoint = req.Endpoint
	dev.Username = req.Username
	if req.Token != "" {
		dev.Token = req.Token
	}
	if req.Capabilities != nil {
		dev.CapabilitiesJSON = db.MarshalStrings(req.Capabilities)
	}
	if err := s.db.Save(&dev).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

	res := remediate.Probe(context.Background(), dev.Endpoint)

	now := time.Now()
	dev.LatencyMs = res.LatencyMs
	dev.LastCheckAt = &now
	if res.Online {
		dev.Status = model.DeviceStatusOnline
	} else {
		dev.Status = model.DeviceStatusOffline
	}
	s.db.Save(&dev)

	s.audit(c, "device", "device.test", auditTarget("Device", dev.ID, dev.Name), model.AuditSuccess, dev.Status+" "+res.Detail)
	c.JSON(http.StatusOK, gin.H{
		"status":    dev.Status,
		"latencyMs": dev.LatencyMs,
		"detail":    res.Detail,
	})
}
