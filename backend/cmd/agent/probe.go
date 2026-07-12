package main

import (
	"fmt"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/model"
	"zhulong-pqm/internal/scan"
)

// observationsToAssets 把探针解析出的 TLS 观测转成待上报的 CryptoAsset。
// KexGroup/KexSafety 由 ParsePCAP（M-A 引擎）填好直接带上；AuthSafety 由证书算法推导；
// 五维评分与 HNDL 由后端 upsertAgentAsset 补。网络端点按 host:port 走后端原生去重。
func observationsToAssets(obs []scan.TLSObservation) []model.CryptoAsset {
	out := make([]model.CryptoAsset, 0, len(obs))
	for _, o := range obs {
		name := o.Subject
		if name == "" {
			name = o.SNI
		}
		if name == "" {
			name = fmt.Sprintf("%s:%d", o.Host, o.Port)
		}
		out = append(out, model.CryptoAsset{
			Name:            name,
			Endpoint:        fmt.Sprintf("%s:%d", o.Host, o.Port),
			Algorithm:       o.Algo,
			KeySize:         o.KeySize,
			Protocol:        o.Version,
			CertFingerprint: o.CertFP,
			KexGroup:        o.KexGroup,
			KexSafety:       o.KexSafety,
			AuthSafety:      cryptoref.AuthSafetyForAlgo(o.Algo),
			Layer:           model.LayerL1,
			Exposure:        model.ExposureInternal,
			RiskHint:        "探针抓包边缘解析",
		})
	}
	return out
}

// assetsFromPcap 解析 pcap 字节流为待上报资产（复用 M-A 的 scan.ParsePCAP）。
func assetsFromPcap(pcapBytes []byte) ([]model.CryptoAsset, scan.PcapStats, error) {
	obs, stats, err := scan.ParsePCAP(pcapBytes)
	if err != nil {
		return nil, stats, err
	}
	return observationsToAssets(obs), stats, nil
}

// runProbe 探针主流程：抓包 → 边缘解析 → 上报（只回传观测，不回传原始包）。
func runProbe(cfg Config) error {
	pcapBytes, err := Capture(&cfg)
	if err != nil {
		return err
	}
	assets, stats, err := assetsFromPcap(pcapBytes)
	if err != nil {
		return fmt.Errorf("解析抓包失败: %v", err)
	}
	fmt.Printf("探针抓包：%s / %d 包 / %d 流 / %d 握手 → %d 观测\n",
		stats.Format, stats.Packets, stats.Flows, stats.Handshakes, len(assets))
	return reportAssets(cfg, assets)
}
