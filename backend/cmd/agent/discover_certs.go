package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/model"
)

// certFileExt 磁盘证书候选扩展名（大小写不敏感）。
var certFileExt = map[string]bool{".pem": true, ".crt": true, ".cer": true, ".cert": true}

// maxCertBundleBlocks 单文件里 CERTIFICATE PEM 块数超过此阈值视为 CA 信任库/证书链
// bundle（不是某服务自己的叶证书），跳过——避免把系统 CA 包当资产入库刷屏。
const maxCertBundleBlocks = 3

// maxCertWalkDepth 单个 root 下递归扫描的最大目录深度（相对 root）。
const maxCertWalkDepth = 4

// discoverDiskCerts 遍历给定目录（roots 由调用方结合 fsRoot 解析好，含常见证书目录的
// glob 展开），找 *.pem/*.crt/*.cer/*.cert 并用 crypto/x509 解析叶证书，产出资产。
// 只读——不修改/不删除任何文件。
func discoverDiskCerts(roots []string) []model.CryptoAsset {
	var out []model.CryptoAsset
	seenFile := map[string]bool{}
	for _, root := range roots {
		root = filepath.Clean(root)
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // 跳过不可读项，不中断整体扫描
			}
			if d.IsDir() {
				rel, _ := filepath.Rel(root, path)
				if rel != "." && strings.Count(rel, string(filepath.Separator))+1 > maxCertWalkDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if !certFileExt[strings.ToLower(filepath.Ext(path))] {
				return nil
			}
			if seenFile[path] {
				return nil
			}
			seenFile[path] = true
			if a, ok := parseCertFile(path); ok {
				out = append(out, a)
			}
			return nil
		})
	}
	return out
}

// parseCertFile 解析单个证书文件（可能含多个 PEM 块），选叶证书产出一条资产。
// 文件不含证书、或疑似 CA 信任库 bundle（块数超阈值）时返回 ok=false。
func parseCertFile(path string) (model.CryptoAsset, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return model.CryptoAsset{}, false
	}
	var certs []*x509.Certificate
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue // 解析失败（如未被 stdlib 支持的曲线/算法）静默跳过
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 || len(certs) > maxCertBundleBlocks {
		return model.CryptoAsset{}, false
	}
	leaf := certs[0]
	for _, c := range certs {
		if !c.IsCA {
			leaf = c
			break
		}
	}
	algo, keySize := certPublicKeyInfo(leaf)
	name := leaf.Subject.CommonName
	if name == "" {
		name = filepath.Base(path)
	}
	notAfter := leaf.NotAfter
	return model.CryptoAsset{
		Name:            name,
		Algorithm:       algo,
		KeySize:         keySize,
		CertFingerprint: certFingerprint(leaf),
		CertNotAfter:    &notAfter,
		Layer:           model.LayerL2,
		Exposure:        model.ExposureInternal,
		AuthSafety:      cryptoref.AuthSafetyForAlgo(algo),
		RiskHint:        "磁盘证书文件 " + path,
	}, true
}

// certFingerprint 证书 DER 编码的 SHA-256 hex 指纹（去重锚点之一）。
func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// certPublicKeyInfo 由证书公钥类型判算法名与位数（RSA 比特数取模数位长，
// ECDSA 取曲线位宽，Ed25519 固定 256）。供磁盘证书与本地 TLS 握手共用。
func certPublicKeyInfo(cert *x509.Certificate) (algo string, keySize int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
			return "RSA", 0
		case x509.ECDSA:
			return "ECDSA", 0
		case x509.Ed25519:
			return "Ed25519", 256
		default:
			return "unknown", 0
		}
	}
}
