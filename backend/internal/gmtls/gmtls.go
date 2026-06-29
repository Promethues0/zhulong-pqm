// Package gmtls 为烛龙 PQM 管理面提供 国密 TLS（TLCP / GB-T 38636），
// 纯 Go 实现（gotlcp + gmsm），无 CGO，随处可跑。
//
// TLCP 需要 *双* SM2 证书：一张签名证书、一张加密证书。
// 本包在首次运行时自动生成自签名 SM2 双证（用于开发），
// 并以 TLCP 协议（SM2/SM3/SM4 套件）对外提供 API。
//
// 生产环境：把 CA 签发的 SM2 签名/加密证书放入证书目录，
// 或用 Tongsuo nginx TLCP 终结器前置（明文）后端。
package gmtls

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// Listener 返回一个说 TLCP 协议的 net.Listener，证书缺失时在 dir 中自动生成 SM2 双证。
func Listener(addr, dir string) (net.Listener, error) {
	sign, enc, err := ensureDualCert(dir)
	if err != nil {
		return nil, err
	}
	cfg := &tlcp.Config{
		Certificates: []tlcp.Certificate{sign, enc}, // [0]=签名证书 [1]=加密证书
		Time:         time.Now,
	}
	return tlcp.Listen("tcp", addr, cfg)
}

// ensureDualCert 从 dir 加载（或创建）SM2 签名 + 加密证书。
func ensureDualCert(dir string) (sign, enc tlcp.Certificate, err error) {
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	paths := map[string]string{
		"sign.crt": filepath.Join(dir, "sm2_sign.crt"),
		"sign.key": filepath.Join(dir, "sm2_sign.key"),
		"enc.crt":  filepath.Join(dir, "sm2_enc.crt"),
		"enc.key":  filepath.Join(dir, "sm2_enc.key"),
	}
	if !exists(paths["sign.crt"]) {
		if err = genCert(paths["sign.crt"], paths["sign.key"], "烛龙 PQM Mgmt Sign",
			x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true); err != nil {
			return
		}
	}
	if !exists(paths["enc.crt"]) {
		if err = genCert(paths["enc.crt"], paths["enc.key"], "烛龙 PQM Mgmt Enc",
			x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment|x509.KeyUsageKeyAgreement, false); err != nil {
			return
		}
	}
	if sign, err = tlcp.LoadX509KeyPair(paths["sign.crt"], paths["sign.key"]); err != nil {
		return
	}
	enc, err = tlcp.LoadX509KeyPair(paths["enc.crt"], paths["enc.key"])
	return
}

// genCert 把一张自签名 SM2 证书 + PKCS#8 私钥写入磁盘。
func genCert(certPath, keyPath, cn string, usage x509.KeyUsage, isCA bool) error {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"烛龙"}, Country: []string{"CN"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              usage,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := smx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := smx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	return writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600)
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	return os.WriteFile(path, b, mode)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func describe(dir string) string {
	return fmt.Sprintf("SM2 双证书目录 %s（sm2_sign.* 签名 / sm2_enc.* 加密）", dir)
}

// Describe 返回用于日志的人类可读字符串。
func Describe(dir string) string { return describe(dir) }
