package main

import (
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/model"
)

// discoverSSHHostKeys 解析 sshDir（默认 /etc/ssh）下 *_key.pub，取算法与位数产出资产。
// 远程 Agentless 扫描拿不到主机密钥类型/位数（那是本地文件，不在网络协议里），
// 这是主机 Agent 相对 Agentless 扫描的独有价值之一。跨平台可跑（纯文件读取，无 /proc 依赖）。
func discoverSSHHostKeys(sshDir string) []model.CryptoAsset {
	matches, err := filepath.Glob(filepath.Join(sshDir, "*_key.pub"))
	if err != nil {
		return nil
	}
	var out []model.CryptoAsset
	for _, path := range matches {
		asset, ok := parseSSHPubKeyFile(path)
		if !ok {
			continue
		}
		out = append(out, asset)
	}
	return out
}

// parseSSHPubKeyFile 解析单个 SSH 公钥文件："<algo-id> <base64 blob> [comment]"。
func parseSSHPubKeyFile(path string) (model.CryptoAsset, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return model.CryptoAsset{}, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return model.CryptoAsset{}, false
	}
	algoID := fields[0]
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return model.CryptoAsset{}, false
	}

	keySize := 0
	switch {
	case algoID == "ssh-rsa":
		keySize = sshRSABits(blob)
	case algoID == "ssh-ed25519":
		keySize = 256
	case strings.HasPrefix(algoID, "ecdsa-sha2-nistp"):
		switch {
		case strings.HasSuffix(algoID, "nistp256"):
			keySize = 256
		case strings.HasSuffix(algoID, "nistp384"):
			keySize = 384
		case strings.HasSuffix(algoID, "nistp521"):
			keySize = 521
		}
	}

	return model.CryptoAsset{
		Name:       "SSH 主机密钥 " + algoID,
		Algorithm:  algoID,
		KeySize:    keySize,
		Protocol:   "SSH",
		Layer:      model.LayerL2,
		Exposure:   model.ExposureInternal,
		AuthSafety: cryptoref.AuthSafetyForAlgo(algoID),
		RiskHint:   "SSH 主机密钥文件 " + path,
	}, true
}

// sshReadLenPrefixed 从 SSH 二进制格式的字节流里读一个 4 字节大端长度前缀的字段，
// 返回该字段内容与剩余字节。
func sshReadLenPrefixed(b []byte) (field, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	l := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if uint64(len(b)) < uint64(l) {
		return nil, nil, false
	}
	return b[:l], b[l:], true
}

// sshRSABits 解析 SSH wire 格式的 ssh-rsa 公钥 blob（算法名 + mpint e + mpint n），
// 返回模数 n 的位长（即 RSA 密钥位数）。纯 stdlib（encoding/binary + math/big），
// 不依赖 golang.org/x/crypto/ssh。
func sshRSABits(blob []byte) int {
	rest := blob
	var ok bool
	if _, rest, ok = sshReadLenPrefixed(rest); !ok { // 算法名 "ssh-rsa"
		return 0
	}
	if _, rest, ok = sshReadLenPrefixed(rest); !ok { // 公钥指数 e
		return 0
	}
	n, _, ok := sshReadLenPrefixed(rest) // 模数 n
	if !ok || len(n) == 0 {
		return 0
	}
	return new(big.Int).SetBytes(n).BitLen()
}
