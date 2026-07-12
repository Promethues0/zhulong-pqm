package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/model"
)

// maxKernelCryptoAssets 内核 /proc/crypto 去重后最多产出的资产数（"少量" 记录，避免刷屏——
// 一台典型 Linux 主机 /proc/crypto 里同一 name 常有十几个 driver 变体，只留一条代表）。
const maxKernelCryptoAssets = 60

// discoverOSCrypto 内核算法（/proc/crypto）与操作系统密码库包清单（dpkg/rpm）两路轻量发现，
// 均产出 Layer=L4 资产。非 Linux（无 /proc/crypto、无 dpkg/rpm）静默跳过对应部分。
func discoverOSCrypto(fsRoot string) []model.CryptoAsset {
	var out []model.CryptoAsset
	out = append(out, discoverKernelCrypto(fsRoot)...)
	out = append(out, discoverPackages(fsRoot)...)
	return out
}

// discoverKernelCrypto 读 {fsRoot}/proc/crypto（块状 "key : value"，空行分块），
// 按 name 去重抽取内核已注册的密码算法实现。
func discoverKernelCrypto(fsRoot string) []model.CryptoAsset {
	path := filepath.Join(fsRoot, "proc", "crypto")
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []model.CryptoAsset
	var name, driver string
	flush := func() {
		defer func() { name, driver = "", "" }()
		if name == "" || seen[name] || len(out) >= maxKernelCryptoAssets {
			return
		}
		seen[name] = true
		out = append(out, model.CryptoAsset{
			Name:       "内核密码算法 " + name,
			Algorithm:  name,
			Layer:      model.LayerL4,
			Exposure:   model.ExposureInternal,
			AuthSafety: cryptoref.AuthSafetyForAlgo(name),
			RiskHint:   "Linux crypto API driver=" + driver,
		})
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			flush()
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.TrimSpace(kv[0]) {
		case "name":
			name = strings.TrimSpace(kv[1])
		case "driver":
			driver = strings.TrimSpace(kv[1])
		}
	}
	flush()
	return out
}

// pkgCryptoPattern 从包名初筛「可能是密码库」的候选（前缀匹配，命中后交 LookupLib 定库）。
var pkgCryptoPattern = regexp.MustCompile(`(?i)^(openssl|libssl|libcrypto|libgnutls|libgcrypt|libnss3|libnspr4|libsoftokn|libmbedtls|libmbedcrypto|libwolfssl|libhitls|libpqmagic|liboqs|oqs-provider|libgmssl|libsymcrypt|tongsuo)`)

// discoverPackages 操作系统包清单里的密码库：dpkg 状态文件纯 Go 解析（可测），
// rpm 系经 exec.Command("rpm","-qa")（允许 shell rpm 命令本身，保二进制纯 Go/免 CGO；
// 本机无 rpm 时用 exec.LookPath 探测后跳过，不报错）。
func discoverPackages(fsRoot string) []model.CryptoAsset {
	var out []model.CryptoAsset
	out = append(out, discoverDpkgPackages(fsRoot)...)
	out = append(out, discoverRPMPackages()...)
	return out
}

// dpkgPkg 一条 dpkg status 记录关心的字段。
type dpkgPkg struct{ name, version string }

// parseDpkgStatus 纯 Go 解析 dpkg status 文件（stanza 用空行分隔，形如 "Key: value"，
// 折行的多行字段以空白开头需跳过，不当新键）。
func parseDpkgStatus(path string) []dpkgPkg {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []dpkgPkg
	var cur dpkgPkg
	flush := func() {
		if cur.name != "" {
			out = append(out, cur)
		}
		cur = dpkgPkg{}
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue // 折行内容（如 Description 续行），非新字段
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.TrimSpace(kv[0]) {
		case "Package":
			cur.name = strings.TrimSpace(kv[1])
		case "Version":
			cur.version = strings.TrimSpace(kv[1])
		}
	}
	flush()
	return out
}

// discoverDpkgPackages fsRoot 注入版本，供测试用 fixture 目录。
func discoverDpkgPackages(fsRoot string) []model.CryptoAsset {
	pkgs := parseDpkgStatus(filepath.Join(fsRoot, "var", "lib", "dpkg", "status"))
	var out []model.CryptoAsset
	for _, p := range pkgs {
		if !pkgCryptoPattern.MatchString(p.name) {
			continue
		}
		if a, ok := packageCryptoAsset(p.name, p.version, "dpkg"); ok {
			out = append(out, a)
		}
	}
	return out
}

// discoverRPMPackages rpm 系包清单（无 fsRoot 注入——rpm 数据库是系统态，用 exec 询问；
// 本机无 rpm 时静默跳过，不影响其余发现模块与测试）。
func discoverRPMPackages() []model.CryptoAsset {
	if _, err := exec.LookPath("rpm"); err != nil {
		return nil
	}
	cmd := exec.Command("rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n")
	data, err := cmd.Output()
	if err != nil {
		return nil
	}
	var out []model.CryptoAsset
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !pkgCryptoPattern.MatchString(fields[0]) {
			continue
		}
		if a, ok := packageCryptoAsset(fields[0], fields[1], "rpm"); ok {
			out = append(out, a)
		}
	}
	return out
}

// packageCryptoAsset 由包名+版本判库画像并产出资产。包名直接命中 cryptoref.LookupLib
// 规则的（gnutls/gcrypt/nss/mbedtls/wolfssl/openHiTLS/PQMagic/liboqs/GmSSL/SymCrypt 等，
// 这些库的 Debian/RPM 包名本身就含 soname 关键片段）直接用；openssl/libssl* 系包名不含
// ".so" 片段、命中不了那条歧义规则本体，借用同一条规则做基底（同为 OpenSSL/铜锁歧义），
// 再用 "OpenSSL <version>" 拼出的文本喂 RefineByVersionString 按版本号判 PQC 能力。
func packageCryptoAsset(name, version, pkgMgr string) (model.CryptoAsset, bool) {
	info, ok := cryptoref.LookupLib(name)
	opensslFallback := false
	if !ok {
		lname := strings.ToLower(name)
		if strings.Contains(lname, "openssl") || strings.HasPrefix(lname, "libssl") || strings.HasPrefix(lname, "libcrypto") {
			info, ok = cryptoref.LookupLib("libssl.so.3")
			opensslFallback = true
		}
	}
	if !ok {
		return model.CryptoAsset{}, false
	}
	if info.Ambiguous {
		text := version
		if opensslFallback {
			text = "OpenSSL " + version + " " + text
		}
		info = cryptoref.RefineByVersionString(info, text)
	}
	authSafety := cryptoref.SafetyClassical
	if info.PQCCapable {
		authSafety = cryptoref.SafetyHybrid
	}
	return model.CryptoAsset{
		Name:       "已安装包 " + name,
		Algorithm:  info.Library + " " + version,
		Layer:      model.LayerL4,
		Exposure:   model.ExposureInternal,
		AuthSafety: authSafety,
		RiskHint:   fmt.Sprintf("%s 包 %s=%s；%s", pkgMgr, name, version, info.Note),
	}, true
}
