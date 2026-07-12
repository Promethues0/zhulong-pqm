package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"zhulong-pqm/internal/cryptoref"
	"zhulong-pqm/internal/model"
)

// reCryptoLib 匹配 /proc/<pid>/maps 里映射到的密码库 .so 路径（含常见 soname 变体）。
var reCryptoLib = regexp.MustCompile(`(?i)lib(ssl|crypto|gnutls|gcrypt|nss|hitls|pqmagic|oqs|gmssl|symcrypt)[^\s]*\.so[0-9.]*`)

// discoverProcessLibs 进程×加密库映射（核心发现模块）：遍历 {fsRoot}/proc/<pid>/maps，
// 抽出映射到的密码库 .so，经 cryptoref.LookupLib 判库与 PQC 能力；soname 有歧义时
// 读该 .so 文件的可打印字符串文本，交 cryptoref.RefineByVersionString 消歧。
//
// 锚点稳定性：产出的 Name 不含 pid（同一 comm 的多个 worker 进程会各自变化的 pid
// 若写进 Name，后端合成锚点每次上报都会变化→重复行）；pid 列表放进 RiskHint。
// 同一 comm+库 若被多个 pid 加载，本函数在返回前合并为一条，避免同批次内重复。
//
// fsRoot 不存在 {fsRoot}/proc（非 Linux 主机，或测试未注入 fixture）时返回 nil——
// 用目录存在性兜底，而非直接判 runtime.GOOS，这样测试可在 macOS 上用 fixture 目录跑通。
func discoverProcessLibs(fsRoot string) []model.CryptoAsset {
	procDir := filepath.Join(fsRoot, "proc")
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil
	}

	type procInfo struct {
		pid  string
		comm string
		libs []string
	}
	var procs []procInfo
	for _, e := range entries {
		if !e.IsDir() || !isAllDigits(e.Name()) {
			continue
		}
		pid := e.Name()
		libs := parseMapsLibs(filepath.Join(procDir, pid, "maps"))
		if len(libs) == 0 {
			continue
		}
		comm := readComm(filepath.Join(procDir, pid, "comm"))
		if comm == "" {
			comm = "pid" + pid
		}
		procs = append(procs, procInfo{pid: pid, comm: comm, libs: libs})
	}

	type key struct{ comm, lib string }
	order := []key{}
	assets := map[key]*model.CryptoAsset{}
	pidsOf := map[key][]string{}

	for _, p := range procs {
		for _, soPath := range p.libs {
			info, ok := cryptoref.LookupLib(soPath)
			if !ok {
				continue
			}
			originallyAmbiguous := info.Ambiguous
			disambiguated := false
			if info.Ambiguous {
				text := readVersionText(fsRoot, soPath)
				refined := cryptoref.RefineByVersionString(info, text)
				if !refined.Ambiguous {
					disambiguated = true
				}
				info = refined
			}

			k := key{comm: p.comm, lib: info.Library}
			pidsOf[k] = append(pidsOf[k], p.pid)
			if _, seen := assets[k]; seen {
				continue
			}
			order = append(order, k)

			authSafety := cryptoref.SafetyClassical
			if info.PQCCapable {
				authSafety = cryptoref.SafetyHybrid
			}

			var hint strings.Builder
			fmt.Fprintf(&hint, "so=%s", soPath)
			switch {
			case disambiguated:
				hint.WriteString("；已按版本串消歧")
			case originallyAmbiguous:
				hint.WriteString("；soname 有歧义、未读到消歧版本串，结论保守")
			}
			if info.SinceNote != "" {
				fmt.Fprintf(&hint, "；%s", info.SinceNote)
			}
			if info.IsGM {
				hint.WriteString("；国密系")
			}
			if info.Note != "" {
				fmt.Fprintf(&hint, "；%s", info.Note)
			}

			assets[k] = &model.CryptoAsset{
				Name:       fmt.Sprintf("进程 %s 加载 %s", p.comm, info.Library),
				Algorithm:  info.Library,
				Layer:      model.LayerL4,
				Exposure:   model.ExposureInternal,
				AuthSafety: authSafety,
				RiskHint:   hint.String(),
			}
		}
	}

	var out []model.CryptoAsset
	for _, k := range order {
		a := assets[k]
		pids := pidsOf[k]
		sort.Strings(pids)
		a.RiskHint = fmt.Sprintf("pid=%s；%s", strings.Join(pids, ","), a.RiskHint)
		out = append(out, *a)
	}
	return out
}

// parseMapsLibs 解析单个进程 /proc/<pid>/maps，去重返回其映射到的密码库 .so 路径。
func parseMapsLibs(mapsPath string) []string {
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue // 匿名映射，无 pathname
		}
		path := strings.Join(fields[5:], " ")
		if !reCryptoLib.MatchString(path) || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

// readComm 读取 /proc/<pid>/comm 得到进程名（去掉尾随换行）。
func readComm(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// isAllDigits 判断字符串是否全数字（用于从 /proc 目录项里筛出 pid 目录）。
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
