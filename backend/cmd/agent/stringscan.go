package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxSoScanBytes 单个 .so 文件版本串扫描的读取上限，避免大文件拖慢发现流程
// （libssl/libcrypto 之类一般数 MB，覆盖首 16MB 足以命中版本串常量区）。
const maxSoScanBytes = 16 * 1024 * 1024

// minPrintableRun 可打印 ASCII 连续段的最小长度阈值（版本串如 "OpenSSL 3.5.0" 显然更长）。
const minPrintableRun = 6

// isPrintableASCII 判断字节是否落在可打印 ASCII 区间（含空格，不含控制字符）。
func isPrintableASCII(b byte) bool {
	return b >= 0x20 && b <= 0x7e
}

// extractPrintableStrings 纯 Go 版「strings」：从字节流里抽取所有长度 >= minPrintableRun
// 的连续可打印 ASCII 段，换行拼接返回，供 cryptoref.RefineByVersionString 做版本串消歧。
// 不 shell 调用系统 strings 命令。
func extractPrintableStrings(data []byte) string {
	var out strings.Builder
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= minPrintableRun {
			if out.Len() > 0 {
				out.WriteByte('\n')
			}
			out.Write(data[start:end])
		}
		start = -1
	}
	for i, b := range data {
		if isPrintableASCII(b) {
			if start < 0 {
				start = i
			}
		} else {
			flush(i)
		}
	}
	flush(len(data))
	return out.String()
}

// readVersionText 读取 fsRoot 下 soPath 指向的 .so 文件（soPath 可为绝对路径，
// 与 /proc/<pid>/maps 里读到的一致；filepath.Join 对 "/" fsRoot 幂等，见调用侧注释），
// 抽出可打印字符串文本用于版本消歧。文件不存在/不可读时返回空串（调用方按无法消歧处理）。
func readVersionText(fsRoot, soPath string) string {
	full := filepath.Join(fsRoot, soPath)
	f, err := os.Open(full)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, maxSoScanBytes)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return ""
	}
	return extractPrintableStrings(buf[:n])
}
