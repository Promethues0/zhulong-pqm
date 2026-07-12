package scan

import "testing"

func TestBuildPQCClientHello(t *testing.T) {
	ch := buildPQCClientHello("example.com", []int{0x11EC, 0x11EE})
	// 记录层：type=0x16 handshake, version=0x0301, len(2)
	if len(ch) < 9 || ch[0] != 0x16 || ch[1] != 0x03 {
		t.Fatalf("bad record header: % X", ch[:9])
	}
	recLen := int(ch[3])<<8 | int(ch[4])
	if recLen != len(ch)-5 {
		t.Errorf("record len %d != body %d", recLen, len(ch)-5)
	}
	// 握手消息：type=0x01 ClientHello
	if ch[5] != 0x01 {
		t.Errorf("handshake type = 0x%02X, want 0x01 ClientHello", ch[5])
	}
	// supported_groups 应包含 0x11EC 与 0x11EE（原始字节里能找到这两个大端码点）
	if !containsBE16(ch, 0x11EC) || !containsBE16(ch, 0x11EE) {
		t.Error("ClientHello missing target groups in supported_groups")
	}
}

func containsBE16(b []byte, v int) bool {
	hi, lo := byte(v>>8), byte(v)
	for i := 0; i+1 < len(b); i++ {
		if b[i] == hi && b[i+1] == lo {
			return true
		}
	}
	return false
}
