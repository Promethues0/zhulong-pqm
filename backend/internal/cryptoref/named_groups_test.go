package cryptoref

import "testing"

func TestClassifyGroup_KnownCodepoints(t *testing.T) {
	cases := []struct {
		cp   int
		name string
		kind string
		iana bool
	}{
		{0x11EC, "X25519MLKEM768", "hybrid", true},
		{0x11EE, "curveSM2MLKEM768", "hybrid", true},
		{0x11EB, "SecP256r1MLKEM768", "hybrid", true},
		{0x0201, "MLKEM768", "pqc", true},
		{0x001D, "x25519", "classical", true},
		{0x0029, "curveSM2", "classical", true},
		{0x6399, "X25519Kyber768Draft00", "hybrid", true},
	}
	for _, c := range cases {
		name, kind, iana, known := ClassifyGroup(c.cp)
		if !known {
			t.Fatalf("0x%04X should be known", c.cp)
		}
		if name != c.name || kind != c.kind || iana != c.iana {
			t.Errorf("0x%04X = (%q,%q,%v), want (%q,%q,%v)", c.cp, name, kind, iana, c.name, c.kind, c.iana)
		}
	}
}

// TestClassifyGroup_ClassicalTLS13Groups FIX 6：标准经典 TLS1.3 组（RFC 7919 ffdhe /
// RFC 8734 brainpool-tls13）须在表内判 classical，不落 "unknown-" 兜底面。
func TestClassifyGroup_ClassicalTLS13Groups(t *testing.T) {
	name, kind, iana, known := ClassifyGroup(0x0100)
	if name != "ffdhe2048" || kind != "classical" || !iana || !known {
		t.Errorf("ClassifyGroup(0x0100) = (%q,%q,%v,%v), want (ffdhe2048,classical,true,true)",
			name, kind, iana, known)
	}
	if g, s := KexSafetyForGroup(0x0100, 0); g != "ffdhe2048" || s != SafetyClassical {
		t.Errorf("KexSafetyForGroup(0x0100,0) = (%q,%q), want (ffdhe2048,classical)", g, s)
	}
	for cp, want := range map[int]string{
		0x0101: "ffdhe3072", 0x0102: "ffdhe4096", 0x0103: "ffdhe6144", 0x0104: "ffdhe8192",
		0x001F: "brainpoolP256r1tls13", 0x0020: "brainpoolP384r1tls13", 0x0021: "brainpoolP512r1tls13",
	} {
		name, kind, _, known := ClassifyGroup(cp)
		if !known || name != want || kind != "classical" {
			t.Errorf("ClassifyGroup(0x%04X) = (%q,%q,known=%v), want (%q,classical,true)",
				cp, name, kind, known, want)
		}
	}
}

func TestIsGREASEGroup(t *testing.T) {
	for _, g := range []int{0x0A0A, 0x1A1A, 0x2A2A, 0xFAFA} {
		if !IsGREASEGroup(g) {
			t.Errorf("0x%04X should be GREASE", g)
		}
	}
	for _, ng := range []int{0x11EC, 0x001D, 0x0201} {
		if IsGREASEGroup(ng) {
			t.Errorf("0x%04X should NOT be GREASE", ng)
		}
	}
}

func TestKexSafetyForGroup(t *testing.T) {
	// 已知码点：直接取 kind→safety
	if g, s := KexSafetyForGroup(0x11EE, 1249); g != "curveSM2MLKEM768" || s != SafetyHybrid {
		t.Errorf("0x11EE = (%q,%q), want (curveSM2MLKEM768,hybrid)", g, s)
	}
	if g, s := KexSafetyForGroup(0x0201, 1184); g != "MLKEM768" || s != SafetySafe {
		t.Errorf("0x0201 = (%q,%q), want (MLKEM768,safe)", g, s)
	}
	if _, s := KexSafetyForGroup(0x001D, 32); s != SafetyClassical {
		t.Errorf("0x001D safety = %q, want classical", s)
	}
	// GREASE：噪声
	if g, s := KexSafetyForGroup(0x1A1A, 1); g != "" || s != "" {
		t.Errorf("GREASE = (%q,%q), want empty", g, s)
	}
	// 未知码点 + 大 key_share → 尺寸兜底 hybrid（保守判含 PQC）
	if _, s := KexSafetyForGroup(0x9ABC, 1249); s != SafetyHybrid {
		t.Errorf("unknown big = %q, want hybrid", s)
	}
	// 未知码点 + 小 key_share → classical
	if _, s := KexSafetyForGroup(0x9ABC, 65); s != SafetyClassical {
		t.Errorf("unknown small = %q, want classical", s)
	}
}

func TestSafetyForGroupName(t *testing.T) {
	if s := SafetyForGroupName("X25519MLKEM768"); s != SafetyHybrid {
		t.Errorf("X25519MLKEM768 = %q, want hybrid", s)
	}
	if s := SafetyForGroupName("MLKEM768"); s != SafetySafe {
		t.Errorf("MLKEM768 = %q, want safe", s)
	}
	if s := SafetyForGroupName("x25519"); s != SafetyClassical {
		t.Errorf("x25519 = %q, want classical", s)
	}
	if s := SafetyForGroupName(""); s != SafetyNA {
		t.Errorf("empty = %q, want na", s)
	}
	if s := SafetyForGroupName("unknown-0x9ABC"); s != SafetyHybrid {
		t.Errorf("unknown- prefix = %q, want hybrid(保守)", s)
	}
	// 大小写不敏感：MatchRules 会把 cipher 整体 ToUpper 后传入，需仍能命中规范名。
	if s := SafetyForGroupName("CURVESM2MLKEM768"); s != SafetyHybrid {
		t.Errorf("CURVESM2MLKEM768(大写) = %q, want hybrid", s)
	}
	if s := SafetyForGroupName("x25519mlkem768"); s != SafetyHybrid {
		t.Errorf("x25519mlkem768(小写) = %q, want hybrid", s)
	}
	if s := SafetyForGroupName("UNKNOWN-0x9ABC"); s != SafetyHybrid {
		t.Errorf("UNKNOWN- prefix(大写) = %q, want hybrid(保守)", s)
	}
}

func TestPQCGroupCodepoints(t *testing.T) {
	got := PQCGroupCodepoints()

	// 必须精确等于这份白名单（顺序敏感：主流/国密靠前决定选主组优先序）
	want := []int{
		0x11EC, // X25519MLKEM768（互联网主流 Rec=Y）
		0x11EE, // curveSM2MLKEM768（国密 铜锁 Tongsuo 8.5+）
		0x11EB, // SecP256r1MLKEM768
		0x11ED, // SecP384r1MLKEM1024
		0x6399, // X25519Kyber768Draft00
		0x0200, // MLKEM512
		0x0201, // MLKEM768
		0x0202, // MLKEM1024
	}
	if len(got) != len(want) {
		t.Fatalf("PQCGroupCodepoints len = %d, want %d: %#x", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("PQCGroupCodepoints[%d] = 0x%04X, want 0x%04X", i, got[i], want[i])
		}
	}

	// 反向不变量：不得含仅作时间指纹的 0xFEFE、任一 GREASE、任一经典组
	for _, cp := range got {
		if cp == 0xFEFE {
			t.Error("白名单不得含 0xFEFE(draft-02 时间指纹，非真实可协商)")
		}
		if IsGREASEGroup(cp) {
			t.Errorf("白名单不得含 GREASE 组 0x%04X", cp)
		}
		if _, kind, _, known := ClassifyGroup(cp); !known || (kind != "pqc" && kind != "hybrid") {
			t.Errorf("0x%04X kind=%q known=%v，白名单只应含真实 pqc/hybrid 组", cp, kind, known)
		}
	}
}
