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
}
