package cryptoref

import "testing"

func TestLookupLib_Unambiguous(t *testing.T) {
	cases := []struct {
		path       string
		library    string
		pqcCapable bool
		isGM       bool
	}{
		{"/usr/lib/libhitls_crypto.so", "openHiTLS", true, true},
		{"/opt/pqmagic/lib/libpqmagic_std.so", "PQMagic", true, true},
		{"/usr/lib/x86_64-linux-gnu/liboqs.so.7", "liboqs", true, false},
		{"/usr/lib/libsymcrypt.so.103", "SymCrypt (微软)", true, false},
		{"/usr/local/lib/libgnutls.so.30", "GnuTLS", false, false},
	}
	for _, c := range cases {
		got, ok := LookupLib(c.path)
		if !ok {
			t.Errorf("%s: not found", c.path)
			continue
		}
		if got.Library != c.library || got.PQCCapable != c.pqcCapable || got.IsGM != c.isGM {
			t.Errorf("%s = (%q, pqc=%v, gm=%v), want (%q,%v,%v)",
				c.path, got.Library, got.PQCCapable, got.IsGM, c.library, c.pqcCapable, c.isGM)
		}
	}
}

func TestLookupLib_AmbiguousSonames(t *testing.T) {
	// libcrypto.so.3 = OpenSSL 或铜锁 → Ambiguous, 未消歧前 PQCCapable=false（保守）。
	got, ok := LookupLib("/usr/lib/libcrypto.so.3")
	if !ok || !got.Ambiguous || got.PQCCapable {
		t.Errorf("libcrypto.so.3 = %+v, want Ambiguous且未定 PQC", got)
	}
	// 无版本后缀的 libcrypto.so → 疑似 BoringSSL, Ambiguous。
	b, ok := LookupLib("/system/lib64/libcrypto.so")
	if !ok || !b.Ambiguous {
		t.Errorf("libcrypto.so = %+v, want Ambiguous", b)
	}
}

func TestRefineByVersionString(t *testing.T) {
	amb, _ := LookupLib("/usr/lib/libcrypto.so.3")

	// OpenSSL 3.5 → PQC 是
	o := RefineByVersionString(amb, "OpenSSL 3.5.0 8 Apr 2025")
	if o.Ambiguous || !o.PQCCapable || o.Library != "OpenSSL 3.5.0" {
		t.Errorf("OpenSSL 3.5 refine = %+v, want 定库+PQC", o)
	}
	// OpenSSL 3.0 → PQC 否
	o30 := RefineByVersionString(amb, "OpenSSL 3.0.13 30 Jan 2024")
	if o30.PQCCapable {
		t.Errorf("OpenSSL 3.0 应无原生 PQC, got %+v", o30)
	}
	// 铜锁 → 国密+PQC
	ts := RefineByVersionString(amb, "Tongsuo 8.5.0 SMTC provider")
	if ts.Ambiguous || !ts.PQCCapable || !ts.IsGM {
		t.Errorf("Tongsuo 8.5 refine = %+v, want 铜锁+国密+PQC", ts)
	}
	ts84 := RefineByVersionString(amb, "Tongsuo 8.4.0")
	if ts84.PQCCapable {
		t.Errorf("Tongsuo 8.4 应无 PQC, got %+v", ts84)
	}
	// 非歧义库原样返回
	hitls, _ := LookupLib("libhitls_crypto.so")
	if RefineByVersionString(hitls, "anything").Library != hitls.Library {
		t.Error("非歧义库不应被 refine 改动")
	}
}

func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		v          string
		maj, mi, pa int
		want       bool
	}{
		{"3.5.0", 3, 5, 0, true},
		{"3.5.4", 3, 5, 0, true},
		{"3.4.9", 3, 5, 0, false},
		{"3.0.13", 3, 5, 0, false},
		{"8.5.0", 8, 5, 0, true},
		{"8.4.0", 8, 5, 0, false},
		{"4.0.0", 3, 5, 0, true},
		{"garbage", 3, 5, 0, false},
	}
	for _, c := range cases {
		if got := versionAtLeast(c.v, c.maj, c.mi, c.pa); got != c.want {
			t.Errorf("versionAtLeast(%q,%d,%d,%d) = %v, want %v", c.v, c.maj, c.mi, c.pa, got, c.want)
		}
	}
}
