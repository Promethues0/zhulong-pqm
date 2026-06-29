package gmtls

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
)

// TestTLCPHandshake 用自动生成的 SM2 双证拉起 国密 TLCP 服务，
// 再用 TLCP 客户端连入——证明国密 TLS 通路可用。
func TestTLCPHandshake(t *testing.T) {
	dir := t.TempDir()
	ln, err := Listener("127.0.0.1:0", dir)
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"msg":"ok"}`))
	})
	go http.Serve(ln, mux)
	time.Sleep(50 * time.Millisecond)

	conn, err := tlcp.Dial("tcp", ln.Addr().String(), &tlcp.Config{InsecureSkipVerify: true, Time: time.Now})
	if err != nil {
		t.Fatalf("TLCP dial/handshake failed: %v", err)
	}
	defer conn.Close()

	_, _ = io.WriteString(conn, "GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n")
	r := bufio.NewReader(conn)
	status, _ := r.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("expected HTTP 200 over TLCP, got: %q", status)
	}
	body, _ := io.ReadAll(r)
	if !strings.Contains(string(body), `"ok"`) {
		t.Fatalf("unexpected body over TLCP: %q", body)
	}
	t.Logf("TLCP handshake OK, status=%s", strings.TrimSpace(status))
}
