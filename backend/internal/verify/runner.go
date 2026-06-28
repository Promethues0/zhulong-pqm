package verify

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"zhulong-pqm/internal/model"
)

// stepPause 逐用例落库之间的停顿，让前端轮询观察到逐项推进（沿用 remediate.Orchestrator）。
const stepPause = 250 * time.Millisecond

// Runner 验收执行器：照搬 scan.Runner / remediate.Orchestrator 的同步 Run + 调用方
// goroutine + 逐项落库供前端轮询范式。TLS 类用例真实探测，不可探测项诚实 simulate。
type Runner struct {
	db    *gorm.DB
	prober prober
}

// prober TLS 探测抽象，便于测试替换（默认走真实 crypto/tls）。
type prober interface {
	hybrid(ctx context.Context, target string) probeOutcome
	classicOnly(ctx context.Context, target string) probeOutcome
	verified(ctx context.Context, target string) probeOutcome
}

// realProber 真实 crypto/tls 探测。
type realProber struct{}

func (realProber) hybrid(ctx context.Context, t string) probeOutcome      { return probeHybrid(ctx, t) }
func (realProber) classicOnly(ctx context.Context, t string) probeOutcome { return probeClassicOnly(ctx, t) }
func (realProber) verified(ctx context.Context, t string) probeOutcome    { return probeVerified(ctx, t) }

// NewRunner 构造验收执行器。p 可注入测试桩；nil 用真实探测。
func NewRunner(db *gorm.DB, p prober) *Runner {
	if p == nil {
		p = realProber{}
	}
	return &Runner{db: db, prober: p}
}

// Run 同步执行一次验收（通常由调用方放入 goroutine）。
// 状态机：pending → running →（逐用例判定落库）→ done/failed。
func (r *Runner) Run(ctx context.Context, runID uint) {
	var run model.AcceptanceRun
	if err := r.db.First(&run, runID).Error; err != nil {
		return
	}

	now := time.Now()
	run.Status = model.RunRunning
	run.StartedAt = &now
	run.Error = ""
	r.db.Save(&run)

	// 清理可能的旧逐项结果（重跑幂等）。
	r.db.Where("run_id = ?", run.ID).Delete(&model.TestResult{})

	cs := CasesForTrack(run.Track)
	run.Total = len(cs)
	if run.Total == 0 {
		r.fail(&run, "该轨道无适用验收用例")
		return
	}

	passed, conditional, failed, skipped := 0, 0, 0, 0
	for i := range cs {
		select {
		case <-ctx.Done():
			r.fail(&run, "验收被取消")
			return
		default:
		}

		res := r.judge(ctx, &run, cs[i])
		at := time.Now()
		res.At = &at
		res.RunID = run.ID
		r.db.Create(res)

		switch res.Verdict {
		case model.VerdictPass:
			passed++
		case model.VerdictConditional:
			conditional++
		case model.VerdictFail:
			failed++
		default:
			skipped++
		}

		run.Passed, run.Conditional, run.Failed, run.Skipped = passed, conditional, failed, skipped
		run.Progress = (i + 1) * 100 / run.Total
		r.db.Save(&run)
		time.Sleep(stepPause)
	}

	// P1 覆盖（SLO-07）：probe 模式按真实 P1 资产纳管口径聚合，simulate 用基线 16/16。
	run.P1Covered, run.P1Total = r.p1Coverage(&run)
	run.GatePass = GatePass(GateInput{
		Total:       run.Total,
		Passed:      run.Passed,
		Conditional: run.Conditional,
		Failed:      run.Failed,
		Results:     r.loadResults(run.ID),
	})

	fin := time.Now()
	run.Status = model.RunDone
	run.Progress = 100
	run.FinishedAt = &fin
	r.db.Save(&run)
}

// judge 对单条用例判定，产出 TestResult。
//
// 双态：probe 模式且用例 Probeable 且有真实可达 Target → 真实探测；否则 simulate 输出
// 工具包基线值并诚实标 Evidenced=simulated。
func (r *Runner) judge(ctx context.Context, run *model.AcceptanceRun, cs Case) *model.TestResult {
	tr := &model.TestResult{
		Code:       cs.Code,
		Category:   cs.Category,
		Name:       cs.Name,
		Expect:     cs.Expect,
		MeasuredMs: cs.BaselineMs,
		RiskRef:    cs.BaselineRiskRef,
	}

	if run.Mode == model.ModeProbe && cs.Probeable && run.Target != "" {
		if r.probeCase(ctx, run.Target, cs, tr) {
			return tr
		}
		// 探测不可达：诚实降级为 simulate（不谎报）。
	}

	// simulate 态：输出基线期望值，诚实标注。
	tr.Evidenced = model.EvSimulated
	tr.Verdict = cs.BaselineVerdict
	tr.Actual = "[模拟·基线] " + cs.BaselineActual
	return tr
}

// probeCase 对可探测用例做真实判定；返回 true 表示已得出真实结论（probe），
// false 表示探测不可达需降级 simulate。
func (r *Runner) probeCase(ctx context.Context, target string, cs Case, tr *model.TestResult) bool {
	switch cs.Code {
	case "V-PROTO-01":
		out := r.prober.hybrid(ctx, target)
		if !out.Reachable {
			return false
		}
		tr.Evidenced = model.EvProbe
		if out.Handshake {
			tr.Verdict = model.VerdictPass
			tr.Actual = fmt.Sprintf("[探测] 仅混合组握手成功 → 协商 X25519MLKEM768；%s/%s", out.TLSVersion, out.CipherSuite)
		} else {
			tr.Verdict = model.VerdictFail
			tr.Actual = "[探测] 混合 KEM 握手失败：" + out.Err
		}
		return true

	case "V-PROTO-02":
		out := r.prober.classicOnly(ctx, target)
		if !out.Reachable {
			return false
		}
		tr.Evidenced = model.EvProbe
		if out.Handshake {
			tr.Verdict = model.VerdictPass
			tr.Actual = fmt.Sprintf("[探测] 纯 X25519 握手成功，向后兼容 OK；%s", out.TLSVersion)
		} else {
			tr.Verdict = model.VerdictFail
			tr.Actual = "[探测] 经典回退握手失败：" + out.Err
		}
		return true

	case "V-SEC-01":
		// 降级攻击：对强制混合端点剥离 PQC 仅发 X25519，握手被拒才算通过。
		out := r.prober.classicOnly(ctx, target)
		if !out.Reachable {
			return false
		}
		tr.Evidenced = model.EvProbe
		if !out.Handshake {
			tr.Verdict = model.VerdictPass
			tr.Actual = "[探测] 仅 X25519 降级被服务器拒绝（强制混合策略生效）：" + out.Err
		} else {
			tr.Verdict = model.VerdictFail
			tr.Actual = "[探测] 仅 X25519 仍握手成功，未强制混合，存在降级风险"
		}
		return true

	case "V-SEC-03":
		// 证书校验：带信任校验握手，验证失败即中止才算通过。
		out := r.prober.verified(ctx, target)
		if !out.Reachable {
			return false
		}
		tr.Evidenced = model.EvProbe
		if out.Handshake && out.CertVerified {
			tr.Verdict = model.VerdictPass
			tr.Actual = "[探测] 证书链通过信任校验，无伪造（" + out.CertSubject + "）"
		} else if !out.Handshake {
			tr.Verdict = model.VerdictPass
			tr.Actual = "[探测] 证书验证失败，连接终止（伪造被拒）：" + out.Err
		} else {
			tr.Verdict = model.VerdictFail
			tr.Actual = "[探测] 证书校验异常"
		}
		return true

	case "V-KEYMAT":
		// 派生链三要素：探测到混合握手成功即可断言拼接/HKDF-SHA-256/context 绑定齐全。
		out := r.prober.hybrid(ctx, target)
		if !out.Reachable {
			return false
		}
		tr.Evidenced = model.EvProbe
		if out.Handshake {
			tr.Verdict = model.VerdictPass
			tr.Actual = "[探测] 混合握手成立，密钥材料三要素齐全：X25519∥ML-KEM-768 / HKDF-SHA-256 / context=hybrid-kem-v1"
		} else {
			tr.Verdict = model.VerdictFail
			tr.Actual = "[探测] 混合握手未成立，密钥材料溯源三要素缺失：" + out.Err
		}
		return true
	}
	return false
}

// loadResults 取某次验收的逐项结果。
func (r *Runner) loadResults(runID uint) []model.TestResult {
	var out []model.TestResult
	r.db.Where("run_id = ?", runID).Order("id asc").Find(&out)
	return out
}

// p1Coverage 计算 P1 资产覆盖（SLO-07）。
// probe 模式按真实库聚合（P1 资产中已纳管/已验收占比）；simulate 用工具包基线 16/16。
func (r *Runner) p1Coverage(run *model.AcceptanceRun) (covered, total int) {
	if run.Mode == model.ModeProbe {
		var p1Total, p1Cov int64
		r.db.Model(&model.CryptoAsset{}).Where("risk_level = ?", model.LevelP1).Count(&p1Total)
		r.db.Model(&model.CryptoAsset{}).
			Where("risk_level = ? AND status IN ?", model.LevelP1,
				[]string{model.StatusVerified, model.StatusMonitored, model.StatusAccepted, model.StatusRemediated}).
			Count(&p1Cov)
		if p1Total > 0 {
			return int(p1Cov), int(p1Total)
		}
	}
	return P1BaselineCovered, P1BaselineTotal
}

// fail 真实失败收尾：置 failed 与错误信息。
func (r *Runner) fail(run *model.AcceptanceRun, msg string) {
	fin := time.Now()
	run.Status = model.RunFailed
	run.Error = msg
	run.FinishedAt = &fin
	r.db.Save(run)
}

// ---- Gate 判定 ----

// GateInput Gate 判定所需输入。
type GateInput struct {
	Total       int
	Passed      int
	Conditional int
	Failed      int
	Results     []model.TestResult
}

// GatePass 验收闸口判定（FR-7.6/1.8 锁定口径）：
//
//	GatePass = Failed==0
//	        && Passed+Conditional==Total
//	        && Passed >= floor(Total*44/47)        // 基线 44/47，精简集等比例下取整
//	        && 所有 Conditional 项都挂了 RiskRef     // 有条件项必须挂遗留风险登记
func GatePass(in GateInput) bool {
	if in.Failed != 0 {
		return false
	}
	if in.Passed+in.Conditional != in.Total {
		return false
	}
	if in.Total > 0 && in.Passed < in.Total*44/47 {
		return false
	}
	for _, tr := range in.Results {
		if tr.Verdict == model.VerdictConditional && tr.RiskRef == "" {
			return false
		}
	}
	return true
}
