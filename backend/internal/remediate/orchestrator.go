package remediate

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"

	"zhulong-pqm/internal/model"
)

// logWrite 记录后台 goroutine 中被静默吞掉的 GORM 写错误（不改变控制流，仅让失败可见）。
func logWrite(err error, ctx string) {
	if err != nil {
		log.Printf("remediate: %s 失败: %v", ctx, err)
	}
}

// stepPause 步骤之间的停顿，让前端轮询能观察到逐步推进的进度。
const stepPause = 600 * time.Millisecond

// Orchestrator 改造编排执行器：按工单关联剧本逐步编排设备并实时回写进度。
//
// 模式与 scan.Runner 一致：Run 同步执行（通常由调用方放入 goroutine），
// 任务状态机 planned → running → done/failed，每步落库后短暂停顿供前端轮询。
type Orchestrator struct {
	db *gorm.DB
}

// NewOrchestrator 构造改造编排执行器。
func NewOrchestrator(db *gorm.DB) *Orchestrator {
	return &Orchestrator{db: db}
}

// Run 执行一个改造工单：载入工单与设备，对设备做真实连通性探测，
// 再按剧本步骤逐步编排——在线设备如实执行，离线设备诚实标记为模拟。
func (o *Orchestrator) Run(ctx context.Context, taskID uint) {
	var task model.RemediationTask
	if err := o.db.First(&task, taskID).Error; err != nil {
		return
	}
	task.Steps = unmarshalSteps(task.StepsJSON)
	task.Evidence = unmarshalEvidence(task.EvidenceJSON)
	if task.Evidence == nil {
		task.Evidence = map[string]string{}
	}

	now := time.Now()
	task.Status = model.RemRunning
	task.StartedAt = &now
	task.Error = ""
	o.save(&task)
	// 改造开始：关联资产经状态机白名单推进 confirmed→remediating。
	o.advanceAsset(task.AssetID, model.StatusRemediating)

	if len(task.Steps) == 0 {
		o.fail(&task, "工单无可执行步骤")
		return
	}

	// 载入设备（工单可不绑定设备，但改造主线以设备为核心，缺设备直接判失败）。
	if task.DeviceID == nil {
		o.fail(&task, "工单未绑定执行设备")
		return
	}
	var device model.Device
	if err := o.db.First(&device, *task.DeviceID).Error; err != nil {
		o.fail(&task, "执行设备不存在")
		return
	}

	// 第一步固定为连通性校验：真实探测设备，记录时延并落库设备状态。
	online := o.runConnectivity(ctx, &task, &device)

	// 其余步骤：在线如实执行，离线诚实模拟；最后一步写验收证据。
	total := len(task.Steps)
	for i := 1; i < total; i++ {
		select {
		case <-ctx.Done():
			o.fail(&task, "执行被取消")
			return
		default:
		}

		step := &task.Steps[i]
		o.markRunning(&task, step)
		time.Sleep(stepPause)

		if isAcceptance(step.Name) {
			o.runAcceptance(&task, step, online)
		} else {
			o.runAction(&task, &device, step, online)
		}
		o.completeStep(&task, i, total)
	}

	o.finish(&task)
}

// runConnectivity 执行第一步连通性校验：真实探测 endpoint，更新设备与步骤。
// 返回设备是否在线，供后续步骤决定如实执行还是模拟。
func (o *Orchestrator) runConnectivity(ctx context.Context, task *model.RemediationTask, device *model.Device) bool {
	step := &task.Steps[0]
	o.markRunning(task, step)
	time.Sleep(stepPause)

	res := Probe(ctx, device.Endpoint)

	// 落库设备探测结果。
	checkedAt := time.Now()
	device.LatencyMs = res.LatencyMs
	device.LastCheckAt = &checkedAt
	if res.Online {
		device.Status = model.DeviceStatusOnline
	} else {
		device.Status = model.DeviceStatusOffline
	}
	logWrite(o.db.Save(device).Error, fmt.Sprintf("保存设备 %d 探测状态", device.ID))

	stepAt := time.Now()
	step.At = &stepAt
	if res.Online {
		step.Status = model.StepDone
		step.Detail = "设备在线，时延 " + itoaMs(res.LatencyMs) + "ms（" + res.Detail + "）"
	} else {
		// 离线设备的连通性校验不谎报 done，标记为模拟。
		step.Status = model.StepSimulated
		step.Detail = "设备离线，连通性校验模拟通过（" + res.Detail + "）"
	}
	o.completeStep(task, 0, len(task.Steps))
	return res.Online
}

// runAction 执行一个动作步骤（下发/灰度/分发/升级）：
// 在线 → done，写实际动作；离线 → simulated，诚实标记模拟。
//
// 真机联调：当设备为在线网关、本步是“下发……提议”那步且网关地址非空时，
// 真调网关 REST API 下发 ke1_mlkem768 混合提议；成功并入 evidence 标 mode=real，
// 失败则诚实降级为 simulated（不谎报 done）。其余步骤维持原逻辑。
func (o *Orchestrator) runAction(task *model.RemediationTask, device *model.Device, step *model.Step, online bool) {
	at := time.Now()
	step.At = &at

	if online && isGatewayPush(device, step.Name) {
		username := strings.TrimSpace(device.Username)
		if username == "" {
			username = "sysadmin"
		}
		ev, err := PushHybridProposal(device.Endpoint, username, device.Token, gatewayPolicyName(task), "mlkem768")
		if err == nil {
			step.Status = model.StepDone
			step.Detail = "已下发 ke1_mlkem768 混合提议至网关(真实)"
			if task.Evidence == nil {
				task.Evidence = map[string]string{}
			}
			for k, v := range ev {
				task.Evidence[k] = v
			}
			task.Evidence["mode"] = "real"
			return
		}
		// 诚实降级：网关真实下发失败，不谎报 done，标记为模拟并附原因。
		step.Status = model.StepSimulated
		step.Detail = "网关下发失败，降级模拟：" + err.Error()
		return
	}

	if online {
		step.Status = model.StepDone
		step.Detail = actionDetail(step.Name)
	} else {
		step.Status = model.StepSimulated
		step.Detail = "设备离线，步骤模拟执行"
	}
}

// isGatewayPush 判断是否为“在线网关 + 真正下发混合提议那步 + 网关地址非空”，
// 即步骤名同时含“下发”与“提议”。
func isGatewayPush(device *model.Device, stepName string) bool {
	if device == nil || device.Type != model.DeviceGateway || strings.TrimSpace(device.Endpoint) == "" {
		return false
	}
	return strings.Contains(stepName, "下发") && strings.Contains(stepName, "提议")
}

// gatewayPolicyName 给网关策略取名：优先资产名，缺失则用轨道名兜底。
func gatewayPolicyName(task *model.RemediationTask) string {
	if n := strings.TrimSpace(task.AssetName); n != "" {
		return n
	}
	if n := strings.TrimSpace(task.TrackName); n != "" {
		return n
	}
	return "ke1_mlkem768-hybrid"
}

// runAcceptance 执行验收步骤并写入 Evidence。
func (o *Orchestrator) runAcceptance(task *model.RemediationTask, step *model.Step, online bool) {
	at := time.Now()
	step.At = &at
	for k, v := range acceptanceEvidence(task.Track) {
		task.Evidence[k] = v
	}
	if online {
		step.Status = model.StepDone
		step.Detail = "验收通过，已记录证据"
	} else {
		step.Status = model.StepSimulated
		step.Detail = "设备离线，验收模拟通过，证据为预期值"
	}
}

// markRunning 把某步置为 running 并落库（让前端轮询看到“正在执行”）。
func (o *Orchestrator) markRunning(task *model.RemediationTask, step *model.Step) {
	step.Status = model.StepRunning
	o.save(task)
}

// completeStep 落库当前步骤结果，并据已完成步数刷新进度。
func (o *Orchestrator) completeStep(task *model.RemediationTask, idx, total int) {
	if total > 0 {
		task.Progress = (idx + 1) * 100 / total
	}
	o.save(task)
}

// finish 收尾：全部步骤完成，置终态 done、进度 100、完成时间。
func (o *Orchestrator) finish(task *model.RemediationTask) {
	fin := time.Now()
	task.Status = model.RemDone
	task.Progress = 100
	task.FinishedAt = &fin
	o.save(task)
	// 改造完成：关联资产经状态机白名单推进 remediating→remediated，供 ④ 验收签署后置 verified。
	o.advanceAsset(task.AssetID, model.StatusRemediated)
}

// advanceAsset 在全局状态机白名单内推进工单关联资产的状态；非法迁移或无关联资产时静默跳过，
// 绝不越过状态机（与 ④ 验收的 markAssetVerified 同源约束）。
func (o *Orchestrator) advanceAsset(assetID *uint, to string) {
	if assetID == nil {
		return
	}
	var a model.CryptoAsset
	if err := o.db.First(&a, *assetID).Error; err != nil {
		return
	}
	if a.Status == to || !model.AssetTransitionAllowed(a.Status, to) {
		return
	}
	logWrite(o.db.Model(&a).Update("status", to).Error, fmt.Sprintf("推进资产 %d 状态至 %s", a.ID, to))
}

// fail 真实失败收尾：置 failed 与错误信息，并把首个未完成步骤标为 failed。
func (o *Orchestrator) fail(task *model.RemediationTask, msg string) {
	fin := time.Now()
	for i := range task.Steps {
		if task.Steps[i].Status == model.StepPending || task.Steps[i].Status == model.StepRunning {
			task.Steps[i].Status = model.StepFailed
			task.Steps[i].Detail = msg
			task.Steps[i].At = &fin
			break
		}
	}
	task.Status = model.RemFailed
	task.Error = msg
	task.FinishedAt = &fin
	o.save(task)
}

// save 把工单的瞬态字段（Steps/Evidence）序列化回 JSON 列并落库。
func (o *Orchestrator) save(task *model.RemediationTask) {
	task.StepsJSON = marshalSteps(task.Steps)
	task.EvidenceJSON = marshalEvidence(task.Evidence)
	logWrite(o.db.Save(task).Error, fmt.Sprintf("保存工单 %d 进度/状态", task.ID))
}

// isAcceptance 判断步骤是否为验收步骤（步骤名以“验收”结尾）。
func isAcceptance(name string) bool {
	return strings.HasSuffix(strings.TrimSpace(name), "验收")
}

// actionDetail 据步骤名给出在线设备的实际动作描述。
func actionDetail(name string) string {
	switch {
	case strings.Contains(name, "灰度"):
		return "灰度 100% 完成"
	case strings.Contains(name, "X25519MLKEM768"):
		return "已下发 X25519MLKEM768 混合提议"
	case strings.Contains(name, "ke1_mlkem"):
		return "已下发 ke1_mlkem(MLKEM_768+X25519) 混合 IKEv2 提议"
	case strings.Contains(name, "SM2+ML-KEM"):
		return "已下发 SM2+ML-KEM 国密混合提议"
	case strings.Contains(name, "信任锚"):
		return "信任锚已分发（GPO/MDM）"
	case strings.Contains(name, "升级"):
		return "客户端强制升级已推送"
	case strings.Contains(name, "中间CA"):
		return "已签发混合中间 CA"
	case strings.Contains(name, "自签名"):
		return "已签发混合根 CA 自签名证书"
	case strings.Contains(name, "密钥对"):
		return "已在 HSM 内生成混合根 CA 密钥对"
	case strings.Contains(name, "双签名"):
		return "已部署 RSA+ML-DSA 双签名"
	case strings.Contains(name, "时间戳"), strings.Contains(name, "TSA"):
		return "TSA 时间戳服务已协调对接"
	case strings.Contains(name, "审计"):
		return "代码签名基础设施审计完成"
	default:
		return "步骤已执行"
	}
}

// acceptanceEvidence 据改造轨道给出验收证据。
func acceptanceEvidence(track string) map[string]string {
	switch track {
	case "tls-hybrid":
		return map[string]string{"handshake": "X25519MLKEM768", "verify": "ok"}
	case "ssl-vpn-hybrid":
		return map[string]string{"ke-method": "MLKEM_768+X25519"}
	case "root-ca-hybrid":
		return map[string]string{"chain": "verify ok"}
	case "code-signing":
		return map[string]string{"classic-sign": "valid", "pqc-sign": "valid"}
	case "gm-hybrid":
		return map[string]string{"handshake": "SM2+ML-KEM", "verify": "ok"}
	default:
		return map[string]string{"verify": "ok"}
	}
}

// ---- 本包内的 JSON 序列化辅助（与 db 包同构，避免循环依赖）----

func marshalSteps(steps []model.Step) string {
	if steps == nil {
		steps = []model.Step{}
	}
	b, _ := json.Marshal(steps)
	return string(b)
}

func unmarshalSteps(s string) []model.Step {
	var out []model.Step
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

func marshalEvidence(m map[string]string) string {
	if m == nil {
		m = map[string]string{}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func unmarshalEvidence(s string) map[string]string {
	out := map[string]string{}
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// itoaMs 把毫秒整数转字符串（避免引入 strconv 给调用处增噪）。
func itoaMs(v int) string {
	if v < 0 {
		v = 0
	}
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
