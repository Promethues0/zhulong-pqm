// Command zhulong-pqm 启动烛龙·后量子迁移治理平台后端服务。
package main

import (
	"context"
	"log"
	"net/http"

	"zhulong-pqm/internal/api"
	"zhulong-pqm/internal/config"
	"zhulong-pqm/internal/db"
	"zhulong-pqm/internal/gmtls"
	"zhulong-pqm/internal/monitor"
)

func main() {
	cfg := config.Load()

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}

	srv := api.NewServer(database, cfg)

	// B0-5 启动进程内统一调度框架（①周期扫描/⑤复扫复用同一 ticker）。
	// ⑤ 监测复扫：把所有启用策略注册到统一调度（A5-2）。
	monitor.RegisterPolicies(srv.Scheduler(), database)
	// ⑥ 仪表板趋势：daily 快照任务注册到同一 ticker（C1，启动即采一次）。
	api.RegisterDailySnapshot(srv.Scheduler(), database)
	srv.Scheduler().Start(context.Background())

	r := srv.Router()

	// 国密 TLCP(SM2/SM3/SM4) 监听：配置了 ZPQM_TLCP_ADDR 时，另起 goroutine 用同一
	// gin router 对外提供 TLCP 服务，与明文口并存。失败只 log 不退出（不影响明文口）。
	if cfg.TLCPAddr != "" {
		go func() {
			ln, err := gmtls.Listener(cfg.TLCPAddr, cfg.TLCPCertDir)
			if err != nil {
				log.Printf("国密 TLCP 启动失败（明文口不受影响）: %v", err)
				return
			}
			log.Printf("国密 TLCP(SM2/SM3/SM4) 已监听 %s（%s）", cfg.TLCPAddr, gmtls.Describe(cfg.TLCPCertDir))
			if err := http.Serve(ln, r); err != nil {
				log.Printf("国密 TLCP 服务退出: %v", err)
			}
		}()
	}

	addr := ":" + cfg.Port
	log.Printf("烛龙 PQM 后端启动，监听 %s（默认账号 admin/admin@1234）", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}
