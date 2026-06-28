// Command zhulong-pqm 启动烛龙·后量子迁移治理平台后端服务。
package main

import (
	"context"
	"log"

	"zhulong-pqm/internal/api"
	"zhulong-pqm/internal/config"
	"zhulong-pqm/internal/db"
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

	addr := ":" + cfg.Port
	log.Printf("烛龙 PQM 后端启动，监听 %s（默认账号 admin/admin@1234）", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}
