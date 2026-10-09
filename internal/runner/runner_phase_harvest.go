package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// runExternalHarvestPhase runs external intelligence harvesting as a standalone phase.
// Harvested URLs are ingested into the httpRecords table via an Executor with zero modules.
func (r *Runner) runExternalHarvestPhase(ctx context.Context, infra *phaseInfra) error {
	if len(r.options.Targets) == 0 {
		return nil
	}

	phaseStart := time.Now()

	src := r.buildExternalHarvesterSource()
	if src == nil {
		zap.L().Warn("ExternalHarvest: no source could be built, skipping")
		return nil
	}

	r.printPhaseStart("ExternalHarvest", "harvest URLs from external intelligence sources")

	ehSpeedDetail := fmt.Sprintf("Speed: concurrency=%s, max-per-host=%s",
		terminal.HiBlue(fmt.Sprintf("%d", r.options.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", r.options.MaxPerHost)))
	if budget := PhaseSpeedDetail(r.settings, "external_harvester", 0); budget != "" {
		ehSpeedDetail += ", " + budget
	}
	r.printPhaseDetail(ehSpeedDetail)
	r.printTargetDetail(r.formatTargetCounts(ctx, len(r.options.Targets)))
	r.printVerboseTargets(r.options.Targets)

	zap.L().Info("ExternalHarvest: ingesting harvested URLs into database")

	executorCfg := core.ExecutorConfig{
		Workers:       r.options.Concurrency,
		Services:      infra.svc,
		HTTPRequester: infra.httpRequester,
		Repository:    r.repository,
		ScanUUID:      infra.scanUUID,
		ProjectUUID:   r.options.ProjectUUID,
		ScopeMatcher:  infra.scopeMatcher,
		PauseCtrl:     r.pauseCtrl,
		OnTraffic:     r.makeOnTraffic("harvest"),
		OnResult: func(result *output.ResultEvent) {
			if err := r.output.Write(result); err != nil {
				zap.L().Error("Failed to write result", zap.Error(err))
			}
		},
	}

	executor := core.NewExecutor(executorCfg, src, nil, nil)
	_, err := executor.Execute(ctx)
	r.currentPhase.Load().noteExecution(executor.Report())
	if err != nil {
		return err
	}

	// Increment processed_count for external harvest phase
	if r.repository != nil && executor.Processed() > 0 {
		if err := r.repository.IncrementProcessedCount(ctx, infra.scanUUID, executor.Processed()); err != nil {
			zap.L().Warn("ExternalHarvest: failed to increment processed count", zap.Error(err))
		}
	}

	elapsed := time.Since(phaseStart)
	r.printPhaseComplete("ExternalHarvest", fmt.Sprintf("completed — %s items ingested in %s",
		terminal.Orange(fmt.Sprintf("%d", executor.Processed())), terminal.HiPurple(fmtDuration(elapsed))))
	zap.L().Info("ExternalHarvest: completed", zap.Int64("processed", executor.Processed()))
	return nil
}
