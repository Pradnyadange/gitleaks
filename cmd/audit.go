package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/audit"
	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

var (
	auditOutput        string
	auditMode          string
	auditContextLines  int
	auditIncludeRaw    bool
	triageEnabled      bool
	triageOffline      bool
	triageDryRun       bool
	geminiModel        string
	triageConcurrency  int
	maxFindings        int
	triageContextLines int
)

var auditCmd = &cobra.Command{
	Use:   "audit [path]",
	Short: "Audit repository or directory and generate enriched findings JSON with optional AI triage",
	Run: func(cmd *cobra.Command, args []string) {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
		}

		if triageEnabled && !triageOffline && !triageDryRun {
			if geminiModel == "" {
				geminiModel = os.Getenv("GEMINI_MODEL")
			}
			if geminiModel == "" {
				log.Fatal().Msg("gemini model must be specified via --gemini-model or GEMINI_MODEL env when --triage is enabled without --offline")
			}

			apiKey := os.Getenv("GEMINI_API_KEY")
			if apiKey == "" {
				log.Fatal().Msg("GEMINI_API_KEY environment variable is required when --triage is enabled without --offline")
			}
		}

		initConfig(targetPath)
		initDiagnostics()

		cfg := Config(cmd)
		detector := Detector(cmd, cfg, targetPath)

		followSymlinks, _ := cmd.Flags().GetBool("follow-symlinks")
		detector.FollowSymlinks = followSymlinks

		var (
			findings []report.Finding
			err      error
		)

		ctx := cmd.Context()
		switch auditMode {
		case "git":
			logOpts := mustGetStringFlag(cmd, "log-opts")
			staged := mustGetBoolFlag(cmd, "staged")
			preCommit := mustGetBoolFlag(cmd, "pre-commit")

			var gitCmd *sources.GitCmd
			var scmPlatform scm.Platform

			if preCommit || staged {
				if gitCmd, err = sources.NewGitDiffCmdContext(ctx, targetPath, staged); err != nil {
					log.Fatal().Err(err).Msg("could not create Git diff cmd")
				}
				scmPlatform = scm.NoPlatform
			} else {
				if gitCmd, err = sources.NewGitLogCmdContext(ctx, targetPath, logOpts); err != nil {
					log.Fatal().Err(err).Msg("could not create Git log cmd")
				}
				if scmPlatform, err = scm.PlatformFromString(mustGetStringFlag(cmd, "platform")); err != nil {
					log.Fatal().Err(err).Send()
				}
			}

			findings, err = detector.DetectSource(
				ctx,
				&sources.Git{
					Cmd:             gitCmd,
					Config:          &detector.Config,
					Remote:          sources.NewRemoteInfoContext(ctx, scmPlatform, targetPath),
					Sema:            detector.Sema,
					MaxArchiveDepth: detector.MaxArchiveDepth,
				},
			)
		case "dir":
			findings, err = detector.DetectSource(
				ctx,
				&sources.Files{
					Config:          &cfg,
					FollowSymlinks:  detector.FollowSymlinks,
					MaxFileSize:     detector.MaxTargetMegaBytes * 1_000_000,
					Path:            targetPath,
					Sema:            detector.Sema,
					MaxArchiveDepth: detector.MaxArchiveDepth,
				},
			)
		default:
			log.Fatal().Msgf("invalid mode %q: expected 'git' or 'dir'", auditMode)
		}

		if err != nil {
			log.Error().Err(err).Msg("scan encountered errors")
		}
		var enriched []audit.EnrichedFinding

		for _, f := range findings {
			masked := audit.MaskSecret(f.Secret)
			secLen := len(f.Secret)

			ctxLines := auditContextLines
			if triageEnabled && triageContextLines > 0 && triageContextLines < auditContextLines {
				ctxLines = triageContextLines
			}

			codeCtx := audit.ExtractContext(
				targetPath,
				auditMode,
				f.Commit,
				f.File,
				f.StartLine,
				ctxLines,
				f.Secret,
				masked,
				auditIncludeRaw,
			)
			pathType := audit.DetectPathType(f.File)
			inHistory := audit.IsInHistoryOnly(targetPath, f.File)

			enrichedFinding := audit.EnrichedFinding{
				Fingerprint:   f.Fingerprint,
				RuleID:        f.RuleID,
				Description:   f.Description,
				File:          f.File,
				StartLine:     f.StartLine,
				EndLine:       f.EndLine,
				Commit:        f.Commit,
				Author:        f.Author,
				Date:          f.Date,
				Entropy:       float64(f.Entropy),
				Tags:          f.Tags,
				MaskedSecret:  masked,
				SecretLength:  secLen,
				CodeContext:   codeCtx,
				PathType:      pathType,
				InHistoryOnly: inHistory,
			}
			enriched = append(enriched, enrichedFinding)
		}

		var stats audit.TriageStats
		if triageEnabled {
			var client audit.LLMClient
			if !triageOffline {
				client = audit.NewGeminiClient(geminiModel, os.Getenv("GEMINI_API_KEY"))
			}
			enriched, stats = audit.TriageFindings(ctx, enriched, client, audit.TriageOptions{
				Offline:     triageOffline,
				DryRun:      triageDryRun,
				Concurrency: triageConcurrency,
				MaxFindings: maxFindings,
				Model:       geminiModel,
			})
		}

		fileData, err := json.MarshalIndent(enriched, "", "  ")
		if err != nil {
			log.Fatal().Err(err).Msg("failed to marshal enriched findings")
		}

		err = os.WriteFile(auditOutput, fileData, 0644)
		if err != nil {
			log.Fatal().Err(err).Msgf("failed to write audit output file %s", auditOutput)
		}

		log.Info().Int("count", len(enriched)).Str("output", auditOutput).Msg("audit findings generated successfully")

		if triageEnabled {
			fmt.Println("\n=== SECRET SENTINEL TRIAGE SUMMARY ===")
			fmt.Printf("Total Findings Processed: %d\n", len(enriched))
			fmt.Println("Verdicts:")
			for v, count := range stats.Verdicts {
				fmt.Printf("  - %s: %d\n", v, count)
			}
			fmt.Println("Sources:")
			for s, count := range stats.Sources {
				fmt.Printf("  - %s: %d\n", s, count)
			}
			fmt.Printf("API Calls Made: %d\n", stats.APICalls)
			fmt.Printf("Cache Hits: %d\n", stats.CacheHits)
			fmt.Printf("LLM Successes: %d\n", stats.LLMSuccesses)
			fmt.Printf("LLM Failures: %d\n", stats.LLMFailures)
			fmt.Println("======================================")
		}

		if len(enriched) > 0 {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.Flags().StringVar(&auditMode, "mode", "git", "scan mode: git or dir")
	auditCmd.Flags().StringVar(&auditOutput, "audit-output", "audit-findings.json", "output JSON file path for enriched findings")
	auditCmd.Flags().IntVar(&auditContextLines, "context-lines", 20, "number of context lines before and after finding")
	auditCmd.Flags().BoolVar(&auditIncludeRaw, "include-raw-secret", false, "include raw secret in context (default false)")
	auditCmd.Flags().String("platform", "", "the target platform used to generate links (github, gitlab)")
	auditCmd.Flags().Bool("staged", false, "scan staged commits (good for pre-commit)")
	auditCmd.Flags().Bool("pre-commit", false, "scan using git diff")
	auditCmd.Flags().String("log-opts", "", "git log options")
	auditCmd.Flags().Bool("follow-symlinks", false, "scan files that are symlinks to other files")

	auditCmd.Flags().BoolVar(&triageEnabled, "triage", false, "enable AI/heuristic triage of findings")
	auditCmd.Flags().BoolVar(&triageOffline, "offline", false, "run triage using heuristics only (zero network calls)")
	auditCmd.Flags().BoolVar(&triageDryRun, "triage-dry-run", false, "print prompts that would be sent without making API calls")
	auditCmd.Flags().StringVar(&geminiModel, "gemini-model", "", "Gemini model name (falls back to GEMINI_MODEL env)")
	auditCmd.Flags().IntVar(&triageConcurrency, "triage-concurrency", 3, "concurrency pool size for triage workers")
	auditCmd.Flags().IntVar(&maxFindings, "max-findings", 50, "maximum number of findings to triage")
	auditCmd.Flags().IntVar(&triageContextLines, "triage-context-lines", 10, "context lines included in triage prompt")
}
