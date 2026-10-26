package cmd

import (
	"encoding/json"
	"os"

	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/audit"
	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

var (
	auditOutput       string
	auditMode         string
	auditContextLines int
	auditIncludeRaw   bool
)

var auditCmd = &cobra.Command{
	Use:   "audit [path]",
	Short: "Audit repository or directory and generate enriched findings JSON",
	Run: func(cmd *cobra.Command, args []string) {
		targetPath := "."
		if len(args) > 0 {
			targetPath = args[0]
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
					logging.Fatal().Err(err).Msg("could not create Git diff cmd")
				}
				scmPlatform = scm.NoPlatform
			} else {
				if gitCmd, err = sources.NewGitLogCmdContext(ctx, targetPath, logOpts); err != nil {
					logging.Fatal().Err(err).Msg("could not create Git log cmd")
				}
				if scmPlatform, err = scm.PlatformFromString(mustGetStringFlag(cmd, "platform")); err != nil {
					logging.Fatal().Err(err).Send()
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
			logging.Fatal().Msgf("invalid mode %q: expected 'git' or 'dir'", auditMode)
		}

		if err != nil {
			logging.Error().Err(err).Msg("scan encountered errors")
		}

		var enriched []audit.EnrichedFinding
		for _, f := range findings {
			masked := audit.MaskSecret(f.Secret)
			codeCtx := audit.ExtractContext(
				targetPath,
				auditMode,
				f.Commit,
				f.File,
				f.StartLine,
				auditContextLines,
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
				Entropy:       f.Entropy,
				Tags:          f.Tags,
				MaskedSecret:  masked,
				CodeContext:   codeCtx,
				PathType:      pathType,
				InHistoryOnly: inHistory,
			}
			enriched = append(enriched, enrichedFinding)
		}

		fileData, err := json.MarshalIndent(enriched, "", "  ")
		if err != nil {
			logging.Fatal().Err(err).Msg("failed to marshal enriched findings")
		}

		err = os.WriteFile(auditOutput, fileData, 0644)
		if err != nil {
			logging.Fatal().Err(err).Msgf("failed to write audit output file %s", auditOutput)
		}

		logging.Info().Int("count", len(enriched)).Str("output", auditOutput).Msg("audit findings generated successfully")

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
}
