using System.CommandLine;
using System.CommandLine.Completions;
using System.CommandLine.Help;

namespace Picket;

internal static partial class Program
{
    private static readonly ParserConfiguration s_commandLineParserConfiguration = new()
    {
        EnablePosixBundling = false,
        ResponseFileTokenReplacer = null,
    };

    private static Task<int> RunCommandLineAsync(string[] args)
    {
        string[] normalizedArgs = NormalizeCommandLineArgs(args);
        if (!CanParseRootCommand(normalizedArgs))
        {
            Console.Error.WriteLine($"unknown command: {args[0]}");
            return Task.FromResult(UnknownFlagExitCode);
        }

        RootCommand rootCommand = CreateRootCommand(args);
        ParseResult parseResult = rootCommand.Parse(normalizedArgs, s_commandLineParserConfiguration);
        return parseResult.InvokeAsync();
    }

    private static RootCommand CreateRootCommand(string[] args)
    {
        var rootCommand = new RootCommand("Bootstrap secrets scanner.")
        {
            TreatUnmatchedTokensAsErrors = true,
        };

        rootCommand.Subcommands.Add(CreateScanCommand(args));
        rootCommand.Subcommands.Add(CreateVerifyCommand(args));
        rootCommand.Subcommands.Add(CreateAnalyzeCommand(args));
        rootCommand.Subcommands.Add(CreateBaselineCommand(args));
        rootCommand.Subcommands.Add(CreateCacheCommand(args));
        rootCommand.Subcommands.Add(CreateGitCommand(args));
        rootCommand.Subcommands.Add(CreateDirectoryCommand(args));
        rootCommand.Subcommands.Add(CreateStdinCommand(args));
        rootCommand.Subcommands.Add(CreateRulesCommand(args));
        rootCommand.Subcommands.Add(CreateHooksCommand(args));
        rootCommand.Subcommands.Add(CreateViewCommand(args));
        rootCommand.Subcommands.Add(CreateTuiCommand(args));
        rootCommand.Subcommands.Add(CreateVersionCommand(args));
        rootCommand.Subcommands.Add(CreateDetectCommand(args));
        rootCommand.Subcommands.Add(CreateProtectCommand(args));

        ConfigureHelp(rootCommand);
        return rootCommand;
    }

    private static Command CreateScanCommand(string[] args)
    {
        Command command = CreateForwardingCommand(
            "scan",
            "Native filesystem and source-host scan.",
            args,
            1,
            static forwardedArgs => Task.FromResult(RunScan(forwardedArgs)));
        AddOptionalArgument(command, "picket scan", "path");
        AddNativeScanOptions(command, "picket scan");
        AddLiveVerificationOptions(command, "picket scan", includeModeSwitches: false);
        AddGitHubSourceOptions(command, "picket scan");
        AddGiteaSourceOptions(command, "picket scan");
        AddGitLabSourceOptions(command, "picket scan");
        AddBitbucketSourceOptions(command, "picket scan");
        AddAzureBlobSourceOptions(command, "picket scan");
        AddGcsSourceOptions(command, "picket scan");
        AddS3SourceOptions(command, "picket scan");
        AddAzureDevOpsSourceOptions(command, "picket scan");
        AddContainerArchiveSourceOptions(command, "picket scan");
        AddResultFilterOptions(command, "picket scan");
        AddScanLimitOptions(command, "picket scan", includeMaxDecodeDepth: false, includeArchiveSizeLimits: true);
        AddDiagnosticsOptions(command, "picket scan");
        command.Options.Add(CreateRedactOption("picket scan"));
        return command;
    }

    private static Command CreateVerifyCommand(string[] args)
    {
        Command command = CreateForwardingCommand(
            "verify",
            "Run native verification for detected findings.",
            args,
            1,
            static forwardedArgs => Task.FromResult(RunVerify(forwardedArgs)));
        AddOptionalArgument(command, "picket verify", "path");
        AddNativeReportOptions(command, "picket verify", "json|jsonl|csv|junit|html|gitlab|sarif|toon");
        AddCacheOptions(command, "picket verify");
        AddLiveVerificationOptions(command, "picket verify", includeModeSwitches: true);
        AddResultFilterOptions(command, "picket verify");
        AddScanLimitOptions(command, "picket verify", includeMaxDecodeDepth: false, includeArchiveSizeLimits: true);
        AddDiagnosticsOptions(command, "picket verify");
        return command;
    }

    private static Command CreateAnalyzeCommand(string[] args)
    {
        Command command = CreateForwardingCommand(
            "analyze",
            "Write incident-response analysis for detected findings.",
            args,
            1,
            static forwardedArgs => Task.FromResult(RunAnalyze(forwardedArgs)));
        AddOptionalArgument(command, "picket analyze", "path");
        AddNativeReportOptions(command, "picket analyze", "json|jsonl|text");
        AddCacheOptions(command, "picket analyze");
        AddLiveVerificationOptions(command, "picket analyze", includeModeSwitches: true);
        AddResultFilterOptions(command, "picket analyze");
        AddScanLimitOptions(command, "picket analyze", includeMaxDecodeDepth: false, includeArchiveSizeLimits: true);
        AddDiagnosticsOptions(command, "picket analyze");
        return command;
    }

    private static Command CreateBaselineCommand(string[] args)
    {
        var command = new Command("baseline", "Baseline workflow commands.")
        {
            TreatUnmatchedTokensAsErrors = true,
        };
        Command createCommand = CreateForwardingCommand(
            "create",
            "Write a Gitleaks-compatible baseline JSON report.",
            args,
            2,
            static forwardedArgs => Task.FromResult(RunBaselineCreate(forwardedArgs)));
        AddOptionalArgument(createCommand, "picket baseline create", "path");
        AddBaselineCreateOptions(createCommand, "picket baseline create");
        command.Subcommands.Add(createCommand);
        return command;
    }

    private static Command CreateCacheCommand(string[] args)
    {
        var command = new Command("cache", "Native scan cache maintenance.")
        {
            TreatUnmatchedTokensAsErrors = true,
        };

        Command statsCommand = CreateForwardingCommand(
            "stats",
            "Summarize native scan cache entries.",
            args,
            2,
            static forwardedArgs => Task.FromResult(RunCacheStats(forwardedArgs)));
        AddOptionalArgument(statsCommand, "picket cache stats", "source");
        AddCacheMaintenanceOptions(statsCommand, "picket cache stats", includePruneOptions: false);

        Command pruneCommand = CreateForwardingCommand(
            "prune",
            "Delete native scan cache entries.",
            args,
            2,
            static forwardedArgs => Task.FromResult(RunCachePrune(forwardedArgs)));
        AddOptionalArgument(pruneCommand, "picket cache prune", "source");
        AddCacheMaintenanceOptions(pruneCommand, "picket cache prune", includePruneOptions: true);

        Command exportCommand = CreateForwardingCommand(
            "export",
            "Write active native scan cache entries to a portable archive.",
            args,
            2,
            static forwardedArgs => Task.FromResult(RunCacheExport(forwardedArgs)));
        AddOptionalArgument(exportCommand, "picket cache export", "source");
        AddCacheMaintenanceOptions(exportCommand, "picket cache export", includePruneOptions: false);
        exportCommand.Options.Add(CreateValueOption("picket cache export", "--output", "path"));

        Command importCommand = CreateForwardingCommand(
            "import",
            "Restore active native scan cache entries from a portable archive.",
            args,
            2,
            static forwardedArgs => Task.FromResult(RunCacheImport(forwardedArgs)));
        AddOptionalArgument(importCommand, "picket cache import", "source");
        AddCacheMaintenanceOptions(importCommand, "picket cache import", includePruneOptions: false);
        importCommand.Options.Add(CreateValueOption("picket cache import", "--input", "path"));

        command.Subcommands.Add(statsCommand);
        command.Subcommands.Add(pruneCommand);
        command.Subcommands.Add(exportCommand);
        command.Subcommands.Add(importCommand);
        return command;
    }

    private static Command CreateGitCommand(string[] args)
    {
        Command command = CreateForwardingCommand(
            "git",
            "Scan git history using the Gitleaks-compatible patch model.",
            args,
            1,
            static forwardedArgs => Task.FromResult(RunGit(forwardedArgs)));
        AddOptionalArgument(command, "picket git", "repo");
        AddCompatibilityOptions(command, "picket git");
        command.Options.Add(CreateValueOption("picket git", "--log-opts", "value"));
        command.Options.Add(CreateChoiceValueOption("picket git", "--platform", "value", "unknown", "none", "github", "gitlab", "azuredevops", "gitea", "bitbucket"));
        command.Options.Add(CreateFlagOption("picket git", "--staged"));
        command.Options.Add(CreateFlagOption("picket git", "--pre-commit"));
        AddScanLimitOptions(command, "picket git", includeMaxDecodeDepth: false, includeArchiveSizeLimits: true);
        AddDiagnosticsOptions(command, "picket git");
        command.Options.Add(CreateRedactOption("picket git"));
        return command;
    }

    private static Command CreateDirectoryCommand(string[] args)
    {
        Command command = CreateForwardingCommand(
            "dir",
            "Scan a directory or file path.",
            args,
            1,
            static forwardedArgs => Task.FromResult(RunDirectory(forwardedArgs)));
        command.Aliases.Add("file");
        command.Aliases.Add("directory");
        AddRequiredArgument(command, "picket dir", "path");
        AddCompatibilityOptions(command, "picket dir");
        command.Options.Add(CreateFlagOption("picket dir", "--follow-symlinks"));
        AddScanLimitOptions(command, "picket dir", includeMaxDecodeDepth: false, includeArchiveSizeLimits: true);
        AddDiagnosticsOptions(command, "picket dir");
        command.Options.Add(CreateRedactOption("picket dir"));
        return command;
    }

    private static Command CreateStdinCommand(string[] args)
    {
        Command command = CreateForwardingCommand(
            "stdin",
            "Scan piped input.",
            args,
            1,
            static forwardedArgs => RunStdinAsync(forwardedArgs));
        AddCompatibilityOptions(command, "picket stdin");
        AddScanLimitOptions(command, "picket stdin", includeMaxDecodeDepth: true, includeArchiveSizeLimits: false);
        command.Options.Add(CreateValueOption("picket stdin", "--max-archive-depth", "n"));
        AddDiagnosticsOptions(command, "picket stdin");
        command.Options.Add(CreateRedactOption("picket stdin"));
        return command;
    }

    private static Command CreateRulesCommand(string[] args)
    {
        var command = new Command("rules", "Rule pack commands.")
        {
            TreatUnmatchedTokensAsErrors = true,
        };

        Command checkCommand = CreateForwardingCommand(
            "check",
            "Validate a resolved rule pack.",
            args,
            2,
            static forwardedArgs => Task.FromResult(RunRulesCheck(forwardedArgs)));
        AddOptionalArgument(checkCommand, "picket rules check", "source");
        checkCommand.Options.Add(CreateValueOption("picket rules check", "--config", "path", "-c"));
        checkCommand.Options.Add(CreateChoiceValueOption("picket rules check", "--profile", "profile", "picket"));
        checkCommand.Options.Add(CreateFlagOption("picket rules check", "--print-config"));

        Command testCommand = CreateForwardingCommand(
            "test",
            "Scan sample text with a single rule.",
            args,
            2,
            static forwardedArgs => Task.FromResult(RunRulesTest(forwardedArgs)));
        AddRequiredArgument(testCommand, "picket rules test", "rule-id");
        AddOptionalArgument(testCommand, "picket rules test", "input");
        testCommand.Options.Add(CreateValueOption("picket rules test", "--config", "path", "-c"));
        testCommand.Options.Add(CreateChoiceValueOption("picket rules test", "--report-format", "json|jsonl|csv|junit|html|gitlab|sarif|toon", ["json", "jsonl", "csv", "junit", "html", "gitlab", "sarif", "toon"], "-f"));
        testCommand.Options.Add(CreateValueOption("picket rules test", "--report-path", "path", "-r"));
        testCommand.Options.Add(CreateChoiceValueOption("picket rules test", "--profile", "profile", "picket"));
        testCommand.Options.Add(CreateValueOption("picket rules test", "--source", "path"));
        testCommand.Options.Add(CreateValueOption("picket rules test", "--path", "path"));
        testCommand.Options.Add(CreateFlagOption("picket rules test", "--print-config"));
        testCommand.Options.Add(CreateFlagOption("picket rules test", "--ignore-gitleaks-allow"));
        AddScanLimitOptions(testCommand, "picket rules test", includeMaxDecodeDepth: true, includeArchiveSizeLimits: false);
        testCommand.Options.Add(CreateRedactOption("picket rules test"));

        command.Subcommands.Add(checkCommand);
        command.Subcommands.Add(testCommand);
        return command;
    }

    private static Command CreateHooksCommand(string[] args)
    {
        var command = new Command("hooks", "Install local git hooks.")
        {
            TreatUnmatchedTokensAsErrors = true,
        };
        Command installCommand = CreateForwardingCommand(
            "install",
            "Write managed pre-commit, pre-push, and pre-receive hooks.",
            args,
            2,
            static forwardedArgs => Task.FromResult(RunHooksInstall(forwardedArgs)));
        AddOptionalArgument(installCommand, "picket hooks install", "pre-commit|pre-push|pre-receive|all");
        installCommand.Options.Add(CreateValueOption("picket hooks install", "--repo", "path"));
        installCommand.Options.Add(CreateFlagOption("picket hooks install", "--force"));
        installCommand.Options.Add(CreateValueOption("picket hooks install", "--command", "path"));
        installCommand.Options.Add(CreateValueOption("picket hooks install", "--config", "path", "-c"));
        installCommand.Options.Add(CreateValueOption("picket hooks install", "--baseline-path", "path", "-b"));
        installCommand.Options.Add(CreateValueOption("picket hooks install", "--max-target-megabytes", "n"));
        installCommand.Options.Add(CreateRedactOption("picket hooks install"));
        command.Subcommands.Add(installCommand);
        return command;
    }

    private static Command CreateViewCommand(string[] args)
    {
        Command command = CreateForwardingCommand(
            "view",
            "Summarize or open a local report.",
            args,
            1,
            static forwardedArgs => Task.FromResult(RunView(forwardedArgs)));
        AddRequiredArgument(command, "picket view", "report");
        command.Options.Add(CreateFlagOption("picket view", "--open"));
        return command;
    }

    private static Command CreateTuiCommand(string[] args)
    {
        Command command = CreateForwardingCommand(
            "tui",
            "Interactive report triage and scan workspace.",
            args,
            1,
            static forwardedArgs => RunTuiAsync(forwardedArgs));
        AddOptionalArgument(command, "picket tui", "report");
        command.Options.Add(CreateFlagOption("picket tui", "--flow"));
        command.Options.Add(CreateFlagOption("picket tui", "--scan"));
        return command;
    }

    private static Command CreateVersionCommand(string[] args)
    {
        return CreateForwardingCommand(
            "version",
            "Print version information.",
            args,
            1,
            static _ =>
            {
                Console.Out.WriteLine("picket dev");
                return Task.FromResult(0);
            });
    }

    private static Command CreateDetectCommand(string[] args)
    {
        Command command = CreateForwardingCommand(
            "detect",
            "Deprecated Gitleaks-compatible detection shim.",
            args,
            1,
            static forwardedArgs => RunDetectAsync(forwardedArgs));
        command.Hidden = !IsHelpForCommand(args, "detect");
        command.Options.Add(CreateValueOption("picket detect", "--source", "path"));
        command.Options.Add(CreateFlagOption("picket detect", "--no-git"));
        command.Options.Add(CreateFlagOption("picket detect", "--pipe"));
        AddCompatibilityReportOptions(command, "picket detect");
        command.Options.Add(CreateValueOption("picket detect", "--log-opts", "value"));
        command.Options.Add(CreateChoiceValueOption("picket detect", "--platform", "value", "unknown", "none", "github", "gitlab", "azuredevops", "gitea", "bitbucket"));
        command.Options.Add(CreateFlagOption("picket detect", "--follow-symlinks"));
        command.Options.Add(CreateValueOption("picket detect", "--max-target-megabytes", "n"));
        command.Options.Add(CreateValueOption("picket detect", "--max-archive-depth", "n"));
        command.Options.Add(CreateValueOption("picket detect", "--timeout", "n"));
        command.Options.Add(CreateRedactOption("picket detect"));
        return command;
    }

    private static Command CreateProtectCommand(string[] args)
    {
        Command command = CreateForwardingCommand(
            "protect",
            "Deprecated Gitleaks-compatible pre-commit shim.",
            args,
            1,
            static forwardedArgs => Task.FromResult(RunProtect(forwardedArgs)));
        command.Hidden = !IsHelpForCommand(args, "protect");
        command.Options.Add(CreateValueOption("picket protect", "--source", "path"));
        command.Options.Add(CreateFlagOption("picket protect", "--staged"));
        AddCompatibilityReportOptions(command, "picket protect");
        command.Options.Add(CreateValueOption("picket protect", "--max-target-megabytes", "n"));
        command.Options.Add(CreateValueOption("picket protect", "--max-archive-depth", "n"));
        command.Options.Add(CreateValueOption("picket protect", "--timeout", "n"));
        command.Options.Add(CreateRedactOption("picket protect"));
        return command;
    }

    private static Command CreateForwardingCommand(
        string name,
        string description,
        string[] originalArgs,
        int commandTokenCount,
        Func<string[], Task<int>> handler)
    {
        var command = new Command(name, description)
        {
            TreatUnmatchedTokensAsErrors = HasHelpToken(originalArgs),
        };
        command.SetAction((_, _) => handler(GetForwardedArgs(originalArgs, commandTokenCount)));
        return command;
    }

    private static string[] GetForwardedArgs(string[] args, int commandTokenCount)
    {
        return args.Length <= commandTokenCount ? [] : args[commandTokenCount..];
    }

    private static void AddNativeScanOptions(Command command, string commandName)
    {
        AddNativeReportOptions(command, commandName, "json|jsonl|csv|junit|html|gitlab|sarif|toon");
        command.Options.Add(CreateValueOption(commandName, "--ignore-path", "path"));
        command.Options.Add(CreateFlagOption(commandName, "--no-ignore"));
        AddCacheOptions(command, commandName);
        command.Options.Add(CreateValueOption(commandName, "--enable-rule", "id"));
        command.Options.Add(CreateFlagOption(commandName, "--verify"));
    }

    private static void AddNativeReportOptions(Command command, string commandName, string formatValues)
    {
        command.Options.Add(CreateValueOption(commandName, "--config", "path", "-c"));
        command.Options.Add(CreateChoiceValueOption(commandName, "--report-format", formatValues, SplitChoices(formatValues), "-f"));
        command.Options.Add(CreateValueOption(commandName, "--report-path", "path", "-r"));
        command.Options.Add(CreateChoiceValueOption(commandName, "--profile", "profile", "picket"));
        command.Options.Add(CreateValueOption(commandName, "--source", "path"));
    }

    private static void AddCacheOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--cache-dir", "path"));
        command.Options.Add(CreateChoiceValueOption(commandName, "--cache-mode", "mode", "raw", "secret-hash-only"));
    }

    private static void AddLiveVerificationOptions(Command command, string commandName, bool includeModeSwitches)
    {
        if (includeModeSwitches)
        {
            command.Options.Add(CreateFlagOption(commandName, "--offline"));
            command.Options.Add(CreateFlagOption(commandName, "--live"));
        }

        command.Options.Add(CreateValueOption(commandName, "--github-api-endpoint", "uri"));
        command.Options.Add(CreateValueOption(commandName, "--github-api-proxy", "uri"));
        command.Options.Add(CreateChoiceValueOption(commandName, "--live-tls-mode", "mode", "system", "tls12-plus"));
        command.Options.Add(CreateValueOption(commandName, "--live-rate-limit-ms", "n"));
        command.Options.Add(CreateValueOption(commandName, "--live-provider-rate-limit-ms", "n"));
        command.Options.Add(CreateFlagOption(commandName, "--allow-non-public-endpoints"));
    }

    private static void AddGitHubSourceOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--github-repository", "owner/name"));
        command.Options.Add(CreateValueOption(commandName, "--github-organization", "org"));
        command.Options.Add(CreateValueOption(commandName, "--github-user", "login"));
        command.Options.Add(CreateValueOption(commandName, "--github-repository-type", "value"));
        command.Options.Add(CreateValueOption(commandName, "--github-gist", "id"));
        command.Options.Add(CreateFlagOption(commandName, "--github-gists"));
        command.Options.Add(CreateValueOption(commandName, "--github-user-gists", "login"));
        command.Options.Add(CreateValueOption(commandName, "--github-token-env", "name"));
        command.Options.Add(CreateValueOption(commandName, "--github-ref", "ref"));
        command.Options.Add(CreateValueOption(commandName, "--github-pull-request", "id"));
        command.Options.Add(CreateFlagOption(commandName, "--github-include-issues"));
        command.Options.Add(CreateChoiceValueOption(commandName, "--github-issue-state", "state", "open", "closed", "all"));
        command.Options.Add(CreateFlagOption(commandName, "--github-include-releases"));
        command.Options.Add(CreateFlagOption(commandName, "--github-include-actions-artifacts"));
        command.Options.Add(CreateValueOption(commandName, "--github-source-api-endpoint", "uri"));
    }

    private static void AddGiteaSourceOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--gitea-repository", "owner/name"));
        command.Options.Add(CreateValueOption(commandName, "--gitea-organization", "org"));
        command.Options.Add(CreateValueOption(commandName, "--gitea-user", "login"));
        command.Options.Add(CreateValueOption(commandName, "--gitea-ref", "ref"));
        command.Options.Add(CreateValueOption(commandName, "--gitea-pull-request", "id"));
        command.Options.Add(CreateFlagOption(commandName, "--gitea-include-issues"));
        command.Options.Add(CreateValueOption(commandName, "--gitea-issue-state", "open|closed|all"));
        command.Options.Add(CreateFlagOption(commandName, "--gitea-include-releases"));
        command.Options.Add(CreateValueOption(commandName, "--gitea-generic-package-owner", "owner"));
        command.Options.Add(CreateValueOption(commandName, "--gitea-generic-package-name", "name"));
        command.Options.Add(CreateValueOption(commandName, "--gitea-generic-package-version", "version"));
        command.Options.Add(CreateValueOption(commandName, "--gitea-generic-package-file", "file"));
        command.Options.Add(CreateValueOption(commandName, "--gitea-token-env", "name"));
        command.Options.Add(CreateValueOption(commandName, "--gitea-api-endpoint", "uri"));
    }

    private static void AddBitbucketSourceOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--bitbucket-repository", "workspace/repo"));
        command.Options.Add(CreateValueOption(commandName, "--bitbucket-workspace", "workspace"));
        command.Options.Add(CreateValueOption(commandName, "--bitbucket-project", "key"));
        command.Options.Add(CreateValueOption(commandName, "--bitbucket-ref", "ref"));
        command.Options.Add(CreateValueOption(commandName, "--bitbucket-pull-request", "id"));
        command.Options.Add(CreateFlagOption(commandName, "--bitbucket-include-downloads"));
        command.Options.Add(CreateValueOption(commandName, "--bitbucket-pipeline-id", "id"));
        command.Options.Add(CreateFlagOption(commandName, "--bitbucket-include-pipeline-logs"));
        command.Options.Add(CreateFlagOption(commandName, "--bitbucket-include-snippets"));
        command.Options.Add(CreateValueOption(commandName, "--bitbucket-token-env", "name"));
        command.Options.Add(CreateValueOption(commandName, "--bitbucket-username-env", "name"));
        command.Options.Add(CreateChoiceValueOption(commandName, "--bitbucket-token-kind", "kind", "bearer", "app-password"));
        command.Options.Add(CreateValueOption(commandName, "--bitbucket-api-endpoint", "uri"));
    }

    private static void AddAzureDevOpsSourceOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--azure-devops-organization", "org"));
        command.Options.Add(CreateValueOption(commandName, "--azure-devops-endpoint", "uri"));
        command.Options.Add(CreateValueOption(commandName, "--azure-devops-token-env", "name"));
        command.Options.Add(CreateChoiceValueOption(commandName, "--azure-devops-token-kind", "kind", "pat", "bearer"));
        command.Options.Add(CreateValueOption(commandName, "--azure-devops-project", "name"));
        command.Options.Add(CreateValueOption(commandName, "--azure-devops-repository", "name"));
        command.Options.Add(CreateValueOption(commandName, "--azure-devops-branch", "name"));
        command.Options.Add(CreateValueOption(commandName, "--azure-devops-pull-request", "id"));
        command.Options.Add(CreateFlagOption(commandName, "--azure-devops-include-wikis"));
        command.Options.Add(CreateValueOption(commandName, "--azure-devops-build-id", "id"));
        command.Options.Add(CreateFlagOption(commandName, "--azure-devops-include-artifacts"));
        command.Options.Add(CreateFlagOption(commandName, "--azure-devops-include-logs"));
        command.Options.Add(CreateValueOption(commandName, "--azure-devops-release-id", "id"));
        command.Options.Add(CreateFlagOption(commandName, "--azure-devops-include-release-artifacts"));
        command.Options.Add(CreateValueOption(commandName, "--azure-devops-max-artifact-megabytes", "n"));
        command.Options.Add(CreateValueOption(commandName, "--azure-devops-max-log-megabytes", "n"));
        command.Options.Add(CreateFlagOption(commandName, "--allow-non-public-source-endpoints"));
        command.Options.Add(CreateFlagOption(commandName, "--allow-insecure-source-endpoints"));
    }

    private static void AddAzureBlobSourceOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--azure-blob-endpoint", "uri"));
        command.Options.Add(CreateValueOption(commandName, "--azure-blob-container", "name"));
        command.Options.Add(CreateValueOption(commandName, "--azure-blob-prefix", "prefix"));
        command.Options.Add(CreateValueOption(commandName, "--azure-blob-token-env", "name"));
        command.Options.Add(CreateChoiceValueOption(commandName, "--azure-blob-token-kind", "kind", "bearer", "sas"));
    }

    private static void AddS3SourceOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--s3-bucket", "name"));
        command.Options.Add(CreateValueOption(commandName, "--s3-region", "region"));
        command.Options.Add(CreateValueOption(commandName, "--s3-endpoint", "uri"));
        command.Options.Add(CreateValueOption(commandName, "--s3-prefix", "prefix"));
        command.Options.Add(CreateValueOption(commandName, "--s3-access-key-id-env", "name"));
        command.Options.Add(CreateValueOption(commandName, "--s3-secret-access-key-env", "name"));
        command.Options.Add(CreateValueOption(commandName, "--s3-session-token-env", "name"));
    }

    private static void AddGcsSourceOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--gcs-bucket", "name"));
        command.Options.Add(CreateValueOption(commandName, "--gcs-endpoint", "uri"));
        command.Options.Add(CreateValueOption(commandName, "--gcs-prefix", "prefix"));
        command.Options.Add(CreateValueOption(commandName, "--gcs-token-env", "name"));
        command.Options.Add(CreateValueOption(commandName, "--gcs-user-project", "project"));
    }

    private static void AddGitLabSourceOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--gitlab-project", "path"));
        command.Options.Add(CreateValueOption(commandName, "--gitlab-group", "path"));
        command.Options.Add(CreateValueOption(commandName, "--gitlab-ref", "ref"));
        command.Options.Add(CreateValueOption(commandName, "--gitlab-merge-request", "id"));
        command.Options.Add(CreateValueOption(commandName, "--gitlab-pipeline-id", "id"));
        command.Options.Add(CreateFlagOption(commandName, "--gitlab-include-subgroups"));
        command.Options.Add(CreateFlagOption(commandName, "--gitlab-include-snippets"));
        command.Options.Add(CreateFlagOption(commandName, "--gitlab-include-job-artifacts"));
        command.Options.Add(CreateFlagOption(commandName, "--gitlab-include-job-logs"));
        command.Options.Add(CreateFlagOption(commandName, "--gitlab-include-packages"));
        command.Options.Add(CreateValueOption(commandName, "--gitlab-token-env", "name"));
        command.Options.Add(CreateValueOption(commandName, "--gitlab-api-endpoint", "uri"));
    }

    private static void AddContainerArchiveSourceOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--docker-archive", "path"));
        command.Options.Add(CreateValueOption(commandName, "--oci-archive", "path"));
    }

    private static void AddResultFilterOptions(Command command, string commandName)
    {
        command.Options.Add(CreateChoiceValueOption(commandName, "--results", "value", "unknown", "structurally-valid", "test-credential", "invalid", "active", "inactive", "skipped", "error"));
        command.Options.Add(CreateFlagOption(commandName, "--only-verified"));
    }

    private static void AddScanLimitOptions(Command command, string commandName, bool includeMaxDecodeDepth, bool includeArchiveSizeLimits)
    {
        command.Options.Add(CreateValueOption(commandName, "--max-target-megabytes", "n"));
        if (includeMaxDecodeDepth)
        {
            command.Options.Add(CreateValueOption(commandName, "--max-decode-depth", "n"));
        }

        command.Options.Add(CreateValueOption(commandName, "--max-archive-depth", "n"));
        if (includeArchiveSizeLimits)
        {
            command.Options.Add(CreateValueOption(commandName, "--max-archive-entries", "n"));
            command.Options.Add(CreateValueOption(commandName, "--max-archive-megabytes", "n"));
            command.Options.Add(CreateValueOption(commandName, "--max-archive-ratio", "n"));
        }

        command.Options.Add(CreateValueOption(commandName, "--timeout", "n"));
    }

    private static void AddDiagnosticsOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--diagnostics", "mode[,mode]"));
        command.Options.Add(CreateValueOption(commandName, "--diagnostics-dir", "path"));
    }

    private static void AddBaselineCreateOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--config", "path", "-c"));
        command.Options.Add(CreateValueOption(commandName, "--report-path", "path", "-r"));
        command.Options.Add(CreateValueOption(commandName, "--source", "path"));
        command.Options.Add(CreateValueOption(commandName, "--ignore-path", "path"));
        command.Options.Add(CreateFlagOption(commandName, "--no-ignore"));
        command.Options.Add(CreateValueOption(commandName, "--enable-rule", "id"));
        AddScanLimitOptions(command, commandName, includeMaxDecodeDepth: false, includeArchiveSizeLimits: true);
        AddDiagnosticsOptions(command, commandName);
        command.Options.Add(CreateRedactOption(commandName));
    }

    private static void AddCacheMaintenanceOptions(Command command, string commandName, bool includePruneOptions)
    {
        command.Options.Add(CreateValueOption(commandName, "--cache-dir", "path"));
        command.Options.Add(CreateValueOption(commandName, "--config", "path", "-c"));
        command.Options.Add(CreateChoiceValueOption(commandName, "--cache-mode", "mode", "raw", "secret-hash-only"));
        command.Options.Add(CreateValueOption(commandName, "--max-decode-depth", "n"));
        command.Options.Add(CreateValueOption(commandName, "--max-target-megabytes", "n"));
        command.Options.Add(CreateFlagOption(commandName, "--ignore-gitleaks-allow"));
        if (includePruneOptions)
        {
            command.Options.Add(CreateFlagOption(commandName, "--other-keys"));
            command.Options.Add(CreateValueOption(commandName, "--older-than-days", "n"));
        }
    }

    private static void AddCompatibilityOptions(Command command, string commandName)
    {
        AddCompatibilityReportOptions(command, commandName);
        command.Options.Add(CreateChoiceValueOption(commandName, "--profile", "profile", "picket"));
        command.Options.Add(CreateFlagOption(commandName, "--no-color"));
        command.Options.Add(CreateFlagOption(commandName, "--no-banner"));
        command.Options.Add(CreateValueOption(commandName, "--report-template", "path"));
        command.Options.Add(CreateValueOption(commandName, "--enable-rule", "id"));
        command.Options.Add(CreateValueOption(commandName, "--exit-code", "n"));
        command.Options.Add(CreateFlagOption(commandName, "--ignore-gitleaks-allow"));
    }

    private static void AddCompatibilityReportOptions(Command command, string commandName)
    {
        command.Options.Add(CreateValueOption(commandName, "--baseline-path", "path", "-b"));
        command.Options.Add(CreateValueOption(commandName, "--config", "path", "-c"));
        command.Options.Add(CreateChoiceValueOption(commandName, "--report-format", "json|csv|junit|sarif|template", ["json", "csv", "junit", "sarif", "template"], "-f"));
        command.Options.Add(CreateValueOption(commandName, "--report-path", "path", "-r"));
        command.Options.Add(CreateValueOption(commandName, "--gitleaks-ignore-path", "path", "-i"));
        command.Options.Add(CreateValueOption(commandName, "--log-level", "level", "-l"));
        command.Options.Add(CreateFlagOption(commandName, "--verbose", "-v"));
    }

    private static Option<string?> CreateValueOption(string commandName, string name, string helpName, params string[] aliases)
    {
        var option = new Option<string?>(name, aliases)
        {
            AllowMultipleArgumentsPerToken = true,
            Arity = ArgumentArity.ZeroOrOne,
            Description = CliOptionMetadata.GetOptionDescription(commandName, name),
            HelpName = helpName,
        };
        return option;
    }

    private static Option<string?> CreateChoiceValueOption(string commandName, string name, string helpName, params string[] choices)
    {
        return CreateChoiceValueOption(commandName, name, helpName, choices, []);
    }

    private static Option<string?> CreateChoiceValueOption(string commandName, string name, string helpName, string[] choices, params string[] aliases)
    {
        Option<string?> option = CreateValueOption(commandName, name, helpName, aliases);
        option.CompletionSources.Add(_ => CreateCompletionItems(choices));
        return option;
    }

    private static Option<bool> CreateFlagOption(string commandName, string name, params string[] aliases)
    {
        var option = new Option<bool>(name, aliases)
        {
            Description = CliOptionMetadata.GetOptionDescription(commandName, name),
        };
        return option;
    }

    private static Option<string?> CreateRedactOption(string commandName)
    {
        return CreateValueOption(commandName, "--redact", "n");
    }

    private static void ConfigureHelp(RootCommand rootCommand)
    {
        foreach (Option option in rootCommand.Options)
        {
            if (option is HelpOption { Action: HelpAction helpAction } helpOption)
            {
                helpOption.Action = new PicketHelpAction(helpAction);
                return;
            }
        }
    }

    private static CompletionItem[] CreateCompletionItems(string[] choices)
    {
        var completions = new CompletionItem[choices.Length];
        for (int i = 0; i < choices.Length; i++)
        {
            completions[i] = new CompletionItem(choices[i]);
        }

        return completions;
    }

    private static string[] SplitChoices(string choices)
    {
        return choices.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static void AddOptionalArgument(Command command, string commandName, string name)
    {
        command.Arguments.Add(new Argument<string?>(name)
        {
            Arity = ArgumentArity.ZeroOrOne,
            Description = CliOptionMetadata.GetArgumentDescription(commandName, string.Concat("<", name, ">")),
        });
    }

    private static void AddRequiredArgument(Command command, string commandName, string name)
    {
        command.Arguments.Add(new Argument<string>(name)
        {
            Arity = ArgumentArity.ExactlyOne,
            Description = CliOptionMetadata.GetArgumentDescription(commandName, string.Concat("<", name, ">")),
        });
    }

    private static string[] NormalizeCommandLineArgs(string[] args)
    {
        if (args.Length == 0)
        {
            return ["--help"];
        }

        string[] normalizedArgs;
        if (args[0].Equals("help", StringComparison.OrdinalIgnoreCase))
        {
            if (args.Length == 1)
            {
                return ["--help"];
            }

            normalizedArgs = [.. args[1..], "--help"];
        }
        else
        {
            normalizedArgs = [.. args];
        }

        int commandIndex = FindCommandTokenIndex(normalizedArgs);
        if (commandIndex < 0)
        {
            return normalizedArgs;
        }

        normalizedArgs[commandIndex] = NormalizeRootCommandName(normalizedArgs[commandIndex]);
        if (commandIndex + 1 < normalizedArgs.Length)
        {
            normalizedArgs[commandIndex + 1] = NormalizeSubcommandName(normalizedArgs[commandIndex], normalizedArgs[commandIndex + 1]);
        }

        return normalizedArgs;
    }

    private static int FindCommandTokenIndex(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg.Length == 0)
            {
                continue;
            }

            if (arg[0] == '[')
            {
                continue;
            }

            return arg[0] == '-' || arg[0] == '/' ? -1 : i;
        }

        return -1;
    }

    private static bool CanParseRootCommand(string[] args)
    {
        if (args.Length != 0 && args[0].Length != 0 && args[0][0] == '[')
        {
            return true;
        }

        int commandIndex = FindCommandTokenIndex(args);
        return commandIndex < 0 || IsKnownRootCommand(args[commandIndex]);
    }

    private static bool HasHelpToken(string[] args)
    {
        foreach (string arg in args)
        {
            if (arg.Equals("help", StringComparison.OrdinalIgnoreCase)
                || arg.Equals("--help", StringComparison.Ordinal)
                || arg.Equals("-h", StringComparison.Ordinal)
                || arg.Equals("-?", StringComparison.Ordinal)
                || arg.Equals("/h", StringComparison.OrdinalIgnoreCase)
                || arg.Equals("/?", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsHelpForCommand(string[] args, string command)
    {
        int commandIndex = FindCommandTokenIndex(args);
        return commandIndex >= 0
            && args[commandIndex].Equals(command, StringComparison.OrdinalIgnoreCase)
            && HasHelpToken(args);
    }

    private static string NormalizeRootCommandName(string command)
    {
        if (IsDirectoryCommand(command))
        {
            return command.Equals("dir", StringComparison.OrdinalIgnoreCase) ? "dir" : command.ToLowerInvariant();
        }

        return IsKnownRootCommand(command) ? command.ToLowerInvariant() : command;
    }

    private static string NormalizeSubcommandName(string command, string subcommand)
    {
        if (!IsKnownGroupedCommand(command))
        {
            return subcommand;
        }

        return IsKnownSubcommand(command, subcommand) ? subcommand.ToLowerInvariant() : subcommand;
    }

    private static bool IsKnownRootCommand(string command)
    {
        return command.Equals("scan", StringComparison.OrdinalIgnoreCase)
            || command.Equals("verify", StringComparison.OrdinalIgnoreCase)
            || command.Equals("analyze", StringComparison.OrdinalIgnoreCase)
            || command.Equals("baseline", StringComparison.OrdinalIgnoreCase)
            || command.Equals("cache", StringComparison.OrdinalIgnoreCase)
            || command.Equals("view", StringComparison.OrdinalIgnoreCase)
            || command.Equals("tui", StringComparison.OrdinalIgnoreCase)
            || command.Equals("stdin", StringComparison.OrdinalIgnoreCase)
            || command.Equals("detect", StringComparison.OrdinalIgnoreCase)
            || command.Equals("protect", StringComparison.OrdinalIgnoreCase)
            || command.Equals("rules", StringComparison.OrdinalIgnoreCase)
            || command.Equals("hooks", StringComparison.OrdinalIgnoreCase)
            || command.Equals("git", StringComparison.OrdinalIgnoreCase)
            || command.Equals("version", StringComparison.OrdinalIgnoreCase)
            || IsDirectoryCommand(command);
    }

    private static bool IsKnownGroupedCommand(string command)
    {
        return command.Equals("baseline", StringComparison.Ordinal)
            || command.Equals("cache", StringComparison.Ordinal)
            || command.Equals("rules", StringComparison.Ordinal)
            || command.Equals("hooks", StringComparison.Ordinal);
    }

    private static bool IsKnownSubcommand(string command, string subcommand)
    {
        return command switch
        {
            "baseline" => subcommand.Equals("create", StringComparison.OrdinalIgnoreCase),
            "cache" => subcommand.Equals("stats", StringComparison.OrdinalIgnoreCase)
                || subcommand.Equals("prune", StringComparison.OrdinalIgnoreCase)
                || subcommand.Equals("export", StringComparison.OrdinalIgnoreCase)
                || subcommand.Equals("import", StringComparison.OrdinalIgnoreCase),
            "rules" => subcommand.Equals("check", StringComparison.OrdinalIgnoreCase)
                || subcommand.Equals("test", StringComparison.OrdinalIgnoreCase),
            "hooks" => subcommand.Equals("install", StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
    }
}
