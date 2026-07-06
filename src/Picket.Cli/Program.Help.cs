namespace Picket;

internal static partial class Program
{
    static void WriteHelp()
    {
        Console.Out.WriteLine("picket - bootstrap secrets scanner");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket scan [path] [-c path] [-f json|jsonl|csv|junit|html|gitlab|sarif|toon] [-r path]... [--profile picket] [--source path] [--ignore-path path] [--no-ignore] [--cache-dir path] [--cache-mode raw|secret-hash-only] [--enable-rule id] [--verify] [--github-api-endpoint uri] [--github-api-proxy uri] [--live-tls-mode system|tls12-plus] [--live-rate-limit-ms n] [--live-provider-rate-limit-ms n] [--allow-non-public-endpoints] [--results value] [--only-verified] [--max-target-megabytes n] [--max-archive-depth n] [--max-archive-entries n] [--max-archive-megabytes n] [--max-archive-ratio n] [--timeout n] [--diagnostics mode[,mode]] [--diagnostics-dir path]");
        Console.Out.WriteLine("  picket verify [path] [-c path] [-f json|jsonl|csv|junit|html|gitlab|sarif|toon] [-r path] [--profile picket] [--source path] [--cache-dir path] [--cache-mode raw|secret-hash-only] [--offline|--live] [--github-api-endpoint uri] [--github-api-proxy uri] [--live-tls-mode system|tls12-plus] [--live-rate-limit-ms n] [--live-provider-rate-limit-ms n] [--allow-non-public-endpoints] [--results value] [--only-verified] [--max-target-megabytes n] [--max-archive-depth n] [--max-archive-entries n] [--max-archive-megabytes n] [--max-archive-ratio n] [--timeout n] [--diagnostics mode[,mode]] [--diagnostics-dir path]");
        Console.Out.WriteLine("  picket analyze [path] [-c path] [-f json|jsonl|text] [-r path] [--profile picket] [--source path] [--cache-dir path] [--cache-mode raw|secret-hash-only] [--offline|--live] [--github-api-endpoint uri] [--github-api-proxy uri] [--live-tls-mode system|tls12-plus] [--live-rate-limit-ms n] [--live-provider-rate-limit-ms n] [--allow-non-public-endpoints] [--results value] [--only-verified] [--max-target-megabytes n] [--max-archive-depth n] [--max-archive-entries n] [--max-archive-megabytes n] [--max-archive-ratio n] [--timeout n] [--diagnostics mode[,mode]] [--diagnostics-dir path]");
        Console.Out.WriteLine("  picket baseline create [path] [-c path] [-r path] [--source path] [--ignore-path path] [--no-ignore] [--enable-rule id] [--max-target-megabytes n] [--max-archive-depth n] [--max-archive-entries n] [--max-archive-megabytes n] [--max-archive-ratio n] [--timeout n] [--diagnostics mode[,mode]] [--diagnostics-dir path] [--redact[=n]]");
        Console.Out.WriteLine("  picket cache stats [source] --cache-dir path [-c path] [--cache-mode raw|secret-hash-only] [--max-decode-depth n] [--max-target-megabytes n] [--ignore-gitleaks-allow]");
        Console.Out.WriteLine("  picket cache prune [source] --cache-dir path [-c path] [--cache-mode raw|secret-hash-only] [--other-keys] [--older-than-days n] [--max-decode-depth n] [--max-target-megabytes n] [--ignore-gitleaks-allow]");
        Console.Out.WriteLine("  picket cache export [source] --cache-dir path --output path [-c path] [--cache-mode raw|secret-hash-only] [--max-decode-depth n] [--max-target-megabytes n] [--ignore-gitleaks-allow]");
        Console.Out.WriteLine("  picket cache import [source] --cache-dir path --input path [-c path] [--cache-mode raw|secret-hash-only] [--max-decode-depth n] [--max-target-megabytes n] [--ignore-gitleaks-allow]");
        Console.Out.WriteLine("  picket git [repo] [-b path] [-c path] [-f json|csv|junit|sarif|template] [-r path] [-i path] [-l level] [-v] [--profile picket] [--no-color] [--no-banner] [--report-template path] [--enable-rule id] [--exit-code n] [--ignore-gitleaks-allow] [--log-opts value] [--platform value] [--staged] [--pre-commit] [--max-target-megabytes n] [--max-archive-depth n] [--max-archive-entries n] [--max-archive-megabytes n] [--max-archive-ratio n] [--timeout n] [--diagnostics mode[,mode]] [--diagnostics-dir path] [--redact[=n]]");
        Console.Out.WriteLine("  picket dir <path> [-b path] [-c path] [-f json|csv|junit|sarif|template] [-r path] [-i path] [-l level] [-v] [--profile picket] [--no-color] [--no-banner] [--report-template path] [--enable-rule id] [--exit-code n] [--follow-symlinks] [--ignore-gitleaks-allow] [--max-target-megabytes n] [--max-archive-depth n] [--max-archive-entries n] [--max-archive-megabytes n] [--max-archive-ratio n] [--timeout n] [--diagnostics mode[,mode]] [--diagnostics-dir path] [--redact[=n]]");
        Console.Out.WriteLine("  picket stdin [-b path] [-c path] [-f json|csv|junit|sarif|template] [-r path] [-l level] [-v] [--profile picket] [--no-color] [--no-banner] [--report-template path] [--enable-rule id] [--exit-code n] [--ignore-gitleaks-allow] [--max-decode-depth n] [--max-archive-depth n] [--max-target-megabytes n] [--timeout n] [--diagnostics mode[,mode]] [--diagnostics-dir path] [--redact[=n]]");
        Console.Out.WriteLine("  picket rules check [source] [-c path] [--profile picket] [--print-config]");
        Console.Out.WriteLine("  picket rules test <rule-id> [-c path] [-f json|jsonl|csv|junit|html|gitlab|sarif|toon] [-r path] [--profile picket] [--source path] [--path path] [--print-config] [--ignore-gitleaks-allow] [--max-decode-depth n] [--max-target-megabytes n] [--redact[=n]] [--] <input>");
        Console.Out.WriteLine("  picket hooks install [pre-commit|pre-push|pre-receive|all] [--repo path] [--force] [--command path] [-c path] [-b path] [--max-target-megabytes n] [--redact[=n]]");
        Console.Out.WriteLine("  picket view <report> [--open]");
        Console.Out.WriteLine("  picket version");
    }

    static void WriteScanHelp()
    {
        Console.Out.WriteLine("picket scan - native filesystem scan");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket scan [path] [-c path] [-f json|jsonl|csv|junit|html|gitlab|sarif|toon] [-r path]... [--profile picket] [--source path] [--ignore-path path] [--no-ignore] [--cache-dir path] [--cache-mode raw|secret-hash-only] [--enable-rule id] [--verify] [--github-api-endpoint uri] [--github-api-proxy uri] [--live-tls-mode system|tls12-plus] [--live-rate-limit-ms n] [--live-provider-rate-limit-ms n] [--allow-non-public-endpoints] [--results unknown|structurally-valid|test-credential|invalid|active|inactive|skipped|error] [--only-verified] [--max-target-megabytes n] [--max-archive-depth n] [--max-archive-entries n] [--max-archive-megabytes n] [--max-archive-ratio n] [--timeout n] [--diagnostics mode[,mode]] [--diagnostics-dir path]");
    }

    static void WriteVerifyHelp()
    {
        Console.Out.WriteLine("picket verify - run native verification for detected findings");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket verify [path] [-c path] [-f json|jsonl|csv|junit|html|gitlab|sarif|toon] [-r path] [--profile picket] [--source path] [--cache-dir path] [--cache-mode raw|secret-hash-only] [--offline|--live] [--github-api-endpoint uri] [--github-api-proxy uri] [--live-tls-mode system|tls12-plus] [--live-rate-limit-ms n] [--live-provider-rate-limit-ms n] [--allow-non-public-endpoints] [--results unknown|structurally-valid|test-credential|invalid|active|inactive|skipped|error] [--only-verified] [--max-target-megabytes n] [--max-archive-depth n] [--max-archive-entries n] [--max-archive-megabytes n] [--max-archive-ratio n] [--timeout n] [--diagnostics mode[,mode]] [--diagnostics-dir path]");
    }

    static void WriteAnalyzeHelp()
    {
        Console.Out.WriteLine("picket analyze - write incident-response analysis for detected findings");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket analyze [path] [-c path] [-f json|jsonl|text] [-r path] [--profile picket] [--source path] [--cache-dir path] [--cache-mode raw|secret-hash-only] [--offline|--live] [--github-api-endpoint uri] [--github-api-proxy uri] [--live-tls-mode system|tls12-plus] [--live-rate-limit-ms n] [--live-provider-rate-limit-ms n] [--allow-non-public-endpoints] [--results unknown|structurally-valid|test-credential|invalid|active|inactive|skipped|error] [--only-verified] [--max-target-megabytes n] [--max-archive-depth n] [--max-archive-entries n] [--max-archive-megabytes n] [--max-archive-ratio n] [--timeout n] [--diagnostics mode[,mode]] [--diagnostics-dir path]");
    }

    static void WriteBaselineHelp()
    {
        Console.Out.WriteLine("picket baseline - baseline workflow commands");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket baseline create [path] [-c path] [-r path] [--source path] [--ignore-path path] [--no-ignore] [--enable-rule id] [--max-target-megabytes n] [--max-archive-depth n] [--max-archive-entries n] [--max-archive-megabytes n] [--max-archive-ratio n] [--timeout n] [--diagnostics mode[,mode]] [--diagnostics-dir path] [--redact[=n]]");
    }

    static void WriteBaselineCreateHelp()
    {
        Console.Out.WriteLine("picket baseline create - write a Gitleaks-compatible baseline JSON report");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket baseline create [path] [-c path] [-r path] [--source path] [--ignore-path path] [--no-ignore] [--enable-rule id] [--max-target-megabytes n] [--max-archive-depth n] [--max-archive-entries n] [--max-archive-megabytes n] [--max-archive-ratio n] [--timeout n] [--diagnostics mode[,mode]] [--diagnostics-dir path] [--redact[=n]]");
    }

    static void WriteCacheHelp()
    {
        Console.Out.WriteLine("picket cache - native scan cache maintenance");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket cache stats [source] --cache-dir path [-c path] [--cache-mode raw|secret-hash-only] [--max-decode-depth n] [--max-target-megabytes n] [--ignore-gitleaks-allow]");
        Console.Out.WriteLine("  picket cache prune [source] --cache-dir path [-c path] [--cache-mode raw|secret-hash-only] [--other-keys] [--older-than-days n] [--max-decode-depth n] [--max-target-megabytes n] [--ignore-gitleaks-allow]");
        Console.Out.WriteLine("  picket cache export [source] --cache-dir path --output path [-c path] [--cache-mode raw|secret-hash-only] [--max-decode-depth n] [--max-target-megabytes n] [--ignore-gitleaks-allow]");
        Console.Out.WriteLine("  picket cache import [source] --cache-dir path --input path [-c path] [--cache-mode raw|secret-hash-only] [--max-decode-depth n] [--max-target-megabytes n] [--ignore-gitleaks-allow]");
    }

    static void WriteCacheStatsHelp()
    {
        Console.Out.WriteLine("picket cache stats - summarize native scan cache entries");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket cache stats [source] --cache-dir path [-c path] [--cache-mode raw|secret-hash-only] [--max-decode-depth n] [--max-target-megabytes n] [--ignore-gitleaks-allow]");
    }

    static void WriteCachePruneHelp()
    {
        Console.Out.WriteLine("picket cache prune - delete native scan cache entries");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket cache prune [source] --cache-dir path [-c path] [--cache-mode raw|secret-hash-only] [--other-keys] [--older-than-days n] [--max-decode-depth n] [--max-target-megabytes n] [--ignore-gitleaks-allow]");
    }

    static void WriteCacheExportHelp()
    {
        Console.Out.WriteLine("picket cache export - write active native scan cache entries to a portable archive");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket cache export [source] --cache-dir path --output path [-c path] [--cache-mode raw|secret-hash-only] [--max-decode-depth n] [--max-target-megabytes n] [--ignore-gitleaks-allow]");
    }

    static void WriteCacheImportHelp()
    {
        Console.Out.WriteLine("picket cache import - restore active native scan cache entries from a portable archive");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket cache import [source] --cache-dir path --input path [-c path] [--cache-mode raw|secret-hash-only] [--max-decode-depth n] [--max-target-megabytes n] [--ignore-gitleaks-allow]");
    }

    static void WriteViewHelp()
    {
        Console.Out.WriteLine("picket view - summarize or open a local report");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket view <report> [--open]");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Formats:");
        Console.Out.WriteLine("  Picket JSON/JSONL, Gitleaks JSON, TruffleHog JSON/JSONL, GitLab code-quality JSON, SARIF, HTML");
    }

    static void WriteRulesHelp()
    {
        Console.Out.WriteLine("picket rules - rule pack commands");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket rules check [source] [-c path] [--profile picket] [--print-config]");
        Console.Out.WriteLine("  picket rules test <rule-id> [-c path] [-f json|jsonl|csv|junit|html|gitlab|sarif|toon] [-r path] [--profile picket] [--source path] [--path path] [--print-config] [--ignore-gitleaks-allow] [--max-decode-depth n] [--max-target-megabytes n] [--redact[=n]] [--] <input>");
    }

    static void WriteRulesCheckHelp()
    {
        Console.Out.WriteLine("picket rules check - validate a resolved rule pack");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket rules check [source] [-c path] [--profile picket] [--print-config]");
    }

    static void WriteRulesTestHelp()
    {
        Console.Out.WriteLine("picket rules test - scan sample text with a single rule");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket rules test <rule-id> [-c path] [-f json|jsonl|csv|junit|html|gitlab|sarif|toon] [-r path] [--profile picket] [--source path] [--path path] [--print-config] [--ignore-gitleaks-allow] [--max-decode-depth n] [--max-target-megabytes n] [--redact[=n]] [--] <input>");
    }

    static void WriteHooksHelp()
    {
        Console.Out.WriteLine("picket hooks - install local git hooks");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket hooks install [pre-commit|pre-push|pre-receive|all] [--repo path] [--force] [--command path] [-c path] [-b path] [--max-target-megabytes n] [--redact[=n]]");
    }

    static void WriteHooksInstallHelp()
    {
        Console.Out.WriteLine("picket hooks install - write managed pre-commit, pre-push, and pre-receive hooks");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Usage:");
        Console.Out.WriteLine("  picket hooks install [pre-commit|pre-push|pre-receive|all] [--repo path] [--force] [--command path] [-c path] [-b path] [--max-target-megabytes n] [--redact[=n]]");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Defaults:");
        Console.Out.WriteLine("  Installs pre-commit when no hook name is provided and uses --redact=100 in generated hooks.");
    }
}
