using Picket.Analyze;
using Picket.Compat;
using Picket.Engine;
using Picket.Report;
using Picket.Rules;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool TryLoadBaseline(string? baselinePath, [NotNullWhen(true)] out GitleaksBaseline? baseline)
    {
        if (string.IsNullOrWhiteSpace(baselinePath))
        {
            baseline = GitleaksBaseline.Empty;
            return true;
        }

        try
        {
            baseline = GitleaksBaseline.Load(baselinePath);
            return true;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException)
        {
            Console.Error.WriteLine(ex.Message);
            baseline = null;
            return false;
        }
    }

    static bool TryWriteReports(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<SecretRule> rules,
        string? reportPath,
        List<string> reportPaths,
        string? reportFormat,
        string? reportTemplatePath,
        bool nativeReportFormats = false,
        bool scanComplete = true)
    {
        if (!nativeReportFormats || reportPaths.Count <= 1)
        {
            return TryWriteReport(findings, rules, reportPath, reportFormat, reportTemplatePath, nativeReportFormats, scanComplete);
        }

        if (!string.IsNullOrWhiteSpace(reportFormat))
        {
            Console.Error.WriteLine("report format cannot be specified when multiple report paths are specified");
            return false;
        }

        if (!string.IsNullOrWhiteSpace(reportTemplatePath))
        {
            Console.Error.WriteLine("report template cannot be specified when multiple report paths are specified");
            return false;
        }

        bool wroteStdout = false;
        foreach (string path in reportPaths)
        {
            if (string.IsNullOrWhiteSpace(path) || path.Equals("-", StringComparison.Ordinal))
            {
                if (wroteStdout)
                {
                    Console.Error.WriteLine("standard output can be specified only once when multiple report paths are specified");
                    return false;
                }

                wroteStdout = true;
            }

            if (!TryWriteReport(findings, rules, path, reportFormat: null, reportTemplatePath: null, nativeReportFormats, scanComplete))
            {
                return false;
            }
        }

        return true;
    }

    static bool TryWriteAnalysisReports(
        IReadOnlyList<Finding> findings,
        string? reportPath,
        List<string> reportPaths,
        string? reportFormat,
        string? reportTemplatePath,
        IReadOnlyDictionary<string, CredentialAnalysisMetadata>? analysisMetadata)
    {
        if (!string.IsNullOrWhiteSpace(reportTemplatePath))
        {
            Console.Error.WriteLine("report templates are not supported for analyze");
            return false;
        }

        if (reportPaths.Count <= 1)
        {
            return TryWriteAnalysisReport(findings, reportPath, reportFormat, analysisMetadata);
        }

        if (!string.IsNullOrWhiteSpace(reportFormat))
        {
            Console.Error.WriteLine("report format cannot be specified when multiple report paths are specified");
            return false;
        }

        bool wroteStdout = false;
        foreach (string path in reportPaths)
        {
            if (string.IsNullOrWhiteSpace(path) || path.Equals("-", StringComparison.Ordinal))
            {
                if (wroteStdout)
                {
                    Console.Error.WriteLine("standard output can be specified only once when multiple report paths are specified");
                    return false;
                }

                wroteStdout = true;
            }

            if (!TryWriteAnalysisReport(findings, path, reportFormat: null, analysisMetadata))
            {
                return false;
            }
        }

        return true;
    }

    static bool TryWriteAnalysisReport(
        IReadOnlyList<Finding> findings,
        string? reportPath,
        string? reportFormat,
        IReadOnlyDictionary<string, CredentialAnalysisMetadata>? analysisMetadata)
    {
        if (!TryResolveAnalysisReportFormat(reportPath, reportFormat, out string? resolvedReportFormat))
        {
            return false;
        }

        List<CredentialAnalysis> analyses = CredentialAnalyzer.Analyze(findings, analysisMetadata);
        string report = resolvedReportFormat switch
        {
            "json" => CredentialAnalysisReportWriter.WriteJson(analyses),
            "jsonl" => CredentialAnalysisReportWriter.WriteJsonLines(analyses),
            "text" => CredentialAnalysisReportWriter.WriteText(analyses),
            _ => throw new InvalidOperationException($"unsupported analyze report format: {resolvedReportFormat}"),
        };

        return TryWriteTextReport(report, reportPath, announceReportPath: true);
    }

    static bool TryResolveAnalysisReportFormat(string? reportPath, string? reportFormat, [NotNullWhen(true)] out string? resolvedReportFormat)
    {
        if (!string.IsNullOrWhiteSpace(reportFormat))
        {
            resolvedReportFormat = reportFormat.Trim().ToLowerInvariant();
            if (resolvedReportFormat.StartsWith('.'))
            {
                resolvedReportFormat = resolvedReportFormat.Equals(".txt", StringComparison.Ordinal)
                    ? "text"
                    : resolvedReportFormat[1..];
            }

            if (resolvedReportFormat is "json" or "jsonl" or "text")
            {
                return true;
            }

            Console.Error.WriteLine($"unsupported analyze report format: {reportFormat}");
            resolvedReportFormat = null;
            return false;
        }

        resolvedReportFormat = InferAnalysisReportFormat(reportPath);
        return true;
    }

    static string InferAnalysisReportFormat(string? reportPath)
    {
        if (string.IsNullOrWhiteSpace(reportPath) || reportPath.Equals("-", StringComparison.Ordinal))
        {
            return "json";
        }

        string extension = Path.GetExtension(reportPath);
        return extension.ToLowerInvariant() switch
        {
            ".jsonl" => "jsonl",
            ".txt" or ".text" => "text",
            _ => "json",
        };
    }

    static bool TryWriteReport(
        IReadOnlyList<Finding> findings,
        IReadOnlyList<SecretRule> rules,
        string? reportPath,
        string? reportFormat,
        string? reportTemplatePath,
        bool nativeReportFormats = false,
        bool scanComplete = true)
    {
        if (!TryResolveReportFormat(reportPath, reportFormat, reportTemplatePath, nativeReportFormats, out string? resolvedReportFormat))
        {
            return false;
        }

        string report;
        try
        {
            report = resolvedReportFormat switch
            {
                "csv" => nativeReportFormats ? PicketCsvReportWriter.Write(findings, rules) : GitleaksCsvReportWriter.Write(findings),
                "gitlab" => PicketGitLabCodeQualityReportWriter.Write(findings),
                "html" => PicketHtmlReportWriter.Write(findings, rules),
                "junit" => nativeReportFormats ? PicketJunitReportWriter.Write(findings, rules) : GitleaksJunitReportWriter.Write(findings),
                "json" => nativeReportFormats ? PicketJsonReportWriter.Write(findings, rules, scanComplete) : GitleaksJsonReportWriter.Write(findings),
                "jsonl" => PicketJsonlReportWriter.Write(findings, rules),
                "sarif" => nativeReportFormats ? PicketSarifReportWriter.Write(findings, rules, scanComplete) : GitleaksSarifReportWriter.Write(findings, rules),
                "template" => GitleaksTemplateReportWriter.Write(findings, ReadReportTemplate(reportTemplatePath)),
                "toon" => PicketToonReportWriter.Write(findings, rules),
                _ => throw new InvalidOperationException($"unsupported report format: {resolvedReportFormat}"),
            };
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"invalid report template: {ex.Message}");
            return false;
        }

        return TryWriteTextReport(report, reportPath, announceReportPath: nativeReportFormats);
    }

    static bool TryWriteTextReport(string report, string? reportPath, bool announceReportPath = false)
    {
        if (string.IsNullOrWhiteSpace(reportPath) || reportPath.Equals("-", StringComparison.Ordinal))
        {
            Console.Out.Write(report);
            return true;
        }

        try
        {
            if (announceReportPath && !TryCreateReportDirectory(reportPath))
            {
                return false;
            }

            File.WriteAllText(reportPath, report);
            if (announceReportPath)
            {
                Console.Error.WriteLine($"report written: {reportPath}");
            }

            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"failed to write report: {ex.Message}");
            return false;
        }
    }

    static bool TryCreateReportDirectory(string reportPath)
    {
        string? directory = Path.GetDirectoryName(Path.GetFullPath(reportPath));
        if (string.IsNullOrEmpty(directory) || Directory.Exists(directory))
        {
            return true;
        }

        try
        {
            Directory.CreateDirectory(directory);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"failed to create report directory: {ex.Message}");
            return false;
        }
    }

    static string ReadReportTemplate(string? reportTemplatePath)
    {
        if (string.IsNullOrWhiteSpace(reportTemplatePath))
        {
            throw new InvalidDataException("template path cannot be empty");
        }

        return File.ReadAllText(reportTemplatePath);
    }

    static bool TryResolveReportFormat(
        string? reportPath,
        string? reportFormat,
        string? reportTemplatePath,
        bool nativeReportFormats,
        [NotNullWhen(true)] out string? resolvedReportFormat)
    {
        if (!string.IsNullOrWhiteSpace(reportFormat))
        {
            if (!TryNormalizeReportFormat(reportFormat, nativeReportFormats, out resolvedReportFormat))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(reportTemplatePath)
                && !resolvedReportFormat.Equals("template", StringComparison.Ordinal))
            {
                Console.Error.WriteLine("report format must be 'template' if --report-template is specified");
                resolvedReportFormat = null;
                return false;
            }

            return true;
        }

        if (!string.IsNullOrWhiteSpace(reportTemplatePath))
        {
            resolvedReportFormat = "template";
            return true;
        }

        if (string.IsNullOrWhiteSpace(reportPath) || reportPath.Equals("-", StringComparison.Ordinal))
        {
            resolvedReportFormat = "json";
            return true;
        }

        string extension = Path.GetExtension(reportPath);
        if (nativeReportFormats && IsGitLabCodeQualityReportPath(reportPath))
        {
            resolvedReportFormat = "gitlab";
            return true;
        }

        if (extension.Equals(".csv", StringComparison.OrdinalIgnoreCase))
        {
            resolvedReportFormat = "csv";
            return true;
        }

        if (nativeReportFormats && (extension.Equals(".html", StringComparison.OrdinalIgnoreCase) || extension.Equals(".htm", StringComparison.OrdinalIgnoreCase)))
        {
            resolvedReportFormat = "html";
            return true;
        }

        if (nativeReportFormats && IsJunitReportPath(reportPath))
        {
            resolvedReportFormat = "junit";
            return true;
        }

        if (extension.Equals(".json", StringComparison.OrdinalIgnoreCase))
        {
            resolvedReportFormat = "json";
            return true;
        }

        if (nativeReportFormats && extension.Equals(".jsonl", StringComparison.OrdinalIgnoreCase))
        {
            resolvedReportFormat = "jsonl";
            return true;
        }

        if (extension.Equals(".sarif", StringComparison.OrdinalIgnoreCase))
        {
            resolvedReportFormat = "sarif";
            return true;
        }

        if (nativeReportFormats && extension.Equals(".toon", StringComparison.OrdinalIgnoreCase))
        {
            resolvedReportFormat = "toon";
            return true;
        }

        Console.Error.WriteLine($"unknown report format for report path: {reportPath}");
        resolvedReportFormat = null;
        return false;
    }

    static bool TryNormalizeReportFormat(string reportFormat, bool nativeReportFormats, [NotNullWhen(true)] out string? resolvedReportFormat)
    {
        string normalizedReportFormat = reportFormat.Trim().ToLowerInvariant();
        if (nativeReportFormats && normalizedReportFormat.StartsWith('.'))
        {
            if (normalizedReportFormat.Equals(".junit.xml", StringComparison.Ordinal))
            {
                normalizedReportFormat = "junit";
            }
            else if (normalizedReportFormat.Equals(".htm", StringComparison.Ordinal))
            {
                normalizedReportFormat = "html";
            }
            else
            {
                normalizedReportFormat = normalizedReportFormat[1..];
            }
        }

        if (nativeReportFormats && IsGitLabCodeQualityReportFormat(normalizedReportFormat))
        {
            resolvedReportFormat = "gitlab";
            return true;
        }

        if (normalizedReportFormat is "csv" or "json" or "junit" or "sarif" or "template"
            || (nativeReportFormats && normalizedReportFormat.Equals("html", StringComparison.Ordinal))
            || (nativeReportFormats && normalizedReportFormat.Equals("jsonl", StringComparison.Ordinal))
            || (nativeReportFormats && normalizedReportFormat.Equals("toon", StringComparison.Ordinal)))
        {
            resolvedReportFormat = normalizedReportFormat;
            return true;
        }

        Console.Error.WriteLine($"unsupported report format: {reportFormat}");
        resolvedReportFormat = null;
        return false;
    }

    static bool IsGitLabCodeQualityReportFormat(string reportFormat)
    {
        return reportFormat is "gitlab" or "gitlab-code-quality" or "codequality" or "code-quality" or "gl-code-quality";
    }

    static bool IsGitLabCodeQualityReportPath(string reportPath)
    {
        string fileName = Path.GetFileName(reportPath);
        return fileName.Equals("gl-code-quality-report.json", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".gitlab-code-quality.json", StringComparison.OrdinalIgnoreCase);
    }

    static bool IsJunitReportPath(string reportPath)
    {
        string fileName = Path.GetFileName(reportPath);
        return fileName.EndsWith(".junit.xml", StringComparison.OrdinalIgnoreCase);
    }

    static bool IsHtmlReportPath(string reportPath)
    {
        string extension = Path.GetExtension(reportPath);
        return extension.Equals(".html", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".htm", StringComparison.OrdinalIgnoreCase);
    }
}
