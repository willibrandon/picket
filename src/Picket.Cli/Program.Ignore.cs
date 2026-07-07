using Picket.Compat;
using Picket.Report;
using Picket.Sources;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static GitleaksIgnore LoadGitleaksIgnore(string gitleaksIgnorePath, string source)
    {
        return GitleaksIgnore.LoadExisting([
            gitleaksIgnorePath,
            Path.Combine(gitleaksIgnorePath, ".gitleaksignore"),
            Path.Combine(source, ".gitleaksignore"),
        ]);
    }

    static bool TryLoadPicketIgnore(
        string root,
        IReadOnlyList<string> nativeIgnorePaths,
        bool respectNativeIgnoreFiles,
        [NotNullWhen(true)] out PicketIgnore? picketIgnore)
    {
        if (!respectNativeIgnoreFiles)
        {
            picketIgnore = PicketIgnore.Empty;
            return true;
        }

        try
        {
            picketIgnore = PicketIgnore.LoadExisting(root, nativeIgnorePaths);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(ex.Message);
            picketIgnore = null;
            return false;
        }
    }

    static List<string?> CreateControlFileDisplayPaths(string root, string? reportPath, List<string> reportPaths)
    {
        var displayPaths = new List<string?>();
        if (reportPaths.Count == 0)
        {
            displayPaths.Add(CreateControlFileDisplayPath(root, reportPath));
            return displayPaths;
        }

        for (int i = 0; i < reportPaths.Count; i++)
        {
            displayPaths.Add(CreateControlFileDisplayPath(root, reportPaths[i]));
        }

        return displayPaths;
    }

    static string? CreateControlFileDisplayPath(string root, string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(root))
        {
            return null;
        }

        string relativePath = Path.GetRelativePath(Path.GetFullPath(root), Path.GetFullPath(path));
        if (relativePath.Equals(".", StringComparison.Ordinal)
            || relativePath.StartsWith("..", StringComparison.Ordinal)
            || Path.IsPathRooted(relativePath))
        {
            return null;
        }

        return relativePath.Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');
    }

    static bool IsNativeIgnoreFile(SourceFile file)
    {
        string fileName = Path.GetFileName(file.DisplayPath);
        return fileName.Equals(".picketignore", StringComparison.Ordinal)
            || fileName.Equals(".gitignore", StringComparison.Ordinal)
            || fileName.Equals(".ignore", StringComparison.Ordinal)
            || fileName.Equals(".rgignore", StringComparison.Ordinal)
            || fileName.Equals(".scoutignore", StringComparison.Ordinal)
            || file.DisplayPath.Equals(".git/info/exclude", StringComparison.Ordinal);
    }

    static string? ResolveConfigControlPath(string? configPath, string source)
    {
        if (!string.IsNullOrWhiteSpace(configPath))
        {
            return configPath;
        }

        string? environmentPath = Environment.GetEnvironmentVariable(GitleaksConfigEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(environmentPath))
        {
            return environmentPath;
        }

        string? environmentToml = Environment.GetEnvironmentVariable(GitleaksConfigTomlEnvironmentVariable);
        return string.IsNullOrWhiteSpace(environmentToml) ? Path.Combine(source, ".gitleaks.toml") : null;
    }

    static bool IsControlFile(SourceFile file, params string?[] displayPaths)
    {
        foreach (string? displayPath in displayPaths)
        {
            if (displayPath is not null && file.DisplayPath.Equals(displayPath, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    static bool IsControlDirectoryFile(SourceFile file, string? displayPath)
    {
        if (displayPath is null)
        {
            return false;
        }

        string prefix = displayPath.EndsWith('/') ? displayPath : string.Concat(displayPath, '/');
        return file.DisplayPath.Equals(displayPath, StringComparison.Ordinal)
            || file.DisplayPath.StartsWith(prefix, StringComparison.Ordinal);
    }

    static void WriteReportViewSummary(string reportPath, ReportSummary summary)
    {
        Console.Out.WriteLine($"report: {reportPath}");
        Console.Out.WriteLine($"format: {summary.Format}");
        Console.Out.WriteLine($"findings: {summary.FindingCount}");
        Console.Out.WriteLine($"files: {summary.FileCount}");
        if (summary.Findings.Count == 0)
        {
            return;
        }

        Console.Out.WriteLine();
        Console.Out.WriteLine("findings:");
        int count = Math.Min(summary.Findings.Count, 10);
        for (int i = 0; i < count; i++)
        {
            ReportFindingSummary finding = summary.Findings[i];
            string location = finding.Line == 0 ? finding.Path : $"{finding.Path}:{finding.Line}";
            if (finding.Fingerprint.Length == 0)
            {
                Console.Out.WriteLine($"  {finding.RuleId} {location}");
            }
            else
            {
                Console.Out.WriteLine($"  {finding.RuleId} {location} {finding.Fingerprint}");
            }
        }

        int remaining = summary.Findings.Count - count;
        if (remaining != 0)
        {
            Console.Out.WriteLine($"  ... {remaining} more");
        }
    }

    static void WriteHtmlViewSummary(string reportPath)
    {
        Console.Out.WriteLine($"report: {reportPath}");
        Console.Out.WriteLine("format: html");
        Console.Out.WriteLine("findings: unknown");
        Console.Out.WriteLine("files: unknown");
    }

    static bool TryOpenReport(string reportPath)
    {
        try
        {
            if (!TryValidateOpenReportPath(reportPath, out string? fullPath))
            {
                return false;
            }

            _ = Process.Start(new ProcessStartInfo(fullPath)
            {
                UseShellExecute = true,
            });
            return true;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or Win32Exception)
        {
            Console.Error.WriteLine($"failed to open report: {ex.Message}");
            return false;
        }
    }

    static bool TryValidateOpenReportPath(string reportPath, [NotNullWhen(true)] out string? fullPath)
    {
        fullPath = null;
        try
        {
            fullPath = Path.GetFullPath(reportPath);
            if (!File.Exists(fullPath))
            {
                Console.Error.WriteLine($"refusing to open report: file does not exist: {reportPath}");
                return false;
            }

            FileAttributes attributes = File.GetAttributes(fullPath);
            if ((attributes & FileAttributes.Directory) != 0 || (attributes & FileAttributes.ReparsePoint) != 0)
            {
                Console.Error.WriteLine($"refusing to open report: expected a regular file: {reportPath}");
                return false;
            }

            if (!HasOpenableReportExtension(fullPath))
            {
                Console.Error.WriteLine($"refusing to open report: unsupported report extension: {Path.GetExtension(reportPath)}");
                return false;
            }

            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or NotSupportedException or PathTooLongException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"refusing to open report: {ex.Message}");
            return false;
        }
    }

    static bool HasOpenableReportExtension(string reportPath)
    {
        string extension = Path.GetExtension(reportPath);
        return extension.Equals(".csv", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".htm", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".html", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".json", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".jsonl", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".sarif", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".toon", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".xml", StringComparison.OrdinalIgnoreCase);
    }
}
