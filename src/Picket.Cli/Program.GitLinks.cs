using Picket.Engine;
using Picket.Sources;
using System.Diagnostics;

namespace Picket;

internal static partial class Program
{
    static bool IsDirectoryCommand(string command)
    {
        return command.Equals("dir", StringComparison.OrdinalIgnoreCase)
            || command.Equals("file", StringComparison.OrdinalIgnoreCase)
            || command.Equals("directory", StringComparison.OrdinalIgnoreCase);
    }

    static List<Finding> ScanGitFragments(
        IReadOnlyList<GitPatchFragment> fragments,
        CompiledRuleSet rules,
        bool ignoreGitleaksAllow,
        long? maxTargetBytes,
        int maxDecodeDepth,
        bool nativeMode,
        long timeoutTimestamp,
        string scmPlatform,
        string remoteUrl,
        out bool timedOut)
    {
        timedOut = false;
        var findings = new List<Finding>();
        foreach (GitPatchFragment fragment in fragments)
        {
            if (IsTimedOut(timeoutTimestamp))
            {
                timedOut = true;
                break;
            }

            IReadOnlyList<Finding> fragmentFindings = SecretScanner.Scan(new ScanRequest(
                fragment.Input,
                fragment.FilePath,
                rules,
                ignoreGitleaksAllow,
                fragment.Commit,
                maxDecodeDepth,
                maxTargetBytes,
                isCancellationRequested: () => IsTimedOut(timeoutTimestamp))
            {
                EnableRandomnessScoring = nativeMode,
            });
            if (IsTimedOut(timeoutTimestamp))
            {
                timedOut = true;
                break;
            }

            foreach (Finding finding in fragmentFindings)
            {
                findings.Add(MapGitFinding(finding, fragment, scmPlatform, remoteUrl));
            }
        }

        return findings;
    }

    static Finding MapGitFinding(Finding finding, GitPatchFragment fragment, string scmPlatform, string remoteUrl)
    {
        int startLine = MapGitLine(fragment, finding.StartLine);
        int endLine = MapGitLine(fragment, finding.EndLine);
        string link = CreateScmLink(scmPlatform, remoteUrl, finding.File, fragment.Commit, startLine, endLine);
        return new Finding(
            finding.RuleID,
            finding.Description,
            startLine,
            endLine,
            finding.StartColumn,
            finding.EndColumn,
            finding.Match,
            finding.Secret,
            finding.File,
            finding.SymlinkFile,
            fragment.Commit,
            finding.Entropy,
            fragment.Author,
            fragment.Email,
            fragment.Date,
            fragment.Message,
            finding.Tags,
            CreateFingerprint(fragment.Commit, finding.File, finding.RuleID, startLine),
            finding.Line,
            link,
            finding.SecretSha256,
            finding.MatchSha256,
            finding.ValidationState,
            finding.BlobSha256,
            finding.DecodePath,
            finding.Randomness);
    }

    static void CreateGitLinkContext(string root, bool disableLinks, string? platform, out string scmPlatform, out string remoteUrl)
    {
        scmPlatform = disableLinks ? "none" : NormalizeScmPlatform(platform);
        remoteUrl = string.Empty;
        if (scmPlatform == "none")
        {
            return;
        }

        if (!TryReadGitRemoteUrl(root, out remoteUrl))
        {
            return;
        }

        if (scmPlatform == "unknown")
        {
            scmPlatform = GetScmPlatformFromRemoteUrl(remoteUrl);
        }
    }

    static bool TryReadGitRemoteUrl(string root, out string remoteUrl)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("git")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            },
        };
        AddGitRemoteArguments(process.StartInfo, "-C", root, "ls-remote", "--quiet", "--get-url");
        try
        {
            if (!process.Start())
            {
                remoteUrl = string.Empty;
                return false;
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            remoteUrl = string.Empty;
            return false;
        }

        string output = process.StandardOutput.ReadToEnd().Trim();
        _ = process.StandardError.ReadToEnd();
        process.WaitForExit();
        remoteUrl = process.ExitCode == 0 ? NormalizeRemoteUrl(output) : string.Empty;
        return remoteUrl.Length != 0;
    }

    static void AddGitRemoteArguments(ProcessStartInfo startInfo, params string[] arguments)
    {
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
    }

    static string NormalizeRemoteUrl(string remoteUrl)
    {
        if (TryNormalizeSshRemoteUrl(remoteUrl, out string sshRemoteUrl))
        {
            remoteUrl = sshRemoteUrl;
        }

        if (remoteUrl.EndsWith(".git", StringComparison.Ordinal))
        {
            remoteUrl = remoteUrl[..^".git".Length];
        }

        if (!Uri.TryCreate(remoteUrl, UriKind.Absolute, out Uri? uri) || uri.UserInfo.Length == 0)
        {
            return remoteUrl;
        }

        var builder = new UriBuilder(uri)
        {
            UserName = string.Empty,
            Password = string.Empty,
        };
        return builder.Uri.AbsoluteUri.TrimEnd('/');
    }

    static bool TryNormalizeSshRemoteUrl(string remoteUrl, out string normalizedRemoteUrl)
    {
        const string prefix = "git@";
        if (!remoteUrl.StartsWith(prefix, StringComparison.Ordinal))
        {
            normalizedRemoteUrl = string.Empty;
            return false;
        }

        int separatorIndex = remoteUrl.IndexOf(':', prefix.Length);
        if (separatorIndex < 0)
        {
            normalizedRemoteUrl = string.Empty;
            return false;
        }

        string host = remoteUrl[prefix.Length..separatorIndex];
        string path = remoteUrl[(separatorIndex + 1)..];
        int pathSlashIndex = path.IndexOf('/');
        if (pathSlashIndex > 0 && IsAllDigits(path.AsSpan(0, pathSlashIndex)))
        {
            path = path[(pathSlashIndex + 1)..];
        }

        if (host.Length == 0 || path.Length == 0)
        {
            normalizedRemoteUrl = string.Empty;
            return false;
        }

        normalizedRemoteUrl = $"https://{host}/{path}";
        return true;
    }

    static bool IsAllDigits(ReadOnlySpan<char> value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            if (!char.IsDigit(value[i]))
            {
                return false;
            }
        }

        return value.Length != 0;
    }

    static string CreateScmLink(string scmPlatform, string remoteUrl, string filePath, string commit, int startLine, int endLine)
    {
        if (commit.Length == 0 || remoteUrl.Length == 0 || scmPlatform is "unknown" or "none")
        {
            return string.Empty;
        }

        bool hasInnerPath = filePath.Contains('!');
        filePath = CleanLinkFilePath(filePath);
        return scmPlatform switch
        {
            "github" => CreateGitHubLink(remoteUrl, commit, filePath, startLine, endLine, hasInnerPath),
            "gitlab" => CreateGitLabLink(remoteUrl, commit, filePath, startLine, endLine, hasInnerPath),
            "azuredevops" => CreateAzureDevOpsLink(remoteUrl, commit, filePath, startLine, endLine, hasInnerPath),
            "gitea" => CreateGiteaLink(remoteUrl, commit, filePath, startLine, endLine, hasInnerPath),
            "bitbucket" => CreateBitbucketLink(remoteUrl, commit, filePath, startLine, endLine, hasInnerPath),
            _ => string.Empty,
        };
    }

    static string CreateGitHubLink(string remoteUrl, string commit, string filePath, int startLine, int endLine, bool hasInnerPath)
    {
        string link = $"{remoteUrl}/blob/{commit}/{filePath}";
        if (hasInnerPath)
        {
            return link;
        }

        if (IsPlainDisplaySource(filePath))
        {
            link += "?plain=1";
        }

        return AppendLineFragment(link, startLine, endLine, "#L", "-L");
    }

    static string CreateGitLabLink(string remoteUrl, string commit, string filePath, int startLine, int endLine, bool hasInnerPath)
    {
        string link = $"{remoteUrl}/blob/{commit}/{filePath}";
        return hasInnerPath ? link : AppendLineFragment(link, startLine, endLine, "#L", "-");
    }

    static string CreateAzureDevOpsLink(string remoteUrl, string commit, string filePath, int startLine, int endLine, bool hasInnerPath)
    {
        string link = $"{remoteUrl}/commit/{commit}?path=/{filePath}";
        if (hasInnerPath)
        {
            return link;
        }

        if (startLine != 0)
        {
            link += $"&line={startLine}";
        }

        if (endLine != startLine)
        {
            link += $"&lineEnd={endLine}";
        }

        return link + "&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files";
    }

    static string CreateGiteaLink(string remoteUrl, string commit, string filePath, int startLine, int endLine, bool hasInnerPath)
    {
        string link = $"{remoteUrl}/src/commit/{commit}/{filePath}";
        if (hasInnerPath)
        {
            return link;
        }

        if (IsPlainDisplaySource(filePath))
        {
            link += "?display=source";
        }

        return AppendLineFragment(link, startLine, endLine, "#L", "-L");
    }

    static string CreateBitbucketLink(string remoteUrl, string commit, string filePath, int startLine, int endLine, bool hasInnerPath)
    {
        string link = $"{remoteUrl}/src/{commit}/{filePath}";
        return hasInnerPath ? link : AppendLineFragment(link, startLine, endLine, "#lines-", ":");
    }

    static string AppendLineFragment(string link, int startLine, int endLine, string startPrefix, string endPrefix)
    {
        if (startLine != 0)
        {
            link += $"{startPrefix}{startLine}";
        }

        if (endLine != startLine)
        {
            link += $"{endPrefix}{endLine}";
        }

        return link;
    }

    static string CleanLinkFilePath(string filePath)
    {
        int innerPathIndex = filePath.IndexOf('!');
        if (innerPathIndex >= 0)
        {
            filePath = filePath[..innerPathIndex];
        }

        return filePath.Replace("%", "%25", StringComparison.Ordinal).Replace(" ", "%20", StringComparison.Ordinal);
    }

    static bool IsPlainDisplaySource(string filePath)
    {
        string extension = Path.GetExtension(filePath);
        return extension.Equals(".ipynb", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".md", StringComparison.OrdinalIgnoreCase);
    }

    static int MapGitLine(GitPatchFragment fragment, int line)
    {
        return line == 0 ? 0 : fragment.StartLine + line - 1;
    }

    static string CreateFingerprint(string commit, string fileName, string ruleId, int startLine)
    {
        return commit.Length == 0
            ? $"{fileName}:{ruleId}:{startLine}"
            : $"{commit}:{fileName}:{ruleId}:{startLine}";
    }
}
