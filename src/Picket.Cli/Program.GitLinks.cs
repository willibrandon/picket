using Picket.Engine;
using Picket.Sources;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.ExceptionServices;

namespace Picket;

internal static partial class Program
{
    static bool IsDirectoryCommand(string command)
    {
        return command.Equals("dir", StringComparison.OrdinalIgnoreCase)
            || command.Equals("file", StringComparison.OrdinalIgnoreCase)
            || command.Equals("directory", StringComparison.OrdinalIgnoreCase);
    }

    static List<Finding> ScanGitFragment(
        GitPatchFragment fragment,
        CompiledRuleSet rules,
        bool ignoreGitleaksAllow,
        long? maxTargetBytes,
        int maxDecodeDepth,
        bool nativeMode,
        long timeoutTimestamp,
        string scmPlatform,
        string remoteUrl,
        CompatibilityScanMetrics? metrics,
        out bool timedOut)
    {
        if (IsTimedOut(timeoutTimestamp))
        {
            timedOut = true;
            return [];
        }

        metrics?.AddBytes(fragment.Input.Length);
        IReadOnlyList<Finding> fragmentFindings = SecretScanner.Scan(new ScanRequest(
            fragment.Input,
            fragment.FilePath,
            rules,
            ignoreGitleaksAllow,
            fragment.Commit,
            maxDecodeDepth,
            maxTargetBytes,
            useGitleaksMaxTargetSemantics: !nativeMode,
            isCancellationRequested: () => IsTimedOut(timeoutTimestamp))
        {
            EnableNativeDetectors = nativeMode,
            EnableNativePredicates = nativeMode,
            EnableRandomnessScoring = nativeMode,
            PositionKind = nativeMode
                ? FindingPositionKind.UnicodeCodePointsExclusive
                : FindingPositionKind.GitleaksUtf8BytesInclusive,
        });
        if (IsTimedOut(timeoutTimestamp))
        {
            timedOut = true;
            return [];
        }

        timedOut = false;
        var findings = new List<Finding>(fragmentFindings.Count);
        foreach (Finding finding in fragmentFindings)
        {
            findings.Add(MapGitFinding(finding, fragment, scmPlatform, remoteUrl));
        }

        return findings;
    }

    static (int CommitCount, int FragmentCount, bool TimedOut) ScanGitFragments(
        GitScanOptions sourceOptions,
        int maxDegreeOfParallelism,
        Func<GitPatchFragment, (IReadOnlyList<Finding> Findings, bool TimedOut)> fragmentScanner,
        Action<int, IReadOnlyList<Finding>> findingsSink)
    {
        ArgumentNullException.ThrowIfNull(sourceOptions);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxDegreeOfParallelism, 1);
        ArgumentNullException.ThrowIfNull(fragmentScanner);
        ArgumentNullException.ThrowIfNull(findingsSink);

        if (maxDegreeOfParallelism == 1)
        {
            int sequentialFragmentCount = 0;
            bool timedOut = false;
            int sequentialCommitCount = GitSource.Enumerate(
                sourceOptions,
                fragment =>
                {
                    int fragmentIndex = sequentialFragmentCount++;
                    (IReadOnlyList<Finding> findings, bool fragmentTimedOut) = fragmentScanner(fragment);
                    timedOut |= fragmentTimedOut;
                    if (!fragmentTimedOut)
                    {
                        findingsSink(fragmentIndex, findings);
                    }
                });
            return (sequentialCommitCount, sequentialFragmentCount, timedOut);
        }

        using var fragments =
            new BlockingCollection<(int Index, GitPatchFragment Fragment)>(maxDegreeOfParallelism);
        object findingsLock = new();
        Exception? workerException = null;
        int timedOutFlag = 0;
        var workers = new List<Task>(maxDegreeOfParallelism);

        void StartWorker()
        {
            workers.Add(Task.Run(
                () =>
                {
                    foreach ((int fragmentIndex, GitPatchFragment fragment) in fragments.GetConsumingEnumerable())
                    {
                        if (Volatile.Read(ref workerException) is not null)
                        {
                            continue;
                        }

                        try
                        {
                            (IReadOnlyList<Finding> findings, bool fragmentTimedOut) = fragmentScanner(fragment);
                            if (fragmentTimedOut)
                            {
                                Interlocked.Exchange(ref timedOutFlag, 1);
                                continue;
                            }

                            lock (findingsLock)
                            {
                                findingsSink(fragmentIndex, findings);
                            }
                        }
                        catch (Exception exception)
                        {
                            Interlocked.CompareExchange(ref workerException, exception, null);
                        }
                    }
                }));
        }

        int fragmentCount = 0;
        int commitCount;
        try
        {
            commitCount = GitSource.Enumerate(
                sourceOptions,
                fragment =>
                {
                    int fragmentIndex = fragmentCount++;
                    if (workers.Count < maxDegreeOfParallelism)
                    {
                        StartWorker();
                    }

                    fragments.Add((fragmentIndex, fragment));
                });
        }
        finally
        {
            fragments.CompleteAdding();
            Task.WaitAll([.. workers]);
        }

        if (workerException is not null)
        {
            ExceptionDispatchInfo.Throw(workerException);
        }

        return (commitCount, fragmentCount, timedOutFlag != 0);
    }

    static Finding MapGitFinding(Finding finding, GitPatchFragment fragment, string scmPlatform, string remoteUrl)
    {
        int startLine = MapGitLine(fragment, finding.StartLine);
        int endLine = MapGitLine(fragment, finding.EndLine);
        string link = CreateScmLink(scmPlatform, remoteUrl, finding.File, fragment.Commit, startLine, endLine);
        Finding mapped = new(
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
            finding.Randomness,
            finding.PositionKind,
            finding.RequiredFindings,
            finding.ProvenanceType);
        return mapped.WithNativeFingerprint(finding.NativeFingerprint);
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
