using Picket.Rules;
using Scout.Text.Regex;
using System.Text;

namespace Picket.Engine;

/// <summary>
/// Byte-oriented secret scanner.
/// </summary>
public sealed class SecretScanner
{
    private static readonly List<CompiledAllowlist> s_emptyAllowlists = [];

    /// <summary>
    /// Scans a byte buffer and returns findings in rule evaluation order.
    /// </summary>
    public static IReadOnlyList<Finding> Scan(ScanRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        ReadOnlySpan<byte> originalInput = request.Input.Span;
        Func<bool>? isCancellationRequested = CreateCancellationPredicate(request);
        if (IsCancellationRequested(isCancellationRequested))
        {
            return [];
        }

        byte[] fileNameBytes = Encoding.UTF8.GetBytes(request.FileName);
        byte[] windowsFileNameBytes = CreateWindowsFileNameBytes(request.FileName);
        var blobIdentity = new SourceBlobIdentity(request.Input, request.BlobSha256);
        SourceLineIndex originalLineIndex = SourceLineIndex.Create(originalInput, request.SourceStartLine, request.SourceStartColumn);
        var findings = new List<Finding>();

        ScanPass(
            originalInput,
            originalInput,
            originalLineIndex,
            null,
            request.FileName,
            fileNameBytes,
            windowsFileNameBytes,
            request.RuleSet,
            request.IgnoreGitleaksAllow,
            request.Commit,
            request.MaxTargetBytes,
            request.SymlinkFile,
            blobIdentity,
            findings,
            request.EnableRandomnessScoring,
            isCancellationRequested);

        if (request.MaxDecodeDepth == 0
            || IsTooLargeForContentScan(originalInput.Length, request.MaxTargetBytes)
            || IsCancellationRequested(isCancellationRequested))
        {
            return CompleteScan(request, findings);
        }

        DecodedInput current = DecodedInput.CreateOriginal(originalInput);
        for (int depth = 0; depth < request.MaxDecodeDepth; depth++)
        {
            bool enableCSharpStringConcatenation = depth == 0
                && request.EnableCSharpStringConcatenation
                && IsCSharpSourceFile(request.FileName);
            DecodedInput? decoded = SecretDecoder.Decode(current, enableCSharpStringConcatenation);
            if (decoded is null)
            {
                break;
            }

            ScanPass(
                decoded.Bytes,
                originalInput,
                originalLineIndex,
                decoded,
                request.FileName,
                fileNameBytes,
                windowsFileNameBytes,
                request.RuleSet,
                request.IgnoreGitleaksAllow,
                request.Commit,
                request.MaxTargetBytes,
                request.SymlinkFile,
                blobIdentity,
                findings,
                request.EnableRandomnessScoring,
                isCancellationRequested);
            if (IsTooLargeForContentScan(decoded.Bytes.Length, request.MaxTargetBytes)
                || IsCancellationRequested(isCancellationRequested))
            {
                break;
            }

            current = decoded;
        }

        return CompleteScan(request, findings);
    }

    private static List<Finding> CompleteScan(ScanRequest request, List<Finding> findings)
    {
        return request.EnableRandomnessScoring
            ? SecretRandomnessFindingProcessor.Apply(findings, request.RuleSet)
            : findings;
    }

    private static SecretRandomnessAssessment? CreateRandomnessAssessment(
        ReadOnlySpan<byte> secret,
        bool enableRandomnessScoring)
    {
        return enableRandomnessScoring && !secret.IsEmpty
            ? SecretRandomnessScorer.Assess(secret)
            : null;
    }

    private static Func<bool>? CreateCancellationPredicate(ScanRequest request)
    {
        if (!request.CancellationToken.CanBeCanceled)
        {
            return request.IsCancellationRequested;
        }

        if (request.IsCancellationRequested is null)
        {
            return () => request.CancellationToken.IsCancellationRequested;
        }

        return () => request.CancellationToken.IsCancellationRequested || request.IsCancellationRequested();
    }

    private static void ScanPass(
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> originalInput,
        SourceLineIndex originalLineIndex,
        DecodedInput? decodedInput,
        string fileName,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        CompiledRuleSet ruleSet,
        bool ignoreGitleaksAllow,
        string commit,
        long? maxTargetBytes,
        string symlinkFile,
        SourceBlobIdentity blobIdentity,
        List<Finding> findings,
        bool enableRandomnessScoring,
        Func<bool>? isCancellationRequested)
    {
        foreach (CompiledRule compiledRule in ruleSet.CompiledRules)
        {
            if (IsCancellationRequested(isCancellationRequested))
            {
                return;
            }

            List<CompiledAllowlist> globalAllowlists = GetGlobalAllowlists(ruleSet, compiledRule);
            List<Finding> ruleFindings = ScanCompiledRule(
                input,
                originalInput,
                originalLineIndex,
                decodedInput,
                fileName,
                fileNameBytes,
                windowsFileNameBytes,
                globalAllowlists,
                ignoreGitleaksAllow,
                commit,
                maxTargetBytes,
                symlinkFile,
                blobIdentity,
                compiledRule,
                includeSkipReport: false,
                enableRandomnessScoring,
                isCancellationRequested);
            if (compiledRule.Rule.RequiredRules.Count != 0)
            {
                ruleFindings = FilterRequiredFindings(
                    ruleFindings,
                    input,
                    originalInput,
                    originalLineIndex,
                    decodedInput,
                    fileName,
                    fileNameBytes,
                    windowsFileNameBytes,
                    ruleSet,
                    ignoreGitleaksAllow,
                    commit,
                    maxTargetBytes,
                    symlinkFile,
                    blobIdentity,
                    compiledRule,
                    enableRandomnessScoring,
                    isCancellationRequested);
            }

            findings.AddRange(ruleFindings);
            if (IsCancellationRequested(isCancellationRequested))
            {
                return;
            }
        }
    }

    private static List<Finding> ScanCompiledRule(
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> originalInput,
        SourceLineIndex originalLineIndex,
        DecodedInput? decodedInput,
        string fileName,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        List<CompiledAllowlist> globalAllowlists,
        bool ignoreGitleaksAllow,
        string commit,
        long? maxTargetBytes,
        string symlinkFile,
        SourceBlobIdentity blobIdentity,
        CompiledRule compiledRule,
        bool includeSkipReport,
        bool enableRandomnessScoring,
        Func<bool>? isCancellationRequested)
    {
        var findings = new List<Finding>();
        if (IsCancellationRequested(isCancellationRequested)
            || (compiledRule.Rule.SkipReport && !includeSkipReport))
        {
            return findings;
        }

        if (!IsPathCandidate(compiledRule, fileNameBytes, windowsFileNameBytes))
        {
            return findings;
        }

        if (!compiledRule.HasContentPattern)
        {
            if (decodedInput is not null)
            {
                return findings;
            }

            if (!IsAllowed(
                globalAllowlists,
                compiledRule.Allowlists,
                fileNameBytes,
                windowsFileNameBytes,
                [],
                [],
                [],
                string.Empty,
                commit))
            {
                findings.Add(CreatePathFinding(fileName, symlinkFile, compiledRule.Rule, commit, blobIdentity.Sha256));
            }

            return findings;
        }

        if (IsTooLargeForContentScan(input.Length, maxTargetBytes))
        {
            return findings;
        }

        if (compiledRule.UsesAwsCredentialPairMatcher)
        {
            if (compiledRule.Prefilter.IsCandidate(input))
            {
                ScanAwsCredentialPairRule(
                    input,
                    originalInput,
                    originalLineIndex,
                    decodedInput,
                    fileName,
                    fileNameBytes,
                    windowsFileNameBytes,
                    globalAllowlists,
                    ignoreGitleaksAllow,
                    commit,
                    symlinkFile,
                    blobIdentity,
                    compiledRule,
                    findings,
                    enableRandomnessScoring,
                    isCancellationRequested);
            }

            return findings;
        }

        if (compiledRule.UsesGenericApiKeyMatcher)
        {
            if (compiledRule.Prefilter.IsCandidate(input))
            {
                ScanGenericApiKeyRule(
                    input,
                    originalInput,
                    originalLineIndex,
                    decodedInput,
                    fileName,
                    fileNameBytes,
                    windowsFileNameBytes,
                    globalAllowlists,
                    ignoreGitleaksAllow,
                    commit,
                    symlinkFile,
                    blobIdentity,
                    compiledRule,
                    findings,
                    enableRandomnessScoring,
                    isCancellationRequested);
            }

            return findings;
        }

        if (compiledRule.UsesGcpServiceAccountKeyMatcher)
        {
            if (compiledRule.Prefilter.IsCandidate(input))
            {
                ScanGcpServiceAccountKeyRule(
                    input,
                    originalInput,
                    originalLineIndex,
                    decodedInput,
                    fileName,
                    fileNameBytes,
                    windowsFileNameBytes,
                    globalAllowlists,
                    ignoreGitleaksAllow,
                    commit,
                    symlinkFile,
                    blobIdentity,
                    compiledRule,
                    findings,
                    enableRandomnessScoring,
                    isCancellationRequested);
            }

            return findings;
        }

        if (compiledRule.Prefilter.IsCandidate(input))
        {
            ByteRegex regex = compiledRule.Regex ?? throw new InvalidOperationException("Content rule regex was not compiled.");
            ScanRule(
                input,
                originalInput,
                originalLineIndex,
                decodedInput,
                fileName,
                fileNameBytes,
                windowsFileNameBytes,
                globalAllowlists,
                ignoreGitleaksAllow,
                commit,
                symlinkFile,
                blobIdentity,
                compiledRule,
                regex,
                findings,
                enableRandomnessScoring,
                isCancellationRequested);
        }

        return findings;
    }

    private static List<Finding> FilterRequiredFindings(
        List<Finding> primaryFindings,
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> originalInput,
        SourceLineIndex originalLineIndex,
        DecodedInput? decodedInput,
        string fileName,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        CompiledRuleSet ruleSet,
        bool ignoreGitleaksAllow,
        string commit,
        long? maxTargetBytes,
        string symlinkFile,
        SourceBlobIdentity blobIdentity,
        CompiledRule primaryRule,
        bool enableRandomnessScoring,
        Func<bool>? isCancellationRequested)
    {
        if (primaryFindings.Count == 0 || IsCancellationRequested(isCancellationRequested))
        {
            return primaryFindings;
        }

        var requiredFindingsByRuleId = new Dictionary<string, List<Finding>>(StringComparer.Ordinal);
        foreach (SecretRequiredRule requiredRule in primaryRule.Rule.RequiredRules)
        {
            if (requiredFindingsByRuleId.ContainsKey(requiredRule.Id))
            {
                continue;
            }

            CompiledRule? compiledRequiredRule = FindCompiledRule(ruleSet, requiredRule.Id);
            requiredFindingsByRuleId.Add(
                requiredRule.Id,
                compiledRequiredRule is null
                    ? []
                    : ScanCompiledRule(
                        input,
                        originalInput,
                        originalLineIndex,
                        decodedInput,
                        fileName,
                        fileNameBytes,
                        windowsFileNameBytes,
                        GetGlobalAllowlists(ruleSet, compiledRequiredRule),
                        ignoreGitleaksAllow,
                        commit,
                        maxTargetBytes,
                        symlinkFile,
                        blobIdentity,
                        compiledRequiredRule,
                        includeSkipReport: true,
                        enableRandomnessScoring,
                        isCancellationRequested));
        }

        var filteredFindings = new List<Finding>(primaryFindings.Count);
        foreach (Finding primaryFinding in primaryFindings)
        {
            if (HasAllRequiredRules(primaryFinding, primaryRule.Rule.RequiredRules, requiredFindingsByRuleId))
            {
                filteredFindings.Add(primaryFinding);
            }
        }

        return filteredFindings;
    }

    private static CompiledRule? FindCompiledRule(CompiledRuleSet ruleSet, string ruleId)
    {
        foreach (CompiledRule compiledRule in ruleSet.CompiledRules)
        {
            if (compiledRule.Rule.Id.Equals(ruleId, StringComparison.Ordinal))
            {
                return compiledRule;
            }
        }

        return null;
    }

    private static bool HasAllRequiredRules(
        Finding primaryFinding,
        IReadOnlyList<SecretRequiredRule> requiredRules,
        Dictionary<string, List<Finding>> requiredFindingsByRuleId)
    {
        var foundRuleIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (SecretRequiredRule requiredRule in requiredRules)
        {
            if (!requiredFindingsByRuleId.TryGetValue(requiredRule.Id, out List<Finding>? requiredFindings))
            {
                continue;
            }

            foreach (Finding requiredFinding in requiredFindings)
            {
                if (IsWithinProximity(primaryFinding, requiredFinding, requiredRule))
                {
                    foundRuleIds.Add(requiredRule.Id);
                    break;
                }
            }
        }

        if (foundRuleIds.Count == 0)
        {
            return false;
        }

        foreach (SecretRequiredRule requiredRule in requiredRules)
        {
            if (!foundRuleIds.Contains(requiredRule.Id))
            {
                return false;
            }
        }

        return true;
    }

    private static List<CompiledAllowlist> GetGlobalAllowlists(CompiledRuleSet ruleSet, CompiledRule? compiledRule)
    {
        return compiledRule?.AppliesGlobalAllowlists == true
            ? ruleSet.Allowlists
            : s_emptyAllowlists;
    }

    private static bool IsWithinProximity(Finding primaryFinding, Finding requiredFinding, SecretRequiredRule requiredRule)
    {
        if (requiredRule.WithinLines is null && requiredRule.WithinColumns is null)
        {
            return true;
        }

        if (requiredRule.WithinLines is int withinLines
            && Math.Abs(primaryFinding.StartLine - requiredFinding.StartLine) > withinLines)
        {
            return false;
        }

        return requiredRule.WithinColumns is not int withinColumns
            || Math.Abs(primaryFinding.StartColumn - requiredFinding.StartColumn) <= withinColumns;
    }

    private static void ScanAwsCredentialPairRule(
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> originalInput,
        SourceLineIndex originalLineIndex,
        DecodedInput? decodedInput,
        string fileName,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        List<CompiledAllowlist> globalAllowlists,
        bool ignoreGitleaksAllow,
        string commit,
        string symlinkFile,
        SourceBlobIdentity blobIdentity,
        CompiledRule compiledRule,
        List<Finding> findings,
        bool enableRandomnessScoring,
        Func<bool>? isCancellationRequested)
    {
        SecretRule rule = compiledRule.Rule;
        int offset = 0;
        while (AwsCredentialPairMatcher.TryFind(input, offset, isCancellationRequested, out int matchStart, out int matchEnd, out int secretStart, out int secretEnd))
        {
            if (IsCancellationRequested(isCancellationRequested))
            {
                return;
            }

            if (!TryMapMatch(
                decodedInput,
                matchStart,
                matchEnd,
                out int reportStart,
                out int reportEnd,
                out IReadOnlyList<string> decodeTags,
                out IReadOnlyList<string> decodePath))
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            ReadOnlySpan<byte> secretBytes = input[secretStart..secretEnd];
            double entropy = ShannonEntropy.Calculate(secretBytes);
            if (rule.Entropy > 0 && entropy <= rule.Entropy)
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            ReadOnlySpan<byte> reportInput = decodedInput is null ? input : originalInput;
            SourcePosition start = originalLineIndex.FromOffset(reportStart);
            SourcePosition end = originalLineIndex.FromExclusiveEndOffset(reportStart, reportEnd);
            ReadOnlySpan<byte> matchBytes = input[matchStart..matchEnd];
            ReadOnlySpan<byte> lineBytes = ExtractLine(reportInput, reportStart);
            ReadOnlySpan<byte> allowlistLineBytes = decodedInput is null ? lineBytes : ExtractLine(input, matchStart);
            if (!ignoreGitleaksAllow && ContainsGitleaksAllow(lineBytes))
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            string matchText = DecodeReportText(matchBytes);
            string secretText = DecodeReportText(secretBytes);
            string lineText = DecodeReportText(lineBytes);
            if (IsAllowed(
                globalAllowlists,
                compiledRule.Allowlists,
                fileNameBytes,
                windowsFileNameBytes,
                matchBytes,
                secretBytes,
                allowlistLineBytes,
                secretText,
                commit))
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            findings.Add(new Finding(
                rule.Id,
                rule.Description,
                start.Line,
                end.Line,
                start.Column,
                end.Column,
                matchText,
                secretText,
                fileName,
                symlinkFile,
                commit,
                ToGitleaksEntropy(entropy),
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                CombineTags(rule.Tags, decodeTags),
                CreateFingerprint(commit, fileName, rule.Id, start.Line),
                lineText,
                blobSha256: blobIdentity.Sha256,
                decodePath: decodePath,
                randomness: CreateRandomnessAssessment(secretBytes, enableRandomnessScoring)));

            offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
        }
    }

    private static void ScanGenericApiKeyRule(
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> originalInput,
        SourceLineIndex originalLineIndex,
        DecodedInput? decodedInput,
        string fileName,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        List<CompiledAllowlist> globalAllowlists,
        bool ignoreGitleaksAllow,
        string commit,
        string symlinkFile,
        SourceBlobIdentity blobIdentity,
        CompiledRule compiledRule,
        List<Finding> findings,
        bool enableRandomnessScoring,
        Func<bool>? isCancellationRequested)
    {
        SecretRule rule = compiledRule.Rule;
        int offset = 0;
        while (GenericApiKeyMatcher.TryFind(input, offset, isCancellationRequested, out int matchStart, out int matchEnd, out int secretStart, out int secretEnd))
        {
            if (IsCancellationRequested(isCancellationRequested))
            {
                return;
            }

            if (!TryMapMatch(
                decodedInput,
                matchStart,
                matchEnd,
                out int reportStart,
                out int reportEnd,
                out IReadOnlyList<string> decodeTags,
                out IReadOnlyList<string> decodePath))
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            ReadOnlySpan<byte> secretBytes = input[secretStart..secretEnd];
            double entropy = ShannonEntropy.Calculate(secretBytes);
            if (rule.Entropy > 0 && entropy <= rule.Entropy)
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            ReadOnlySpan<byte> reportInput = decodedInput is null ? input : originalInput;
            SourcePosition start = originalLineIndex.FromOffset(reportStart);
            SourcePosition end = originalLineIndex.FromExclusiveEndOffset(reportStart, reportEnd);
            ReadOnlySpan<byte> matchBytes = input[matchStart..matchEnd];
            ReadOnlySpan<byte> lineBytes = ExtractLine(reportInput, reportStart);
            ReadOnlySpan<byte> allowlistLineBytes = decodedInput is null ? lineBytes : ExtractLine(input, matchStart);
            if (!ignoreGitleaksAllow && ContainsGitleaksAllow(lineBytes))
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            string matchText = DecodeReportText(matchBytes);
            string secretText = DecodeReportText(secretBytes);
            string lineText = DecodeReportText(lineBytes);
            if (IsAllowed(
                globalAllowlists,
                compiledRule.Allowlists,
                fileNameBytes,
                windowsFileNameBytes,
                matchBytes,
                secretBytes,
                allowlistLineBytes,
                secretText,
                commit))
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            findings.Add(new Finding(
                rule.Id,
                rule.Description,
                start.Line,
                end.Line,
                start.Column,
                end.Column,
                matchText,
                secretText,
                fileName,
                symlinkFile,
                commit,
                ToGitleaksEntropy(entropy),
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                CombineTags(rule.Tags, decodeTags),
                CreateFingerprint(commit, fileName, rule.Id, start.Line),
                lineText,
                blobSha256: blobIdentity.Sha256,
                decodePath: decodePath,
                randomness: CreateRandomnessAssessment(secretBytes, enableRandomnessScoring)));

            offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
        }
    }

    private static void ScanGcpServiceAccountKeyRule(
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> originalInput,
        SourceLineIndex originalLineIndex,
        DecodedInput? decodedInput,
        string fileName,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        List<CompiledAllowlist> globalAllowlists,
        bool ignoreGitleaksAllow,
        string commit,
        string symlinkFile,
        SourceBlobIdentity blobIdentity,
        CompiledRule compiledRule,
        List<Finding> findings,
        bool enableRandomnessScoring,
        Func<bool>? isCancellationRequested)
    {
        SecretRule rule = compiledRule.Rule;
        int offset = 0;
        while (GcpServiceAccountKeyMatcher.TryFind(input, offset, isCancellationRequested, out int matchStart, out int matchEnd))
        {
            if (IsCancellationRequested(isCancellationRequested))
            {
                return;
            }

            if (!TryMapMatch(
                decodedInput,
                matchStart,
                matchEnd,
                out int reportStart,
                out int reportEnd,
                out IReadOnlyList<string> decodeTags,
                out IReadOnlyList<string> decodePath))
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            ReadOnlySpan<byte> secretBytes = input[matchStart..matchEnd];
            double entropy = ShannonEntropy.Calculate(secretBytes);
            if (rule.Entropy > 0 && entropy <= rule.Entropy)
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            ReadOnlySpan<byte> reportInput = decodedInput is null ? input : originalInput;
            SourcePosition start = originalLineIndex.FromOffset(reportStart);
            SourcePosition end = originalLineIndex.FromExclusiveEndOffset(reportStart, reportEnd);
            ReadOnlySpan<byte> lineBytes = ExtractLine(reportInput, reportStart);
            ReadOnlySpan<byte> allowlistLineBytes = decodedInput is null ? lineBytes : ExtractLine(input, matchStart);
            if (!ignoreGitleaksAllow && ContainsGitleaksAllow(lineBytes))
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            string matchText = DecodeReportText(secretBytes);
            string lineText = DecodeReportText(lineBytes);
            if (IsAllowed(
                globalAllowlists,
                compiledRule.Allowlists,
                fileNameBytes,
                windowsFileNameBytes,
                secretBytes,
                secretBytes,
                allowlistLineBytes,
                matchText,
                commit))
            {
                offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
                continue;
            }

            findings.Add(new Finding(
                rule.Id,
                rule.Description,
                start.Line,
                end.Line,
                start.Column,
                end.Column,
                matchText,
                matchText,
                fileName,
                symlinkFile,
                commit,
                ToGitleaksEntropy(entropy),
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                CombineTags(rule.Tags, decodeTags),
                CreateFingerprint(commit, fileName, rule.Id, start.Line),
                lineText,
                blobSha256: blobIdentity.Sha256,
                decodePath: decodePath,
                randomness: CreateRandomnessAssessment(secretBytes, enableRandomnessScoring)));

            offset = AdvanceAfterMatch(matchStart, matchEnd, input.Length);
        }
    }

    private static void ScanRule(
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> originalInput,
        SourceLineIndex originalLineIndex,
        DecodedInput? decodedInput,
        string fileName,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        List<CompiledAllowlist> globalAllowlists,
        bool ignoreGitleaksAllow,
        string commit,
        string symlinkFile,
        SourceBlobIdentity blobIdentity,
        CompiledRule compiledRule,
        ByteRegex regex,
        List<Finding> findings,
        bool enableRandomnessScoring,
        Func<bool>? isCancellationRequested)
    {
        SecretRule rule = compiledRule.Rule;
        int offset = 0;
        while (offset <= input.Length)
        {
            if (IsCancellationRequested(isCancellationRequested))
            {
                return;
            }

            ByteRegexCaptures? captures = regex.FindCaptures(input, offset);
            if (captures is null)
            {
                return;
            }

            ByteRegexMatch match = captures.Match;
            if (!TryMapMatch(
                decodedInput,
                match.Start,
                match.End,
                out int reportStart,
                out int reportEnd,
                out IReadOnlyList<string> decodeTags,
                out IReadOnlyList<string> decodePath))
            {
                offset = AdvanceAfterMatch(match, input.Length);
                continue;
            }

            ByteRegexMatch secret = ResolveSecret(captures, rule.SecretGroup);
            ReadOnlySpan<byte> secretBytes = secret.Value(input);
            double entropy = ShannonEntropy.Calculate(secretBytes);
            if (rule.Entropy > 0 && entropy <= rule.Entropy)
            {
                offset = AdvanceAfterMatch(match, input.Length);
                continue;
            }

            ReadOnlySpan<byte> reportInput = decodedInput is null ? input : originalInput;
            SourcePosition start = originalLineIndex.FromOffset(reportStart);
            SourcePosition end = originalLineIndex.FromExclusiveEndOffset(reportStart, reportEnd);
            ReadOnlySpan<byte> matchBytes = match.Value(input);
            ReadOnlySpan<byte> lineBytes = ExtractLine(reportInput, reportStart);
            ReadOnlySpan<byte> allowlistLineBytes = decodedInput is null ? lineBytes : ExtractLine(input, match.Start);
            if (!ignoreGitleaksAllow && ContainsGitleaksAllow(lineBytes))
            {
                offset = AdvanceAfterMatch(match, input.Length);
                continue;
            }

            string matchText = DecodeReportText(matchBytes);
            string secretText = DecodeReportText(secretBytes);
            string lineText = DecodeReportText(lineBytes);
            if (IsAllowed(
                globalAllowlists,
                compiledRule.Allowlists,
                fileNameBytes,
                windowsFileNameBytes,
                matchBytes,
                secretBytes,
                allowlistLineBytes,
                secretText,
                commit))
            {
                offset = AdvanceAfterMatch(match, input.Length);
                continue;
            }

            findings.Add(new Finding(
                rule.Id,
                rule.Description,
                start.Line,
                end.Line,
                start.Column,
                end.Column,
                matchText,
                secretText,
                fileName,
                symlinkFile,
                commit,
                ToGitleaksEntropy(entropy),
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                CombineTags(rule.Tags, decodeTags),
                CreateFingerprint(commit, fileName, rule.Id, start.Line),
                lineText,
                blobSha256: blobIdentity.Sha256,
                decodePath: decodePath,
                randomness: CreateRandomnessAssessment(secretBytes, enableRandomnessScoring)));

            offset = AdvanceAfterMatch(match, input.Length);
        }
    }

    private static bool TryMapMatch(
        DecodedInput? decodedInput,
        int matchStart,
        int matchEnd,
        out int reportStart,
        out int reportEnd,
        out IReadOnlyList<string> decodeTags,
        out IReadOnlyList<string> decodePath)
    {
        if (decodedInput is null)
        {
            reportStart = matchStart;
            reportEnd = matchEnd;
            decodeTags = [];
            decodePath = [];
            return true;
        }

        bool hasOverlap = false;
        int originalStart = int.MaxValue;
        int originalEnd = 0;
        int depth = 0;
        DecodedEncoding encodings = DecodedEncoding.None;
        IReadOnlyList<string> bestDecodePath = [];
        foreach (DecodedSegment segment in decodedInput.Segments)
        {
            if (!segment.OverlapsDecoded(matchStart, matchEnd))
            {
                continue;
            }

            hasOverlap = true;
            originalStart = Math.Min(originalStart, segment.OriginalStart);
            originalEnd = Math.Max(originalEnd, segment.OriginalEnd);
            if (segment.Depth >= depth)
            {
                depth = segment.Depth;
                bestDecodePath = segment.DecodePath;
            }

            encodings |= segment.Encodings;
        }

        if (!hasOverlap)
        {
            reportStart = 0;
            reportEnd = 0;
            decodeTags = [];
            decodePath = [];
            return false;
        }

        reportStart = originalStart;
        reportEnd = originalEnd;
        decodeTags = CreateDecodeTags(encodings, depth);
        decodePath = bestDecodePath;
        return true;
    }

    private static double ToGitleaksEntropy(double entropy)
    {
        return (float)entropy;
    }

    private static bool IsCancellationRequested(Func<bool>? isCancellationRequested)
    {
        return isCancellationRequested is not null && isCancellationRequested();
    }

    private static List<string> CreateDecodeTags(DecodedEncoding encodings, int depth)
    {
        var tags = new List<string>(4);
        if ((encodings & DecodedEncoding.Percent) != 0)
        {
            tags.Add("decoded:percent");
        }

        if ((encodings & DecodedEncoding.Unicode) != 0)
        {
            tags.Add("decoded:unicode");
        }

        if ((encodings & DecodedEncoding.Hex) != 0)
        {
            tags.Add("decoded:hex");
        }

        if ((encodings & DecodedEncoding.Base64) != 0)
        {
            tags.Add("decoded:base64");
        }

        if ((encodings & DecodedEncoding.CSharpStringConcat) != 0)
        {
            tags.Add("decoded:csharp-string-concat");
        }

        tags.Add($"decode-depth:{depth}");
        return tags;
    }

    private static bool IsCSharpSourceFile(string fileName)
    {
        return fileName.EndsWith(".cs", StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<string> CombineTags(IReadOnlyList<string> ruleTags, IReadOnlyList<string> decodeTags)
    {
        if (decodeTags.Count == 0)
        {
            return ruleTags;
        }

        var tags = new List<string>(ruleTags.Count + decodeTags.Count);
        tags.AddRange(ruleTags);
        tags.AddRange(decodeTags);
        return tags;
    }

    private static bool IsAllowed(
        List<CompiledAllowlist> globalAllowlists,
        List<CompiledAllowlist> ruleAllowlists,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        ReadOnlySpan<byte> matchBytes,
        ReadOnlySpan<byte> secretBytes,
        ReadOnlySpan<byte> lineBytes,
        string secretText,
        string commit)
    {
        return IsAllowed(globalAllowlists, fileNameBytes, windowsFileNameBytes, matchBytes, secretBytes, lineBytes, secretText, commit)
            || IsAllowed(ruleAllowlists, fileNameBytes, windowsFileNameBytes, matchBytes, secretBytes, lineBytes, secretText, commit);
    }

    private static bool IsAllowed(
        List<CompiledAllowlist> allowlists,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        ReadOnlySpan<byte> matchBytes,
        ReadOnlySpan<byte> secretBytes,
        ReadOnlySpan<byte> lineBytes,
        string secretText,
        string commit)
    {
        foreach (CompiledAllowlist allowlist in allowlists)
        {
            if (IsAllowed(allowlist, fileNameBytes, windowsFileNameBytes, matchBytes, secretBytes, lineBytes, secretText, commit))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsAllowed(
        CompiledAllowlist compiledAllowlist,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes,
        ReadOnlySpan<byte> matchBytes,
        ReadOnlySpan<byte> secretBytes,
        ReadOnlySpan<byte> lineBytes,
        string secretText,
        string commit)
    {
        SecretAllowlist allowlist = compiledAllowlist.Allowlist;
        bool commitAllowed = IsCommitAllowed(allowlist, commit);
        bool pathAllowed = IsPathAllowed(compiledAllowlist, fileNameBytes, windowsFileNameBytes);
        bool regexAllowed = IsRegexAllowed(compiledAllowlist, allowlist.RegexTarget switch
        {
            AllowlistRegexTarget.Match => matchBytes,
            AllowlistRegexTarget.Line => lineBytes,
            _ => secretBytes,
        });
        bool stopWordAllowed = ContainsStopWord(allowlist, secretText);

        if (allowlist.Condition == AllowlistCondition.Or)
        {
            return commitAllowed || pathAllowed || regexAllowed || stopWordAllowed;
        }

        return IsConfiguredCheckAllowed(allowlist.Commits.Count, commitAllowed)
            && IsConfiguredCheckAllowed(allowlist.PathPatterns.Count, pathAllowed)
            && IsConfiguredCheckAllowed(allowlist.RegexPatterns.Count, regexAllowed)
            && IsConfiguredCheckAllowed(allowlist.StopWords.Count, stopWordAllowed);
    }

    private static bool IsConfiguredCheckAllowed(int count, bool isAllowed)
    {
        return count == 0 || isAllowed;
    }

    private static bool IsCommitAllowed(SecretAllowlist allowlist, string commit)
    {
        return commit.Length != 0
            && allowlist.Commits.Contains(commit.ToLowerInvariant(), StringComparer.Ordinal);
    }

    private static bool IsPathAllowed(
        CompiledAllowlist allowlist,
        ReadOnlySpan<byte> fileNameBytes,
        ReadOnlySpan<byte> windowsFileNameBytes)
    {
        return AnyRegexMatches(allowlist.PathRegexes, fileNameBytes)
            || (!windowsFileNameBytes.IsEmpty && AnyRegexMatches(allowlist.PathRegexes, windowsFileNameBytes));
    }

    private static bool IsRegexAllowed(CompiledAllowlist allowlist, ReadOnlySpan<byte> target)
    {
        return !target.IsEmpty && AnyRegexMatches(allowlist.Regexes, target);
    }

    private static bool AnyRegexMatches(List<ByteRegex> regexes, ReadOnlySpan<byte> input)
    {
        foreach (ByteRegex regex in regexes)
        {
            if (regex.FindCaptures(input, 0) is not null)
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsStopWord(SecretAllowlist allowlist, string secretText)
    {
        if (secretText.Length == 0)
        {
            return false;
        }

        foreach (string stopWord in allowlist.StopWords)
        {
            if (secretText.Contains(stopWord, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsGitleaksAllow(ReadOnlySpan<byte> lineBytes)
    {
        return lineBytes.IndexOf("gitleaks:allow"u8) >= 0;
    }

    private static bool IsPathCandidate(CompiledRule compiledRule, ReadOnlySpan<byte> fileNameBytes, ReadOnlySpan<byte> windowsFileNameBytes)
    {
        if (compiledRule.PathRegex is null)
        {
            return true;
        }

        if (compiledRule.PathRegex.FindCaptures(fileNameBytes, 0) is not null)
        {
            return true;
        }

        return !windowsFileNameBytes.IsEmpty
            && compiledRule.PathRegex.FindCaptures(windowsFileNameBytes, 0) is not null;
    }

    private static bool IsTooLargeForContentScan(int inputLength, long? maxTargetBytes)
    {
        return maxTargetBytes.HasValue && inputLength > maxTargetBytes.Value;
    }

    private static Finding CreatePathFinding(string fileName, string symlinkFile, SecretRule rule, string commit, string blobSha256)
    {
        return new Finding(
            rule.Id,
            rule.Description,
            0,
            0,
            0,
            0,
            $"file detected: {fileName}",
            string.Empty,
            fileName,
            symlinkFile,
            commit,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            rule.Tags,
            CreateFingerprint(commit, fileName, rule.Id, 0),
            blobSha256: blobSha256);
    }

    private static string CreateFingerprint(string commit, string fileName, string ruleId, int startLine)
    {
        return commit.Length == 0
            ? $"{fileName}:{ruleId}:{startLine}"
            : $"{commit}:{fileName}:{ruleId}:{startLine}";
    }

    private static ByteRegexMatch ResolveSecret(ByteRegexCaptures captures, int secretGroup)
    {
        if (secretGroup > 0)
        {
            ByteRegexMatch? group = captures.GetGroup(secretGroup);
            return group ?? captures.Match;
        }

        for (int groupIndex = 1; groupIndex < captures.GroupCount; groupIndex++)
        {
            ByteRegexMatch? group = captures.GetGroup(groupIndex);
            if (group is { Length: > 0 })
            {
                return group.Value;
            }
        }

        return captures.Match;
    }

    private static int AdvanceAfterMatch(ByteRegexMatch match, int inputLength)
    {
        return AdvanceAfterMatch(match.Start, match.End, inputLength);
    }

    private static int AdvanceAfterMatch(int matchStart, int matchEnd, int inputLength)
    {
        if (matchEnd == matchStart)
        {
            return matchEnd < inputLength ? matchEnd + 1 : inputLength + 1;
        }

        return matchEnd;
    }

    private static string DecodeReportText(ReadOnlySpan<byte> bytes)
    {
        return Encoding.UTF8.GetString(bytes);
    }

    private static ReadOnlySpan<byte> ExtractLine(ReadOnlySpan<byte> input, int offset)
    {
        int start = offset;
        while (start > 0 && input[start - 1] is not ((byte)'\n' or (byte)'\r'))
        {
            start--;
        }

        int end = offset;
        while (end < input.Length && input[end] is not ((byte)'\n' or (byte)'\r'))
        {
            end++;
        }

        return input[start..end];
    }

    private static byte[] CreateWindowsFileNameBytes(string fileName)
    {
        return fileName.Contains('/')
            ? Encoding.UTF8.GetBytes(fileName.Replace('/', '\\'))
            : [];
    }
}
