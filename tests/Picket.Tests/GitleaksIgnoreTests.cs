using Picket.Compat;
using Picket.Engine;

namespace Picket.Tests;

/// <summary>
/// Tests for <see cref="GitleaksIgnore" />.
/// </summary>
[TestClass]
public sealed class GitleaksIgnoreTests
{
    /// <summary>
    /// Verifies Windows path normalization follows Gitleaks .gitleaksignore parsing.
    /// </summary>
    [TestMethod]
    public void FromLinesNormalizesWindowsPaths()
    {
        GitleaksIgnore ignore = GitleaksIgnore.FromLines([
            @"foo\bar\gitleaks-false-positive.yaml:aws-access-token:4",
            @"b55d88dc151f7022901cda41a03d43e0e508f2b7:test_data\test_local_repo_three_leaks.json:aws-access-token:73",
            "foo/bar/gitleaks-false-positive.yaml:aws-access-token:5",
            "# comment",
            "",
        ]);

        Assert.AreEqual(3, ignore.Count);
        Assert.IsTrue(ignore.IsIgnored(CreateFinding("foo/bar/gitleaks-false-positive.yaml", "aws-access-token", 4)));
        Assert.IsTrue(ignore.IsIgnored(CreateFinding("foo/bar/gitleaks-false-positive.yaml", "aws-access-token", 5)));
        Assert.IsTrue(ignore.IsIgnored(CreateFinding(
            "test_data/test_local_repo_three_leaks.json",
            "aws-access-token",
            73,
            "b55d88dc151f7022901cda41a03d43e0e508f2b7")));
    }

    /// <summary>
    /// Verifies commitless fingerprints suppress findings before commit-qualified fingerprints are checked.
    /// </summary>
    [TestMethod]
    public void IsIgnoredUsesCommitlessFingerprintForCommitFindings()
    {
        GitleaksIgnore ignore = GitleaksIgnore.FromLines(["src/file.txt:rule:10"]);
        Finding finding = CreateFinding("src/file.txt", "rule", 10, "abcdef");

        Assert.IsTrue(ignore.IsIgnored(finding));
    }

    /// <summary>
    /// Verifies non-ignored findings are preserved in input order.
    /// </summary>
    [TestMethod]
    public void FilterPreservesNonIgnoredFindings()
    {
        Finding ignored = CreateFinding("ignored.txt", "rule", 1);
        Finding kept = CreateFinding("kept.txt", "rule", 1);
        GitleaksIgnore ignore = GitleaksIgnore.FromLines(["ignored.txt:rule:1"]);

        IReadOnlyList<Finding> findings = ignore.Filter([ignored, kept]);

        Assert.HasCount(1, findings);
        Assert.AreEqual("kept.txt", findings[0].File);
    }

    private static Finding CreateFinding(string file, string ruleId, int startLine, string commit = "")
    {
        string fingerprint = commit.Length == 0
            ? $"{file}:{ruleId}:{startLine}"
            : $"{commit}:{file}:{ruleId}:{startLine}";

        return new Finding(
            ruleId,
            "description",
            startLine,
            startLine,
            1,
            1,
            "match",
            "secret",
            file,
            string.Empty,
            commit,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            fingerprint);
    }
}
