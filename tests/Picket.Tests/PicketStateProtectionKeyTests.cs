using Picket.Security;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Picket.Tests;

/// <summary>
/// Tests state-protection key persistence.
/// </summary>
[TestClass]
public sealed class PicketStateProtectionKeyTests
{
    /// <summary>
    /// Gets or sets the test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies concurrent callers repair a malformed key without observing different replacements.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task LoadOrCreatePathRepairsMalformedKeyOnceAcrossConcurrentCallers()
    {
        using TempDirectory temp = TempDirectory.Create();
        string keyPath = Path.Combine(temp.Path, "state.key");
        File.WriteAllBytes(keyPath, [0x01]);
        using var start = new ManualResetEventSlim();
        CancellationToken cancellationToken = TestContext.CancellationToken;
        var tasks = new Task<byte[]>[32];
        for (int i = 0; i < tasks.Length; i++)
        {
            tasks[i] = Task.Run(() =>
            {
                start.Wait(cancellationToken);
                return PicketStateProtectionKey.LoadOrCreatePath(keyPath);
            }, cancellationToken);
        }

        start.Set();
        byte[][] keys = await Task.WhenAll(tasks).ConfigureAwait(false);

        Assert.HasCount(tasks.Length, keys);
        Assert.HasCount(32, keys[0]);
        for (int i = 1; i < keys.Length; i++)
        {
            CollectionAssert.AreEqual(keys[0], keys[i]);
        }

        CollectionAssert.AreEqual(keys[0], File.ReadAllBytes(keyPath));
    }

    /// <summary>
    /// Verifies key repair waits for a Windows reader that temporarily blocks atomic replacement.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    [OSCondition(ConditionMode.Include, OperatingSystems.Windows)]
    public async Task LoadOrCreatePathWaitsForTransientDestinationReader()
    {
        using TempDirectory temp = TempDirectory.Create();
        string keyPath = Path.Combine(temp.Path, "state.key");
        File.WriteAllBytes(keyPath, [0x01]);
        CancellationToken cancellationToken = TestContext.CancellationToken;
        FileStream reader = File.Open(keyPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        Task<byte[]> repair = Task.Run(
            () => PicketStateProtectionKey.LoadOrCreatePath(keyPath),
            cancellationToken);
        try
        {
            bool tempFileObserved = false;
            for (int attempt = 0; attempt < 100; attempt++)
            {
                if (Directory.EnumerateFiles(temp.Path, "state.key.*.tmp").Any())
                {
                    tempFileObserved = true;
                    break;
                }

                await Task.Delay(10, cancellationToken).ConfigureAwait(false);
            }

            Assert.IsTrue(tempFileObserved);
            Assert.IsFalse(repair.IsCompleted);
        }
        finally
        {
            reader.Dispose();
        }

        byte[] key = await repair.ConfigureAwait(false);

        Assert.HasCount(32, key);
        CollectionAssert.AreEqual(key, File.ReadAllBytes(keyPath));
    }

    /// <summary>
    /// Verifies state-protection keys do not follow symbolic-link paths.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Exclude, OperatingSystems.Windows)]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [SupportedOSPlatform("freebsd")]
    public void LoadOrCreatePathRejectsSymbolicLinkKeyFile()
    {
        using TempDirectory temp = TempDirectory.Create();
        string targetPath = Path.Combine(temp.Path, "target.key");
        string keyPath = Path.Combine(temp.Path, "state.key");
        byte[] target = [.. Enumerable.Repeat((byte)0x5a, 32)];
        File.WriteAllBytes(targetPath, target);
        File.CreateSymbolicLink(keyPath, targetPath);

        Assert.ThrowsExactly<IOException>(() => PicketStateProtectionKey.LoadOrCreatePath(keyPath));
        CollectionAssert.AreEqual(target, File.ReadAllBytes(targetPath));
    }

    /// <summary>
    /// Verifies state-protection key locking does not follow symbolic-link paths.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Exclude, OperatingSystems.Windows)]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [SupportedOSPlatform("freebsd")]
    public void LoadOrCreatePathRejectsSymbolicLinkLockFile()
    {
        using TempDirectory temp = TempDirectory.Create();
        string targetPath = Path.Combine(temp.Path, "target.lock");
        string keyPath = Path.Combine(temp.Path, "state.key");
        File.WriteAllText(targetPath, "unchanged");
        File.CreateSymbolicLink(string.Concat(keyPath, ".lock"), targetPath);

        Assert.ThrowsExactly<IOException>(() => PicketStateProtectionKey.LoadOrCreatePath(keyPath));
        Assert.AreEqual("unchanged", File.ReadAllText(targetPath));
    }

    /// <summary>
    /// Verifies state-protection key and lock files are owner-only on Unix-like systems.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Exclude, OperatingSystems.Windows)]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("macos")]
    [SupportedOSPlatform("freebsd")]
    public void LoadOrCreatePathCreatesOwnerOnlyFilesOnUnix()
    {
        const UnixFileMode GroupOrOther = UnixFileMode.GroupRead
            | UnixFileMode.GroupWrite
            | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead
            | UnixFileMode.OtherWrite
            | UnixFileMode.OtherExecute;
        using TempDirectory temp = TempDirectory.Create();
        string keyPath = Path.Combine(temp.Path, "state.key");

        _ = PicketStateProtectionKey.LoadOrCreatePath(keyPath);

        Assert.AreEqual((UnixFileMode)0, File.GetUnixFileMode(keyPath) & GroupOrOther);
        Assert.AreEqual((UnixFileMode)0, File.GetUnixFileMode(string.Concat(keyPath, ".lock")) & GroupOrOther);
    }

    /// <summary>
    /// Verifies state-protection key and lock files allow only the current Windows user.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Include, OperatingSystems.Windows)]
    [SupportedOSPlatform("windows")]
    public void LoadOrCreatePathCreatesOwnerOnlyFilesOnWindows()
    {
        using TempDirectory temp = TempDirectory.Create();
        string keyPath = Path.Combine(temp.Path, "state.key");

        _ = PicketStateProtectionKey.LoadOrCreatePath(keyPath);

        WindowsAccessControlAssert.AllowsOnlyCurrentUser(keyPath);
        WindowsAccessControlAssert.AllowsOnlyCurrentUser(string.Concat(keyPath, ".lock"));
    }

    /// <summary>
    /// Verifies an owner-correct Windows directory can be protected without rewriting its owner.
    /// </summary>
    [TestMethod]
    [OSCondition(ConditionMode.Include, OperatingSystems.Windows)]
    [SupportedOSPlatform("windows")]
    public void LoadOrCreatePathDoesNotRewriteMatchingWindowsOwner()
    {
        using TempDirectory temp = TempDirectory.Create();
        string keyDirectory = Path.Combine(temp.Path, "restricted");
        Directory.CreateDirectory(keyDirectory);
        var directory = new DirectoryInfo(keyDirectory);
        DirectorySecurity security = FileSystemAclExtensions.GetAccessControl(directory);
        SecurityIdentifier owner = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Could not resolve the current Windows user SID.");
        security.SetOwner(owner);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetAccessRule(new FileSystemAccessRule(
            owner,
            FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        FileSystemAclExtensions.SetAccessControl(directory, security);
        string keyPath = Path.Combine(keyDirectory, "state.key");

        _ = PicketStateProtectionKey.LoadOrCreatePath(keyPath);

        WindowsAccessControlAssert.AllowsOnlyCurrentUser(keyDirectory);
        WindowsAccessControlAssert.AllowsOnlyCurrentUser(keyPath);
        WindowsAccessControlAssert.AllowsOnlyCurrentUser(string.Concat(keyPath, ".lock"));
    }
}
