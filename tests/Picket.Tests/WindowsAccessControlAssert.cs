using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Picket.Tests;

internal static class WindowsAccessControlAssert
{
    [SupportedOSPlatform("windows")]
    internal static void AllowsOnlyCurrentUser(string path)
    {
        SecurityIdentifier currentUser = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Could not resolve the current Windows user SID.");
        FileSystemSecurity security = Directory.Exists(path)
            ? FileSystemAclExtensions.GetAccessControl(new DirectoryInfo(path))
            : FileSystemAclExtensions.GetAccessControl(new FileInfo(path));
        AuthorizationRuleCollection rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier));
        int allowCount = 0;

        foreach (AuthorizationRule authorizationRule in rules)
        {
            var rule = (FileSystemAccessRule)authorizationRule;
            Assert.AreEqual(AccessControlType.Allow, rule.AccessControlType);
            Assert.AreEqual(currentUser, rule.IdentityReference);
            Assert.AreEqual(FileSystemRights.FullControl, rule.FileSystemRights & FileSystemRights.FullControl);
            allowCount++;
        }

        Assert.IsGreaterThan(0, allowCount);
    }
}
