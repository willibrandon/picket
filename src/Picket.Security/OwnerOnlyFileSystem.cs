using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Picket.Security;

internal static class OwnerOnlyFileSystem
{
    private const UnixFileMode OwnerOnlyDirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode OwnerOnlyFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    internal static void CreateDirectory(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        Directory.CreateDirectory(path);
        if (OperatingSystem.IsWindows())
        {
            ProtectWindowsDirectory(path);
        }
        else
        {
            File.SetUnixFileMode(path, OwnerOnlyDirectoryMode);
        }
    }

    internal static FileStream OpenNewFile(string path)
    {
        return OpenFile(path, FileMode.CreateNew, FileAccess.Write);
    }

    internal static FileStream OpenFile(string path, FileMode mode, FileAccess access)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var options = new FileStreamOptions
        {
            Access = access,
            Mode = mode,
            Share = FileShare.None,
            Options = FileOptions.SequentialScan,
        };
        if (!OperatingSystem.IsWindows() && CanCreateFile(mode))
        {
            options.UnixCreateMode = OwnerOnlyFileMode;
        }

        return new FileStream(path, options);
    }

    internal static void RejectSymbolicLink(string path, string description)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(description);

        var file = new FileInfo(path);
        file.Refresh();
        if (file.LinkTarget is not null || (file.Exists && (file.Attributes & FileAttributes.ReparsePoint) != 0))
        {
            throw new IOException($"{description} must not be a symbolic link: {path}");
        }
    }

    private static bool CanCreateFile(FileMode mode)
    {
        return mode is FileMode.Append or FileMode.Create or FileMode.CreateNew or FileMode.OpenOrCreate;
    }

    internal static void ProtectFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (OperatingSystem.IsWindows())
        {
            ProtectWindowsFile(path);
        }
        else
        {
            File.SetUnixFileMode(path, OwnerOnlyFileMode);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ProtectWindowsDirectory(string path)
    {
        DirectorySecurity security = FileSystemAclExtensions.GetAccessControl(new DirectoryInfo(path));
        SecurityIdentifier owner = GetCurrentUserSid();
        SetOwnerIfDifferent(security, owner);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetAccessRule(new FileSystemAccessRule(
            owner,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(path), security);
    }

    [SupportedOSPlatform("windows")]
    private static void ProtectWindowsFile(string path)
    {
        FileSecurity security = FileSystemAclExtensions.GetAccessControl(new FileInfo(path));
        SecurityIdentifier owner = GetCurrentUserSid();
        SetOwnerIfDifferent(security, owner);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
        FileSystemAclExtensions.SetAccessControl(new FileInfo(path), security);
    }

    [SupportedOSPlatform("windows")]
    private static SecurityIdentifier GetCurrentUserSid()
    {
        return WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Could not resolve the current Windows user SID.");
    }

    [SupportedOSPlatform("windows")]
    private static void SetOwnerIfDifferent(FileSystemSecurity security, SecurityIdentifier owner)
    {
        if (!owner.Equals(security.GetOwner(typeof(SecurityIdentifier))))
        {
            security.SetOwner(owner);
        }
    }
}
