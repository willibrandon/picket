#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:include ScriptSupport.cs

using System.ComponentModel;

try
{
    return PublishLinuxMuslApp.Run(args);
}
catch (Exception ex) when (ex is ArgumentException
    or IOException
    or InvalidOperationException
    or PlatformNotSupportedException
    or UnauthorizedAccessException
    or Win32Exception)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>
/// Publishes and optionally packs Picket's Linux musl Native AOT tools in a pinned Alpine toolchain.
/// </summary>
internal static class PublishLinuxMuslApp
{
    /// <summary>
    /// Digest-pinned .NET 10 Alpine AOT SDK image used for native linking.
    /// </summary>
    private const string AotSdkImage = "mcr.microsoft.com/dotnet/sdk@sha256:999d96611287a92e064668b8aec18ee97cd7c2f3e5796d22f1e8b720d944ff69";

    /// <summary>
    /// Supported Linux musl runtime identifiers.
    /// </summary>
    private static readonly string[] s_allowedRuntimeIdentifiers = ["linux-musl-arm64", "linux-musl-x64"];

    /// <summary>
    /// File-based app options that accept one value.
    /// </summary>
    private static readonly string[] s_valueOptions =
    [
        "DockerPath",
        "OutputDirectory",
        "RuntimeIdentifier",
        "ToolPackageOutputDirectory",
        "Version",
        "ZstandardLibrary",
    ];

    /// <summary>
    /// Publishes the requested musl tools and validates their ELF interpreters.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static int Run(string[] args)
    {
        (Dictionary<string, List<string>> values, _) = ScriptSupport.ParseArguments(args, s_valueOptions, [], []);
        string runtimeIdentifier = RequireValue(values, "RuntimeIdentifier");
        ScriptSupport.RequireValueInSet("-RuntimeIdentifier", runtimeIdentifier, s_allowedRuntimeIdentifiers);

        string repositoryRoot = ScriptSupport.FindRepositoryRoot();
        string dockerPath = ScriptSupport.ResolveCommandPath(
            ScriptSupport.GetString(values, "DockerPath", "docker"),
            "Docker CLI");
        string gitPath = ScriptSupport.ResolveCommandPath("git", "Git CLI");
        string outputDirectory = PrepareEmptyDirectory(RequireValue(values, "OutputDirectory"));
        string toolPackageOutputValue = ScriptSupport.GetString(values, "ToolPackageOutputDirectory");
        string toolPackageOutputDirectory = string.IsNullOrWhiteSpace(toolPackageOutputValue)
            ? string.Empty
            : PrepareEmptyDirectory(toolPackageOutputValue);
        string zstandardLibrary = ResolveZstandardLibrary(RequireValue(values, "ZstandardLibrary"));
        string version = ScriptSupport.GetString(values, "Version");

        EnsureCommittedTreeIsClean(gitPath, repositoryRoot);
        string temporaryDirectory = Path.Combine(
            Path.GetTempPath(),
            string.Concat("picket-musl-publish-", Guid.NewGuid().ToString("N")));
        string sourceArchive = Path.Combine(temporaryDirectory, "picket.tar");
        string containerName = string.Concat("picket-musl-publish-", Guid.NewGuid().ToString("N"));
        bool containerCreated = false;

        try
        {
            Directory.CreateDirectory(temporaryDirectory);
            RunChecked(
                gitPath,
                ["archive", "--format=tar", string.Concat("--output=", sourceArchive), "HEAD"],
                repositoryRoot,
                "source archive creation");
            RunChecked(dockerPath, ["pull", AotSdkImage], repositoryRoot, "Alpine AOT SDK image pull");
            ValidateImageArchitecture(dockerPath, repositoryRoot, runtimeIdentifier);

            var createArguments = new List<string>
            {
                "create",
                "--name",
                containerName,
                "--mount",
                CreateBindMount(outputDirectory, "/out", readOnly: false),
                "--mount",
                CreateBindMount(zstandardLibrary, "/zstd/libzstd.so", readOnly: true),
            };
            if (!string.IsNullOrEmpty(toolPackageOutputDirectory))
            {
                createArguments.Add("--mount");
                createArguments.Add(CreateBindMount(toolPackageOutputDirectory, "/packages", readOnly: false));
            }

            createArguments.Add(AotSdkImage);
            createArguments.Add("tail");
            createArguments.Add("-f");
            createArguments.Add("/dev/null");
            RunChecked(dockerPath, createArguments, repositoryRoot, "musl build container creation");
            containerCreated = true;

            RunChecked(dockerPath, ["start", containerName], repositoryRoot, "musl build container start");
            RunChecked(
                dockerPath,
                ["cp", sourceArchive, string.Concat(containerName, ":/tmp/picket.tar")],
                repositoryRoot,
                "source archive copy");
            RunContainerCommand(dockerPath, repositoryRoot, containerName, "source directory creation", ["mkdir", "-p", "/src"]);
            RunContainerCommand(
                dockerPath,
                repositoryRoot,
                containerName,
                "source archive extraction",
                ["tar", "-xf", "/tmp/picket.tar", "-C", "/src"]);

            RestoreSolution(dockerPath, repositoryRoot, containerName);

            if (string.IsNullOrEmpty(toolPackageOutputDirectory))
            {
                PublishProject(dockerPath, repositoryRoot, containerName, runtimeIdentifier, version, "src/Picket.Cli/Picket.Cli.csproj");
                PublishProject(dockerPath, repositoryRoot, containerName, runtimeIdentifier, version, "src/Picket.Tui.Cli/Picket.Tui.Cli.csproj");
            }
            else
            {
                PackProject(dockerPath, repositoryRoot, containerName, runtimeIdentifier, version, "src/Picket.Cli/Picket.Cli.csproj");
                PackProject(dockerPath, repositoryRoot, containerName, runtimeIdentifier, version, "src/Picket.Tui.Cli/Picket.Tui.Cli.csproj");
                CopyPackedPublishOutput(dockerPath, repositoryRoot, containerName, runtimeIdentifier, "Picket.Cli");
                CopyPackedPublishOutput(dockerPath, repositoryRoot, containerName, runtimeIdentifier, "Picket.Tui.Cli");
            }

            ValidateMuslInterpreter(dockerPath, repositoryRoot, containerName, "/out/picket");
            ValidateMuslInterpreter(dockerPath, repositoryRoot, containerName, "/out/picket-tui");
            RestoreLinuxOutputOwnership(dockerPath, repositoryRoot, containerName, toolPackageOutputDirectory);
        }
        finally
        {
            if (containerCreated)
            {
                ScriptSupport.RunProcess(dockerPath, ["rm", "--force", containerName], repositoryRoot);
            }

            if (Directory.Exists(temporaryDirectory))
            {
                Directory.Delete(temporaryDirectory, recursive: true);
            }
        }

        ValidateOutputs(outputDirectory, toolPackageOutputDirectory, runtimeIdentifier);
        Console.Out.WriteLine(outputDirectory);
        if (!string.IsNullOrEmpty(toolPackageOutputDirectory))
        {
            Console.Out.WriteLine(toolPackageOutputDirectory);
        }

        return 0;
    }

    /// <summary>
    /// Requires a nonempty parsed option value.
    /// </summary>
    /// <param name="values">The parsed option values.</param>
    /// <param name="name">The option name.</param>
    /// <returns>The required value.</returns>
    private static string RequireValue(Dictionary<string, List<string>> values, string name)
    {
        string value = ScriptSupport.GetString(values, name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(string.Concat("-", name, " is required."));
        }

        return value;
    }

    /// <summary>
    /// Creates or validates an empty output directory.
    /// </summary>
    /// <param name="path">The requested output path.</param>
    /// <returns>The full output path.</returns>
    private static string PrepareEmptyDirectory(string path)
    {
        string fullPath = Path.GetFullPath(path);
        if (Directory.Exists(fullPath) && Directory.EnumerateFileSystemEntries(fullPath).Any())
        {
            throw new IOException(string.Concat("Output directory is not empty: ", fullPath));
        }

        Directory.CreateDirectory(fullPath);
        return fullPath;
    }

    /// <summary>
    /// Resolves the verified musl zstandard shared library.
    /// </summary>
    /// <param name="path">The configured library path.</param>
    /// <returns>The full library path.</returns>
    private static string ResolveZstandardLibrary(string path)
    {
        string fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException(string.Concat("Musl zstandard runtime does not exist: ", fullPath));
        }

        return fullPath;
    }

    /// <summary>
    /// Refuses to archive tracked working-tree changes that would not be included in the build.
    /// </summary>
    /// <param name="gitPath">The Git executable.</param>
    /// <param name="repositoryRoot">The repository root.</param>
    private static void EnsureCommittedTreeIsClean(string gitPath, string repositoryRoot)
    {
        string status = RunChecked(
            gitPath,
            ["status", "--porcelain", "--untracked-files=no"],
            repositoryRoot,
            "working-tree validation");
        if (!string.IsNullOrWhiteSpace(status))
        {
            throw new InvalidOperationException(
                "The musl publish builds committed HEAD. Commit or revert tracked working-tree changes before running it.");
        }
    }

    /// <summary>
    /// Verifies that Docker selected the architecture required by the target RID.
    /// </summary>
    /// <param name="dockerPath">The Docker executable.</param>
    /// <param name="workingDirectory">The process working directory.</param>
    /// <param name="runtimeIdentifier">The target runtime identifier.</param>
    private static void ValidateImageArchitecture(string dockerPath, string workingDirectory, string runtimeIdentifier)
    {
        string architecture = RunChecked(
            dockerPath,
            ["image", "inspect", "--format", "{{.Architecture}}", AotSdkImage],
            workingDirectory,
            "Alpine AOT SDK architecture inspection").Trim();
        string expectedArchitecture = runtimeIdentifier.EndsWith("-arm64", StringComparison.Ordinal) ? "arm64" : "amd64";
        if (!architecture.Equals(expectedArchitecture, StringComparison.Ordinal))
        {
            throw new PlatformNotSupportedException(
                string.Concat(runtimeIdentifier, " requires a Docker ", expectedArchitecture, " host, but the selected image is ", architecture, "."));
        }
    }

    /// <summary>
    /// Creates a Docker bind-mount specification without invoking a shell.
    /// </summary>
    /// <param name="source">The host source path.</param>
    /// <param name="target">The container target path.</param>
    /// <param name="readOnly">Whether the mount is read-only.</param>
    /// <returns>The Docker mount specification.</returns>
    private static string CreateBindMount(string source, string target, bool readOnly)
    {
        if (source.Contains(','))
        {
            throw new ArgumentException(string.Concat("Docker bind-mount paths cannot contain commas: ", source));
        }

        return string.Concat("type=bind,source=", source, ",target=", target, readOnly ? ",readonly" : string.Empty);
    }

    /// <summary>
    /// Restores the locked solution graph that contains every declared tool runtime identifier.
    /// </summary>
    /// <param name="dockerPath">The Docker executable.</param>
    /// <param name="workingDirectory">The process working directory.</param>
    /// <param name="containerName">The build container name.</param>
    private static void RestoreSolution(
        string dockerPath,
        string workingDirectory,
        string containerName)
    {
        RunDotNetCommand(
            dockerPath,
            workingDirectory,
            containerName,
            "locked solution restore",
            ["dotnet", "restore", "Picket.slnx", "--locked-mode", "--verbosity", "minimal"]);
    }

    /// <summary>
    /// Publishes one project into the shared release output directory.
    /// </summary>
    /// <param name="dockerPath">The Docker executable.</param>
    /// <param name="workingDirectory">The process working directory.</param>
    /// <param name="containerName">The build container name.</param>
    /// <param name="runtimeIdentifier">The target runtime identifier.</param>
    /// <param name="version">The optional package and assembly version.</param>
    /// <param name="projectPath">The repository-relative project path.</param>
    private static void PublishProject(
        string dockerPath,
        string workingDirectory,
        string containerName,
        string runtimeIdentifier,
        string version,
        string projectPath)
    {
        var arguments = new List<string>
        {
            "dotnet",
            "publish",
            projectPath,
            "--configuration",
            "Release",
            "-p:PublishProfile=release-speed",
            "-r",
            runtimeIdentifier,
            "--no-restore",
            "--output",
            "/out",
        };
        AddVersionArguments(arguments, version);
        RunDotNetCommand(dockerPath, workingDirectory, containerName, string.Concat("publish for ", projectPath), arguments);
    }

    /// <summary>
    /// Packs one RID-specific Native AOT tool package.
    /// </summary>
    /// <param name="dockerPath">The Docker executable.</param>
    /// <param name="workingDirectory">The process working directory.</param>
    /// <param name="containerName">The build container name.</param>
    /// <param name="runtimeIdentifier">The target runtime identifier.</param>
    /// <param name="version">The optional package and assembly version.</param>
    /// <param name="projectPath">The repository-relative project path.</param>
    private static void PackProject(
        string dockerPath,
        string workingDirectory,
        string containerName,
        string runtimeIdentifier,
        string version,
        string projectPath)
    {
        var arguments = new List<string>
        {
            "dotnet",
            "pack",
            projectPath,
            "--configuration",
            "Release",
            "-p:PublishProfile=release-speed",
            "-r",
            runtimeIdentifier,
            "--no-restore",
            "--output",
            "/packages",
        };
        AddVersionArguments(arguments, version);
        RunDotNetCommand(dockerPath, workingDirectory, containerName, string.Concat("pack for ", projectPath), arguments);
    }

    /// <summary>
    /// Adds explicit release version properties when supplied.
    /// </summary>
    /// <param name="arguments">The mutable dotnet argument list.</param>
    /// <param name="version">The optional release version.</param>
    private static void AddVersionArguments(List<string> arguments, string version)
    {
        if (string.IsNullOrWhiteSpace(version))
        {
            return;
        }

        arguments.Add(string.Concat("-p:Version=", version));
        arguments.Add(string.Concat("-p:PackageVersion=", version));
    }

    /// <summary>
    /// Copies a pack-generated project publish layout into the combined release directory.
    /// </summary>
    /// <param name="dockerPath">The Docker executable.</param>
    /// <param name="workingDirectory">The process working directory.</param>
    /// <param name="containerName">The build container name.</param>
    /// <param name="runtimeIdentifier">The target runtime identifier.</param>
    /// <param name="projectDirectoryName">The project directory name.</param>
    private static void CopyPackedPublishOutput(
        string dockerPath,
        string workingDirectory,
        string containerName,
        string runtimeIdentifier,
        string projectDirectoryName)
    {
        string source = string.Concat(
            "/src/src/",
            projectDirectoryName,
            "/bin/Release/net10.0/",
            runtimeIdentifier,
            "/publish/.");
        RunContainerCommand(
            dockerPath,
            workingDirectory,
            containerName,
            string.Concat("publish output copy for ", projectDirectoryName),
            ["cp", "-a", source, "/out/"]);
    }

    /// <summary>
    /// Runs dotnet inside the pinned build container with deterministic environment settings.
    /// </summary>
    /// <param name="dockerPath">The Docker executable.</param>
    /// <param name="workingDirectory">The process working directory.</param>
    /// <param name="containerName">The build container name.</param>
    /// <param name="description">The operation description.</param>
    /// <param name="command">The container command and arguments.</param>
    private static void RunDotNetCommand(
        string dockerPath,
        string workingDirectory,
        string containerName,
        string description,
        IEnumerable<string> command)
    {
        var arguments = new List<string>
        {
            "exec",
            "--env",
            "DOTNET_CLI_TELEMETRY_OPTOUT=1",
            "--env",
            "DOTNET_NOLOGO=true",
            "--env",
            "PICKET_ZSTANDARD_MUSL_LIBRARY=/zstd/libzstd.so",
            "--workdir",
            "/src",
            containerName,
        };
        arguments.AddRange(command);
        RunChecked(dockerPath, arguments, workingDirectory, description);
    }

    /// <summary>
    /// Runs a command inside the active build container.
    /// </summary>
    /// <param name="dockerPath">The Docker executable.</param>
    /// <param name="workingDirectory">The process working directory.</param>
    /// <param name="containerName">The build container name.</param>
    /// <param name="description">The operation description.</param>
    /// <param name="command">The container command and arguments.</param>
    /// <returns>Captured standard output.</returns>
    private static string RunContainerCommand(
        string dockerPath,
        string workingDirectory,
        string containerName,
        string description,
        IEnumerable<string> command)
    {
        var arguments = new List<string> { "exec", containerName };
        arguments.AddRange(command);
        return RunChecked(dockerPath, arguments, workingDirectory, description);
    }

    /// <summary>
    /// Verifies that a published executable requests a musl dynamic loader.
    /// </summary>
    /// <param name="dockerPath">The Docker executable.</param>
    /// <param name="workingDirectory">The process working directory.</param>
    /// <param name="containerName">The build container name.</param>
    /// <param name="executablePath">The executable path inside the container.</param>
    private static void ValidateMuslInterpreter(
        string dockerPath,
        string workingDirectory,
        string containerName,
        string executablePath)
    {
        string output = RunContainerCommand(
            dockerPath,
            workingDirectory,
            containerName,
            string.Concat("ELF interpreter validation for ", executablePath),
            ["readelf", "-l", executablePath]);
        if (!output.Contains("ld-musl-", StringComparison.Ordinal)
            || output.Contains("ld-linux", StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                string.Concat(executablePath, " was not linked against the musl dynamic loader."));
        }
    }

    /// <summary>
    /// Restores host ownership for bind-mounted outputs on Linux runners.
    /// </summary>
    /// <param name="dockerPath">The Docker executable.</param>
    /// <param name="workingDirectory">The process working directory.</param>
    /// <param name="containerName">The build container name.</param>
    /// <param name="toolPackageOutputDirectory">The optional host tool-package output path.</param>
    private static void RestoreLinuxOutputOwnership(
        string dockerPath,
        string workingDirectory,
        string containerName,
        string toolPackageOutputDirectory)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        string userId = RunChecked("id", ["-u"], workingDirectory, "host user ID lookup").Trim();
        string groupId = RunChecked("id", ["-g"], workingDirectory, "host group ID lookup").Trim();
        var command = new List<string> { "chown", "-R", string.Concat(userId, ":", groupId), "/out" };
        if (!string.IsNullOrEmpty(toolPackageOutputDirectory))
        {
            command.Add("/packages");
        }

        RunContainerCommand(dockerPath, workingDirectory, containerName, "output ownership restoration", command);
    }

    /// <summary>
    /// Verifies the expected release files and RID-specific tool packages.
    /// </summary>
    /// <param name="outputDirectory">The host release output directory.</param>
    /// <param name="toolPackageOutputDirectory">The optional host package output directory.</param>
    /// <param name="runtimeIdentifier">The target runtime identifier.</param>
    private static void ValidateOutputs(
        string outputDirectory,
        string toolPackageOutputDirectory,
        string runtimeIdentifier)
    {
        foreach (string fileName in new[] { "libzstd.so", "picket", "picket-tui" })
        {
            string path = Path.Combine(outputDirectory, fileName);
            if (!File.Exists(path))
            {
                throw new FileNotFoundException(string.Concat("Musl publish did not produce ", path));
            }
        }

        if (string.IsNullOrEmpty(toolPackageOutputDirectory))
        {
            return;
        }

        RequireToolPackage(toolPackageOutputDirectory, string.Concat("Picket.", runtimeIdentifier, "."));
        RequireToolPackage(toolPackageOutputDirectory, string.Concat("Picket.Tui.Cli.", runtimeIdentifier, "."));
    }

    /// <summary>
    /// Requires one RID-specific NuGet tool package with the expected package ID prefix.
    /// </summary>
    /// <param name="directory">The package output directory.</param>
    /// <param name="fileNamePrefix">The expected package file-name prefix.</param>
    private static void RequireToolPackage(string directory, string fileNamePrefix)
    {
        bool found = Directory.EnumerateFiles(directory, "*.nupkg", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileName)
            .Any(fileName => fileName is not null && fileName.StartsWith(fileNamePrefix, StringComparison.OrdinalIgnoreCase));
        if (!found)
        {
            throw new FileNotFoundException(string.Concat("Musl pack did not produce package ", fileNamePrefix, "*.nupkg"));
        }
    }

    /// <summary>
    /// Runs a required process and returns its captured standard output.
    /// </summary>
    /// <param name="filePath">The executable path.</param>
    /// <param name="arguments">The process arguments.</param>
    /// <param name="workingDirectory">The process working directory.</param>
    /// <param name="description">The operation description.</param>
    /// <returns>Captured standard output.</returns>
    private static string RunChecked(
        string filePath,
        IEnumerable<string> arguments,
        string workingDirectory,
        string description)
    {
        (int exitCode, string stdout, string stderr) = ScriptSupport.RunProcess(filePath, arguments, workingDirectory);
        if (exitCode == 0)
        {
            return stdout;
        }

        string diagnostics = string.Concat(stdout, stderr);
        if (diagnostics.Length > 4096)
        {
            diagnostics = diagnostics[..4096];
        }

        throw new InvalidOperationException(
            string.Concat(description, " failed with exit code ", exitCode, ": ", diagnostics.Trim()));
    }
}
