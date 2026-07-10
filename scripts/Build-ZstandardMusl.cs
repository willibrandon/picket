#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:include ScriptSupport.cs

using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;

try
{
    return await BuildZstandardMuslApp.RunAsync(args).ConfigureAwait(false);
}
catch (Exception ex) when (ex is ArgumentException
    or HttpRequestException
    or IOException
    or InvalidOperationException
    or PlatformNotSupportedException
    or TaskCanceledException
    or UnauthorizedAccessException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>
/// Builds the pinned decompression-only zstandard shared library for musl release artifacts.
/// </summary>
internal static class BuildZstandardMuslApp
{
    /// <summary>
    /// Downloads, verifies, builds, and validates the musl zstandard runtime.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static async Task<int> RunAsync(string[] args)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The musl zstandard runtime must be built on Linux.");
        }

        (Dictionary<string, List<string>> values, _) = ScriptSupport.ParseArguments(
            args,
            ["OutputDirectory"],
            [],
            []);
        string outputDirectory = ScriptSupport.GetString(values, "OutputDirectory");
        if (string.IsNullOrWhiteSpace(outputDirectory))
        {
            throw new ArgumentException("-OutputDirectory is required.");
        }

        const string ArchiveSha256 = "eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3";
        const string ArchiveUrl = "https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz";
        string temporaryDirectory = Path.Combine(Path.GetTempPath(), string.Concat("picket-zstd-", Guid.NewGuid().ToString("N")));
        try
        {
            Directory.CreateDirectory(temporaryDirectory);
            using var httpClient = new HttpClient
            {
                MaxResponseContentBufferSize = 20_000_000,
                Timeout = TimeSpan.FromMinutes(2),
            };
            byte[] archive = await httpClient.GetByteArrayAsync(ArchiveUrl).ConfigureAwait(false);
            string actualSha256 = Convert.ToHexStringLower(SHA256.HashData(archive));
            if (!actualSha256.Equals(ArchiveSha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException("The downloaded zstandard source archive did not match its pinned SHA-256 digest.");
            }

            using var archiveStream = new MemoryStream(archive, writable: false);
            using var gzipStream = new GZipStream(archiveStream, CompressionMode.Decompress);
            TarFile.ExtractToDirectory(gzipStream, temporaryDirectory, overwriteFiles: false);
            string sourceDirectory = Path.Combine(temporaryDirectory, "zstd-1.5.7");
            RunChecked(
                "make",
                [
                    "-C",
                    "lib",
                    "libzstd-nomt",
                    "CC=musl-gcc",
                    "ZSTD_LIB_COMPRESSION=0",
                    "ZSTD_LIB_DICTBUILDER=0",
                    "ZSTD_LIB_DEPRECATED=0",
                ],
                sourceDirectory,
                "musl zstandard build");

            string builtLibrary = Path.Combine(sourceDirectory, "lib", "libzstd-nomt");
            RunChecked("strip", ["--strip-unneeded", builtLibrary], sourceDirectory, "musl zstandard symbol stripping");
            (int readElfExitCode, string readElfOutput, string readElfError) = ScriptSupport.RunProcess(
                "readelf",
                ["-d", builtLibrary],
                sourceDirectory);
            if (readElfExitCode != 0)
            {
                throw new InvalidOperationException(string.Concat("musl zstandard ELF validation failed: ", readElfError.Trim()));
            }

            if (readElfOutput.Contains("libc.so.6", StringComparison.Ordinal))
            {
                throw new InvalidDataException("The musl zstandard runtime unexpectedly depends on glibc.");
            }

            string fullOutputDirectory = Path.GetFullPath(outputDirectory);
            Directory.CreateDirectory(fullOutputDirectory);
            string outputPath = Path.Combine(fullOutputDirectory, "libzstd.so");
            File.Copy(builtLibrary, outputPath, overwrite: true);
            Console.Out.WriteLine(outputPath);
            return 0;
        }
        finally
        {
            if (Directory.Exists(temporaryDirectory))
            {
                Directory.Delete(temporaryDirectory, recursive: true);
            }
        }
    }

    /// <summary>
    /// Runs a required build command and reports bounded process diagnostics on failure.
    /// </summary>
    /// <param name="filePath">The executable to run.</param>
    /// <param name="arguments">The command arguments.</param>
    /// <param name="workingDirectory">The command working directory.</param>
    /// <param name="description">The operation description.</param>
    private static void RunChecked(
        string filePath,
        string[] arguments,
        string workingDirectory,
        string description)
    {
        (int exitCode, _, string stderr) = ScriptSupport.RunProcess(filePath, arguments, workingDirectory);
        if (exitCode != 0)
        {
            string diagnostics = stderr.Length <= 4096 ? stderr : stderr[..4096];
            throw new InvalidOperationException(string.Concat(description, " failed: ", diagnostics.Trim()));
        }
    }
}
