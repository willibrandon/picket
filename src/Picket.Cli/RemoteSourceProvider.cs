using Picket.Engine;
using Picket.Sources;

namespace Picket;

/// <summary>
/// Enumerates source files selected by a native remote source provider.
/// </summary>
internal delegate List<SourceFile> RemoteSourceProvider(
    string root,
    CompiledRuleSet rules,
    long? maxTargetBytes,
    int maxArchiveDepth,
    int maxArchiveEntries,
    long? maxArchiveBytes,
    int maxArchiveCompressionRatio,
    long timeoutTimestamp);
