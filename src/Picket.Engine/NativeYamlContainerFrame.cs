namespace Picket.Engine;

/// <summary>
/// Tracks one YAML mapping or sequence while consuming parser events.
/// </summary>
internal sealed class NativeYamlContainerFrame(
    bool isMapping,
    int mappingId,
    int ownerMappingId,
    string propertyName)
{
    internal bool IsMapping { get; } = isMapping;

    internal int MappingId { get; } = mappingId;

    internal int OwnerMappingId { get; } = ownerMappingId;

    internal string PropertyName { get; } = propertyName;

    internal bool ExpectsKey { get; set; } = isMapping;

    internal string PendingKey { get; set; } = string.Empty;

    internal string ConsumePendingKey()
    {
        string key = PendingKey;
        PendingKey = string.Empty;
        ExpectsKey = true;
        return key;
    }
}
