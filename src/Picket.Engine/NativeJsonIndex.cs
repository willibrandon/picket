using System.Text.Json;

namespace Picket.Engine;

/// <summary>
/// Indexes JSON string properties in one bounded streaming parse.
/// </summary>
internal sealed class NativeJsonIndex
{
    private readonly List<NativeJsonStringProperty> _properties;

    private NativeJsonIndex(List<NativeJsonStringProperty> properties)
    {
        _properties = properties;
    }

    internal IReadOnlyList<NativeJsonStringProperty> Properties => _properties;

    internal static bool TryCreate(
        ReadOnlySpan<byte> input,
        Func<bool>? isCancellationRequested,
        out NativeJsonIndex? index)
    {
        var properties = new List<NativeJsonStringProperty>();
        var containerObjectIds = new List<int>();
        var containerPathPushCounts = new List<int>();
        var path = new List<string>();
        string? pendingProperty = null;
        int nextObjectId = 0;
        int tokenCount = 0;

        try
        {
            var reader = new Utf8JsonReader(
                input,
                new JsonReaderOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 64,
                });
            while (reader.Read())
            {
                if ((tokenCount++ & 0xFF) == 0 && IsCancellationRequested(isCancellationRequested))
                {
                    index = null;
                    return false;
                }

                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName:
                        pendingProperty = reader.GetString() ?? string.Empty;
                        break;
                    case JsonTokenType.StartObject:
                        PushContainer(path, containerPathPushCounts, pendingProperty);
                        containerObjectIds.Add(nextObjectId++);
                        pendingProperty = null;
                        break;
                    case JsonTokenType.StartArray:
                        PushContainer(path, containerPathPushCounts, pendingProperty);
                        containerObjectIds.Add(containerObjectIds.Count == 0 ? -1 : containerObjectIds[^1]);
                        pendingProperty = null;
                        break;
                    case JsonTokenType.EndObject:
                    case JsonTokenType.EndArray:
                        PopContainer(path, containerObjectIds, containerPathPushCounts);
                        pendingProperty = null;
                        break;
                    case JsonTokenType.String when pendingProperty is not null:
                        AddStringProperty(properties, path, containerObjectIds, pendingProperty, ref reader);
                        pendingProperty = null;
                        break;
                    default:
                        if (pendingProperty is not null && reader.TokenType is not JsonTokenType.None)
                        {
                            pendingProperty = null;
                        }

                        break;
                }
            }
        }
        catch (JsonException)
        {
            index = null;
            return false;
        }

        index = properties.Count == 0 ? null : new NativeJsonIndex(properties);
        return index is not null;
    }

    internal bool HasObjectProperty(int objectId, string name, string value)
    {
        for (int i = 0; i < _properties.Count; i++)
        {
            NativeJsonStringProperty property = _properties[i];
            if (property.ObjectId == objectId
                && property.Name.Equals(name, StringComparison.Ordinal)
                && property.Value.Equals(value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    internal bool HasObjectProperty(int objectId, string name)
    {
        for (int i = 0; i < _properties.Count; i++)
        {
            NativeJsonStringProperty property = _properties[i];
            if (property.ObjectId == objectId && property.Name.Equals(name, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static void AddStringProperty(
        List<NativeJsonStringProperty> properties,
        List<string> path,
        List<int> containerObjectIds,
        string name,
        ref Utf8JsonReader reader)
    {
        string[] propertyPath = new string[path.Count + 1];
        path.CopyTo(propertyPath);
        propertyPath[^1] = name;
        int valueStart = checked((int)reader.TokenStartIndex + 1);
        int valueEnd = checked((int)reader.BytesConsumed - 1);
        properties.Add(new NativeJsonStringProperty(
            name,
            reader.GetString() ?? string.Empty,
            valueStart,
            valueEnd,
            containerObjectIds.Count == 0 ? -1 : containerObjectIds[^1],
            propertyPath,
            reader.ValueIsEscaped));
    }

    private static void PushContainer(
        List<string> path,
        List<int> containerPathPushCounts,
        string? pendingProperty)
    {
        if (pendingProperty is null)
        {
            containerPathPushCounts.Add(0);
            return;
        }

        path.Add(pendingProperty);
        containerPathPushCounts.Add(1);
    }

    private static void PopContainer(
        List<string> path,
        List<int> containerObjectIds,
        List<int> containerPathPushCounts)
    {
        if (containerObjectIds.Count == 0 || containerPathPushCounts.Count == 0)
        {
            return;
        }

        containerObjectIds.RemoveAt(containerObjectIds.Count - 1);
        int pushCount = containerPathPushCounts[^1];
        containerPathPushCounts.RemoveAt(containerPathPushCounts.Count - 1);
        if (pushCount != 0)
        {
            path.RemoveAt(path.Count - 1);
        }
    }

    private static bool IsCancellationRequested(Func<bool>? isCancellationRequested)
    {
        return isCancellationRequested is not null && isCancellationRequested();
    }
}
