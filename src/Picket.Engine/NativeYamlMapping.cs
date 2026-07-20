namespace Picket.Engine;

/// <summary>
/// Represents one YAML mapping in the event index.
/// </summary>
internal sealed class NativeYamlMapping(int id, int parentId, string propertyName)
{
    private readonly List<NativeYamlScalarValue> _values = [];

    internal int Id { get; } = id;

    internal int ParentId { get; } = parentId;

    internal string PropertyName { get; } = propertyName;

    internal IReadOnlyList<NativeYamlScalarValue> Values => _values;

    internal void AddValue(NativeYamlScalarValue value)
    {
        _values.Add(value);
    }

    internal bool HasValue(string key, string value)
    {
        for (int i = 0; i < _values.Count; i++)
        {
            NativeYamlScalarValue scalar = _values[i];
            if (scalar.Key.Equals(key, StringComparison.Ordinal)
                && scalar.Value.Equals(value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
