using SharpYaml;
using SharpYaml.Events;
using System.Text;

namespace Picket.Engine;

/// <summary>
/// Indexes YAML mappings through the low-level event API without alias expansion.
/// </summary>
internal sealed class NativeYamlIndex
{
    private const int MaxDepth = 64;
    private readonly List<NativeYamlMapping> _mappings;

    private NativeYamlIndex(List<NativeYamlMapping> mappings)
    {
        _mappings = mappings;
    }

    internal IReadOnlyList<NativeYamlMapping> Mappings => _mappings;

    internal static bool TryCreate(
        ReadOnlySpan<byte> input,
        Func<bool>? isCancellationRequested,
        out NativeYamlIndex? index)
    {
        string source;
        try
        {
            source = new UTF8Encoding(false, true).GetString(input);
        }
        catch (DecoderFallbackException)
        {
            index = null;
            return false;
        }

        var mappings = new List<NativeYamlMapping>();
        var frames = new List<NativeYamlContainerFrame>();
        var offsets = new Utf8OffsetTracker(source);
        try
        {
            IParser parser = Parser.CreateParser(new StringReader(source), MaxDepth);
            int eventCount = 0;
            while (parser.MoveNext())
            {
                if ((eventCount++ & 0xFF) == 0 && IsCancellationRequested(isCancellationRequested))
                {
                    index = null;
                    return false;
                }

                ParsingEvent? current = parser.Current;
                switch (current)
                {
                    case MappingStart:
                        PushMapping(frames, mappings);
                        if (frames.Count > MaxDepth)
                        {
                            index = null;
                            return false;
                        }

                        break;
                    case SequenceStart:
                        PushSequence(frames);
                        if (frames.Count > MaxDepth)
                        {
                            index = null;
                            return false;
                        }

                        break;
                    case Scalar scalar:
                        ConsumeScalar(source, offsets, frames, mappings, scalar);
                        break;
                    case AnchorAlias:
                        CompleteIgnoredValue(frames);
                        break;
                    case MappingEnd:
                    case SequenceEnd:
                        if (frames.Count != 0)
                        {
                            frames.RemoveAt(frames.Count - 1);
                        }

                        break;
                }
            }
        }
        catch (YamlException)
        {
            index = null;
            return false;
        }

        index = mappings.Count == 0 ? null : new NativeYamlIndex(mappings);
        return index is not null;
    }

    private static void PushMapping(
        List<NativeYamlContainerFrame> frames,
        List<NativeYamlMapping> mappings)
    {
        GetChildContext(frames, out int parentMappingId, out string propertyName);
        int id = mappings.Count;
        mappings.Add(new NativeYamlMapping(id, parentMappingId, propertyName));
        frames.Add(new NativeYamlContainerFrame(
            isMapping: true,
            mappingId: id,
            ownerMappingId: id,
            propertyName));
    }

    private static void PushSequence(List<NativeYamlContainerFrame> frames)
    {
        GetChildContext(frames, out int ownerMappingId, out string propertyName);
        frames.Add(new NativeYamlContainerFrame(
            isMapping: false,
            mappingId: -1,
            ownerMappingId,
            propertyName));
    }

    private static void GetChildContext(
        List<NativeYamlContainerFrame> frames,
        out int parentMappingId,
        out string propertyName)
    {
        if (frames.Count == 0)
        {
            parentMappingId = -1;
            propertyName = string.Empty;
            return;
        }

        NativeYamlContainerFrame parent = frames[^1];
        if (parent.IsMapping)
        {
            parentMappingId = parent.MappingId;
            propertyName = parent.ExpectsKey ? string.Empty : parent.ConsumePendingKey();
            return;
        }

        parentMappingId = parent.OwnerMappingId;
        propertyName = parent.PropertyName;
    }

    private static void ConsumeScalar(
        string source,
        Utf8OffsetTracker offsets,
        List<NativeYamlContainerFrame> frames,
        List<NativeYamlMapping> mappings,
        Scalar scalar)
    {
        GetScalarBounds(source, scalar, out int characterStart, out int characterEnd, out bool transformed);
        int valueStart = offsets.GetByteOffset(characterStart);
        int valueEnd = offsets.GetByteOffset(characterEnd);
        if (frames.Count == 0 || !frames[^1].IsMapping)
        {
            return;
        }

        NativeYamlContainerFrame frame = frames[^1];
        if (frame.ExpectsKey)
        {
            frame.PendingKey = scalar.Value;
            frame.ExpectsKey = false;
            return;
        }

        string key = frame.ConsumePendingKey();
        mappings[frame.MappingId].AddValue(new NativeYamlScalarValue(
            key,
            scalar.Value,
            valueStart,
            valueEnd,
            transformed));
    }

    private static void GetScalarBounds(
        string source,
        Scalar scalar,
        out int start,
        out int end,
        out bool transformed)
    {
        start = checked((int)Math.Clamp(scalar.Start.Index, 0, source.Length));
        end = checked((int)Math.Clamp(scalar.End.Index, start, source.Length));
        if (end - start >= 2
            && source[start] is '\'' or '"'
            && source[end - 1] == source[start])
        {
            start++;
            end--;
        }

        transformed = !source.AsSpan(start, end - start).SequenceEqual(scalar.Value);
    }

    private static void CompleteIgnoredValue(List<NativeYamlContainerFrame> frames)
    {
        if (frames.Count != 0 && frames[^1].IsMapping && !frames[^1].ExpectsKey)
        {
            frames[^1].ConsumePendingKey();
        }
    }

    private static bool IsCancellationRequested(Func<bool>? isCancellationRequested)
    {
        return isCancellationRequested is not null && isCancellationRequested();
    }
}
