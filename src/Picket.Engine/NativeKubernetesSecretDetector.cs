using System.Text;

namespace Picket.Engine;

/// <summary>
/// Produces credential spans from Kubernetes Secret YAML resources.
/// </summary>
internal static class NativeKubernetesSecretDetector
{
    private static readonly string[] s_base64DecodePath = ["kubernetes-base64"];
    private static readonly string[] s_tags = ["structured:yaml", "kubernetes-secret"];
    private static readonly string[] s_yamlDecodePath = ["yaml-scalar"];

    internal static List<NativeDetectorMatch> Find(NativeYamlIndex index)
    {
        var secretMappingIds = new HashSet<int>();
        foreach (NativeYamlMapping mapping in index.Mappings)
        {
            if (mapping.HasValue("kind", "Secret"))
            {
                secretMappingIds.Add(mapping.Id);
            }
        }

        var matches = new List<NativeDetectorMatch>();
        foreach (NativeYamlMapping mapping in index.Mappings)
        {
            if (!secretMappingIds.Contains(mapping.ParentId))
            {
                continue;
            }

            bool encoded = mapping.PropertyName.Equals("data", StringComparison.Ordinal);
            bool plain = mapping.PropertyName.Equals("stringData", StringComparison.Ordinal);
            if (!encoded && !plain)
            {
                continue;
            }

            foreach (NativeYamlScalarValue value in mapping.Values)
            {
                if (value.Value.Length == 0 || value.ValueStart >= value.ValueEnd)
                {
                    continue;
                }

                if (encoded && TryDecodeBase64(value.Value, out string decoded))
                {
                    matches.Add(CreateMatch(value, decoded, s_base64DecodePath));
                }
                else
                {
                    matches.Add(CreateMatch(
                        value,
                        value.Value,
                        value.ValueIsTransformed ? s_yamlDecodePath : null));
                }
            }
        }

        return matches;
    }

    private static NativeDetectorMatch CreateMatch(
        NativeYamlScalarValue value,
        string secret,
        IReadOnlyList<string>? decodePath)
    {
        return new NativeDetectorMatch(
            value.ValueStart,
            value.ValueEnd,
            value.ValueStart,
            value.ValueEnd,
            secret,
            secret,
            s_tags,
            decodePath);
    }

    private static bool TryDecodeBase64(string value, out string decoded)
    {
        byte[] bytes = new byte[checked((value.Length * 3 / 4) + 3)];
        if (!Convert.TryFromBase64String(value, bytes, out int bytesWritten))
        {
            decoded = string.Empty;
            return false;
        }

        try
        {
            decoded = new UTF8Encoding(false, true).GetString(bytes, 0, bytesWritten);
        }
        catch (DecoderFallbackException)
        {
            decoded = string.Empty;
            return false;
        }

        if (decoded.Length == 0)
        {
            return false;
        }

        for (int i = 0; i < decoded.Length; i++)
        {
            char character = decoded[i];
            if (character == '\0'
                || char.IsControl(character) && character is not ('\r' or '\n' or '\t'))
            {
                decoded = string.Empty;
                return false;
            }
        }

        return true;
    }
}
