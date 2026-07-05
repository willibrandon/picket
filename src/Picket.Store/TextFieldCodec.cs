using System.Text;

namespace Picket.Store;

internal static class TextFieldCodec
{
    internal static string Encode(string value)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
    }

    internal static string Decode(string value)
    {
        return Encoding.UTF8.GetString(Convert.FromBase64String(value));
    }

    internal static string EncodeTags(IReadOnlyList<string> tags)
    {
        if (tags.Count == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        for (int i = 0; i < tags.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(',');
            }

            builder.Append(Encode(tags[i]));
        }

        return builder.ToString();
    }

    internal static List<string> DecodeTags(string value)
    {
        if (value.Length == 0)
        {
            return [];
        }

        string[] encodedTags = value.Split(',');
        var tags = new List<string>(encodedTags.Length);
        for (int i = 0; i < encodedTags.Length; i++)
        {
            tags.Add(Decode(encodedTags[i]));
        }

        return tags;
    }
}
