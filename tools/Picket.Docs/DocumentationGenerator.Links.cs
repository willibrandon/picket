using System.Globalization;
using System.Text;

namespace Picket.Docs;

internal sealed partial class DocumentationGenerator
{
    internal List<string> ValidateDocumentationLinks()
    {
        return ValidateDocumentationLinks(_siteDocsRoot);
    }

    internal static List<string> ValidateDocumentationLinks(string siteDocsRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteDocsRoot);

        string root = Path.GetFullPath(siteDocsRoot);
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException($"Documentation content root does not exist: {root}");
        }

        string[] files = [.. Directory
            .EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
            .Where(static path => path.EndsWith(".md", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".mdx", StringComparison.OrdinalIgnoreCase))
            .Order(StringComparer.OrdinalIgnoreCase)];
        var routes = new Dictionary<string, string>(StringComparer.Ordinal);
        var anchors = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);

        for (int i = 0; i < files.Length; i++)
        {
            string route = GetDocumentationRoute(root, files[i]);
            routes[route] = files[i];
            anchors[route] = ReadDocumentationAnchors(files[i]);
        }

        var violations = new List<string>();
        for (int i = 0; i < files.Length; i++)
        {
            string file = files[i];
            string route = GetDocumentationRoute(root, file);
            string relative = NormalizeDocumentationPath(Path.GetRelativePath(root, file));
            string[] lines = File.ReadAllLines(file);
            bool fenced = false;

            for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
            {
                string line = lines[lineIndex];
                if (IsFenceDelimiter(line))
                {
                    fenced = !fenced;
                    continue;
                }

                if (fenced)
                {
                    continue;
                }

                ValidateLineLinks(root, file, relative, route, line, lineIndex + 1, routes, anchors, violations);
            }
        }

        return violations;
    }

    private static void ValidateLineLinks(
        string root,
        string file,
        string relative,
        string route,
        string line,
        int lineNumber,
        Dictionary<string, string> routes,
        Dictionary<string, HashSet<string>> anchors,
        List<string> violations)
    {
        foreach (string target in EnumerateMarkdownLinkTargets(line))
        {
            ValidateLinkTarget(root, file, relative, route, lineNumber, target, routes, anchors, violations);
        }

        foreach (string target in EnumerateHtmlHrefTargets(line))
        {
            ValidateLinkTarget(root, file, relative, route, lineNumber, target, routes, anchors, violations);
        }
    }

    private static void ValidateLinkTarget(
        string root,
        string file,
        string relative,
        string route,
        int lineNumber,
        string target,
        Dictionary<string, string> routes,
        Dictionary<string, HashSet<string>> anchors,
        List<string> violations)
    {
        string value = NormalizeLinkTarget(target);
        if (value.Length == 0 || IsExternalLinkTarget(value))
        {
            return;
        }

        SplitLinkTarget(value, out string pathPart, out string fragment);
        if (!TryResolveDocumentationRoute(root, file, route, pathPart, out string linkedRoute)
            || !routes.ContainsKey(linkedRoute))
        {
            violations.Add($"{relative}:{lineNumber}: local link `{target}` points to a missing page");
            return;
        }

        if (fragment.Length == 0 || fragment.Equals("_top", StringComparison.Ordinal))
        {
            return;
        }

        string decodedFragment = Uri.UnescapeDataString(fragment);
        if (!anchors[linkedRoute].Contains(decodedFragment))
        {
            violations.Add($"{relative}:{lineNumber}: local link `{target}` points to missing fragment `#{decodedFragment}`");
        }
    }

    private static bool TryResolveDocumentationRoute(
        string root,
        string file,
        string route,
        string pathPart,
        out string linkedRoute)
    {
        linkedRoute = route;

        if (pathPart.Length == 0)
        {
            return true;
        }

        string normalizedPath = pathPart.Replace('\\', '/');
        if (normalizedPath.StartsWith('/'))
        {
            if (normalizedPath.Equals("/picket", StringComparison.Ordinal))
            {
                linkedRoute = string.Empty;
                return true;
            }

            if (!normalizedPath.StartsWith("/picket/", StringComparison.Ordinal))
            {
                return false;
            }

            linkedRoute = NormalizeRoute(normalizedPath["/picket/".Length..]);
            return true;
        }

        if (normalizedPath.EndsWith(".md", StringComparison.OrdinalIgnoreCase)
            || normalizedPath.EndsWith(".mdx", StringComparison.OrdinalIgnoreCase))
        {
            string directory = Path.GetDirectoryName(file) ?? root;
            string resolvedPath = Path.GetFullPath(Path.Combine(directory, normalizedPath.Replace('/', Path.DirectorySeparatorChar)));
            if (!IsPathWithinRoot(root, resolvedPath))
            {
                return false;
            }

            linkedRoute = GetDocumentationRoute(root, resolvedPath);
            return true;
        }

        linkedRoute = NormalizeRoute(CombineRoute(GetRouteDirectory(route), normalizedPath));
        return true;
    }

    private static string GetDocumentationRoute(string root, string file)
    {
        string relative = NormalizeDocumentationPath(Path.GetRelativePath(root, file));
        int extensionIndex = relative.LastIndexOf('.');
        if (extensionIndex >= 0)
        {
            relative = relative[..extensionIndex];
        }

        return NormalizeRoute(relative);
    }

    private static string NormalizeRoute(string value)
    {
        string route = value.Replace('\\', '/').Trim('/');
        if (route.Equals("index", StringComparison.Ordinal))
        {
            return string.Empty;
        }

        if (route.EndsWith("/index", StringComparison.Ordinal))
        {
            route = route[..^"/index".Length];
        }

        if (route.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
        {
            route = route[..^".html".Length];
        }

        return route;
    }

    private static string GetRouteDirectory(string route)
    {
        int separatorIndex = route.LastIndexOf('/');
        return separatorIndex < 0 ? string.Empty : route[..separatorIndex];
    }

    private static string CombineRoute(string baseRoute, string relativePath)
    {
        var segments = new List<string>();
        AddRouteSegments(segments, baseRoute);
        AddRouteSegments(segments, relativePath);
        return string.Join('/', segments);
    }

    private static void AddRouteSegments(List<string> segments, string value)
    {
        foreach (string rawSegment in value.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            string segment = rawSegment.Trim();
            if (segment.Length == 0 || segment.Equals(".", StringComparison.Ordinal))
            {
                continue;
            }

            if (segment.Equals("..", StringComparison.Ordinal))
            {
                if (segments.Count != 0)
                {
                    segments.RemoveAt(segments.Count - 1);
                }

                continue;
            }

            segments.Add(segment);
        }
    }

    private static HashSet<string> ReadDocumentationAnchors(string file)
    {
        string[] lines = File.ReadAllLines(file);
        var anchors = new HashSet<string>(StringComparer.Ordinal)
        {
            "_top",
        };
        var slugCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        bool fenced = false;

        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i];
            if (IsFenceDelimiter(line))
            {
                fenced = !fenced;
                continue;
            }

            if (fenced)
            {
                continue;
            }

            if (TryReadHeadingText(line, out string headingText))
            {
                string slug = CreateHeadingSlug(headingText);
                if (slug.Length != 0)
                {
                    anchors.Add(GetUniqueHeadingSlug(slugCounts, slug));
                }
            }

            foreach (string id in EnumerateHtmlIdTargets(line))
            {
                anchors.Add(id);
            }
        }

        return anchors;
    }

    private static bool TryReadHeadingText(string line, out string text)
    {
        text = string.Empty;
        int index = 0;
        while (index < line.Length && line[index] == '#')
        {
            index++;
        }

        if (index is 0 or > 6 || index >= line.Length || !char.IsWhiteSpace(line[index]))
        {
            return false;
        }

        text = line[index..].Trim();
        while (text.EndsWith('#'))
        {
            text = text[..^1].TrimEnd();
        }

        return text.Length != 0;
    }

    private static string CreateHeadingSlug(string heading)
    {
        var builder = new StringBuilder(heading.Length);
        bool previousDash = false;
        bool inHtmlTag = false;

        for (int i = 0; i < heading.Length; i++)
        {
            char c = heading[i];
            if (c == '<')
            {
                inHtmlTag = true;
                continue;
            }

            if (inHtmlTag)
            {
                if (c == '>')
                {
                    inHtmlTag = false;
                }

                continue;
            }

            if (c == '`')
            {
                continue;
            }

            if (char.IsLetterOrDigit(c))
            {
                builder.Append(char.ToLowerInvariant(c));
                previousDash = false;
                continue;
            }

            if (char.IsWhiteSpace(c) || c == '-')
            {
                if (builder.Length != 0 && !previousDash)
                {
                    builder.Append('-');
                    previousDash = true;
                }
            }
        }

        if (builder.Length != 0 && builder[^1] == '-')
        {
            builder.Length--;
        }

        return builder.ToString();
    }

    private static string GetUniqueHeadingSlug(Dictionary<string, int> slugCounts, string slug)
    {
        int count = slugCounts.GetValueOrDefault(slug);
        slugCounts[slug] = count + 1;
        return count == 0 ? slug : string.Create(CultureInfo.InvariantCulture, $"{slug}-{count}");
    }

    private static List<string> EnumerateMarkdownLinkTargets(string line)
    {
        var targets = new List<string>();
        int index = 0;
        while (index < line.Length)
        {
            int start = line.IndexOf("](", index, StringComparison.Ordinal);
            if (start < 0)
            {
                break;
            }

            int targetStart = start + 2;
            int targetEnd = FindMarkdownLinkTargetEnd(line, targetStart);
            if (targetEnd < 0)
            {
                break;
            }

            targets.Add(line[targetStart..targetEnd]);
            index = targetEnd + 1;
        }

        return targets;
    }

    private static int FindMarkdownLinkTargetEnd(string line, int start)
    {
        int depth = 0;
        bool escaped = false;
        for (int i = start; i < line.Length; i++)
        {
            char c = line[i];
            if (escaped)
            {
                escaped = false;
                continue;
            }

            if (c == '\\')
            {
                escaped = true;
                continue;
            }

            if (c == '(')
            {
                depth++;
                continue;
            }

            if (c == ')')
            {
                if (depth == 0)
                {
                    return i;
                }

                depth--;
            }
        }

        return -1;
    }

    private static List<string> EnumerateHtmlHrefTargets(string line)
    {
        return EnumerateHtmlAttributeValues(line, "href");
    }

    private static List<string> EnumerateHtmlIdTargets(string line)
    {
        return EnumerateHtmlAttributeValues(line, "id");
    }

    private static List<string> EnumerateHtmlAttributeValues(string line, string attributeName)
    {
        var values = new List<string>();
        string prefix = string.Concat(attributeName, "=");
        int index = 0;
        while (index < line.Length)
        {
            int start = line.IndexOf(prefix, index, StringComparison.OrdinalIgnoreCase);
            if (start < 0)
            {
                break;
            }

            int quoteIndex = start + prefix.Length;
            if (quoteIndex >= line.Length || (line[quoteIndex] != '"' && line[quoteIndex] != '\''))
            {
                index = quoteIndex;
                continue;
            }

            char quote = line[quoteIndex];
            int valueStart = quoteIndex + 1;
            int valueEnd = line.IndexOf(quote, valueStart);
            if (valueEnd < 0)
            {
                break;
            }

            values.Add(line[valueStart..valueEnd]);
            index = valueEnd + 1;
        }

        return values;
    }

    private static string NormalizeLinkTarget(string target)
    {
        string value = target.Trim();
        if (value.StartsWith('<') && value.EndsWith('>'))
        {
            value = value[1..^1].Trim();
        }

        int whitespaceIndex = value.IndexOfAny([' ', '\t']);
        return whitespaceIndex < 0 ? value : value[..whitespaceIndex];
    }

    private static void SplitLinkTarget(string target, out string pathPart, out string fragment)
    {
        int fragmentIndex = target.IndexOf('#');
        fragment = fragmentIndex < 0 ? string.Empty : target[(fragmentIndex + 1)..];
        pathPart = fragmentIndex < 0 ? target : target[..fragmentIndex];

        int queryIndex = pathPart.IndexOf('?');
        if (queryIndex >= 0)
        {
            pathPart = pathPart[..queryIndex];
        }
    }

    private static bool IsExternalLinkTarget(string target)
    {
        if (target.StartsWith("//", StringComparison.Ordinal))
        {
            return true;
        }

        int schemeIndex = target.IndexOf(':');
        if (schemeIndex <= 0)
        {
            return false;
        }

        int separatorIndex = target.IndexOfAny(['/', '#', '?']);
        return separatorIndex < 0 || schemeIndex < separatorIndex;
    }

    private static bool IsFenceDelimiter(string line)
    {
        string trimmed = line.TrimStart();
        return trimmed.StartsWith("```", StringComparison.Ordinal)
            || trimmed.StartsWith("~~~", StringComparison.Ordinal);
    }

    private static bool IsPathWithinRoot(string root, string path)
    {
        string normalizedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string normalizedPath = Path.GetFullPath(path);
        return normalizedPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeDocumentationPath(string value)
    {
        return value.Replace('\\', '/');
    }
}
