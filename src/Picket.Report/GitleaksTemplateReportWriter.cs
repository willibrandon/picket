using System.Globalization;
using System.Text;
using Picket.Engine;

namespace Picket.Report;

/// <summary>
/// Writes Gitleaks template reports for common Go <c>text/template</c> report templates.
/// </summary>
public static class GitleaksTemplateReportWriter
{
    private static readonly string[] s_blockActions = ["if", "range", "with"];
    private static readonly string[] s_forbiddenFunctions = ["env", "expandenv", "getHostByName"];

    /// <summary>
    /// Renders findings with a Gitleaks-compatible template.
    /// </summary>
    /// <param name="findings">The findings to report.</param>
    /// <param name="templateText">The template text.</param>
    /// <returns>The rendered report.</returns>
    public static string Write(IReadOnlyList<Finding> findings, string templateText)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(templateText);

        var variables = new Dictionary<string, object?>(StringComparer.Ordinal);
        var builder = new StringBuilder(templateText.Length + findings.Count * 64);
        int index = 0;
        RenderTemplate(templateText, ref index, findings, findings, variables, builder, stopAtEnd: false);
        return builder.ToString();
    }

    private static bool RenderTemplate(
        string templateText,
        ref int index,
        object? root,
        object? dot,
        Dictionary<string, object?> variables,
        StringBuilder builder,
        bool stopAtEnd)
    {
        bool trimNextText = false;
        while (index < templateText.Length)
        {
            int actionStart = templateText.IndexOf("{{", index, StringComparison.Ordinal);
            if (actionStart < 0)
            {
                AppendText(builder, templateText[index..], ref trimNextText);
                index = templateText.Length;
                return false;
            }

            AppendText(builder, templateText[index..actionStart], ref trimNextText);

            int actionContentStart = actionStart + 2;
            bool leftTrim = actionContentStart < templateText.Length && templateText[actionContentStart] == '-';
            if (leftTrim)
            {
                TrimTrailingWhitespace(builder);
                actionContentStart++;
            }

            int actionEnd = templateText.IndexOf("}}", actionContentStart, StringComparison.Ordinal);
            if (actionEnd < 0)
            {
                throw new InvalidDataException("template action is missing a closing delimiter");
            }

            int actionContentEnd = actionEnd;
            bool rightTrim = actionContentEnd > actionContentStart && templateText[actionContentEnd - 1] == '-';
            if (rightTrim)
            {
                actionContentEnd--;
            }

            string action = templateText[actionContentStart..actionContentEnd].Trim();
            index = actionEnd + 2;
            if (action.Length == 0)
            {
                trimNextText = rightTrim;
                continue;
            }

            if (action.Equals("end", StringComparison.Ordinal))
            {
                if (stopAtEnd)
                {
                    trimNextText = rightTrim;
                    return true;
                }

                throw new InvalidDataException("template end action does not match a block action");
            }

            if (IsAction(action, "range"))
            {
                string body = ExtractBlock(templateText, index, out index, out bool endRightTrim);
                if (rightTrim)
                {
                    body = TrimLeadingWhitespace(body);
                }

                RenderRange(action, body, root, dot, variables, builder);
                trimNextText = endRightTrim;
                continue;
            }

            if (IsAction(action, "with"))
            {
                string body = ExtractBlock(templateText, index, out index, out bool endRightTrim);
                if (rightTrim)
                {
                    body = TrimLeadingWhitespace(body);
                }

                object? value = EvaluateExpression(action["with".Length..], root, dot, variables);
                if (IsTruthy(value))
                {
                    int bodyIndex = 0;
                    RenderTemplate(body, ref bodyIndex, root, value, variables, builder, stopAtEnd: false);
                }

                trimNextText = endRightTrim;
                continue;
            }

            if (IsAction(action, "if"))
            {
                string body = ExtractBlock(templateText, index, out index, out bool endRightTrim);
                if (rightTrim)
                {
                    body = TrimLeadingWhitespace(body);
                }

                object? value = EvaluateExpression(action["if".Length..], root, dot, variables);
                if (IsTruthy(value))
                {
                    int bodyIndex = 0;
                    RenderTemplate(body, ref bodyIndex, root, dot, variables, builder, stopAtEnd: false);
                }

                trimNextText = endRightTrim;
                continue;
            }

            if (!TryAssignVariable(action, root, dot, variables))
            {
                object? value = EvaluateExpression(action, root, dot, variables);
                builder.Append(FormatTemplateValue(value));
            }

            trimNextText = rightTrim;
        }

        return false;
    }

    private static void RenderRange(
        string action,
        string body,
        object? root,
        object? dot,
        Dictionary<string, object?> variables,
        StringBuilder builder)
    {
        string rangeExpression = action["range".Length..].Trim();
        string collectionExpression = rangeExpression;
        string? indexVariable = null;
        string? valueVariable = null;
        int assignmentIndex = rangeExpression.IndexOf(":=", StringComparison.Ordinal);
        if (assignmentIndex >= 0)
        {
            string variableList = rangeExpression[..assignmentIndex].Trim();
            collectionExpression = rangeExpression[(assignmentIndex + 2)..].Trim();
            string[] variableNames = variableList.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (variableNames.Length == 1)
            {
                valueVariable = variableNames[0];
            }
            else if (variableNames.Length == 2)
            {
                indexVariable = variableNames[0];
                valueVariable = variableNames[1];
            }
            else
            {
                throw new InvalidDataException($"unsupported template range variables: {variableList}");
            }
        }

        object? collection = EvaluateExpression(collectionExpression, root, dot, variables);
        int count = GetCollectionCount(collection);
        for (int i = 0; i < count; i++)
        {
            object? item = GetCollectionItem(collection, i);
            var childVariables = new Dictionary<string, object?>(variables, StringComparer.Ordinal);
            if (!string.IsNullOrEmpty(indexVariable))
            {
                childVariables[indexVariable] = i;
            }

            if (!string.IsNullOrEmpty(valueVariable))
            {
                childVariables[valueVariable] = item;
            }

            int bodyIndex = 0;
            RenderTemplate(body, ref bodyIndex, root, item, childVariables, builder, stopAtEnd: false);
        }
    }

    private static bool TryAssignVariable(
        string action,
        object? root,
        object? dot,
        Dictionary<string, object?> variables)
    {
        int assignmentIndex = action.IndexOf(":=", StringComparison.Ordinal);
        if (assignmentIndex < 0)
        {
            return false;
        }

        string name = action[..assignmentIndex].Trim();
        if (!name.StartsWith('$'))
        {
            throw new InvalidDataException($"unsupported template assignment target: {name}");
        }

        string expression = action[(assignmentIndex + 2)..].Trim();
        variables[name] = EvaluateExpression(expression, root, dot, variables);
        return true;
    }

    private static string ExtractBlock(string templateText, int bodyStartIndex, out int nextIndex, out bool endRightTrim)
    {
        int depth = 1;
        int searchIndex = bodyStartIndex;
        while (searchIndex < templateText.Length)
        {
            int actionStart = templateText.IndexOf("{{", searchIndex, StringComparison.Ordinal);
            if (actionStart < 0)
            {
                break;
            }

            int actionContentStart = actionStart + 2;
            bool leftTrim = actionContentStart < templateText.Length && templateText[actionContentStart] == '-';
            if (leftTrim)
            {
                actionContentStart++;
            }

            int actionEnd = templateText.IndexOf("}}", actionContentStart, StringComparison.Ordinal);
            if (actionEnd < 0)
            {
                throw new InvalidDataException("template action is missing a closing delimiter");
            }

            int actionContentEnd = actionEnd;
            bool rightTrim = actionContentEnd > actionContentStart && templateText[actionContentEnd - 1] == '-';
            if (rightTrim)
            {
                actionContentEnd--;
            }

            string action = templateText[actionContentStart..actionContentEnd].Trim();
            if (IsBlockAction(action))
            {
                depth++;
            }
            else if (action.Equals("end", StringComparison.Ordinal))
            {
                depth--;
                if (depth == 0)
                {
                    string body = templateText[bodyStartIndex..actionStart];
                    if (leftTrim)
                    {
                        body = TrimTrailingWhitespace(body);
                    }

                    nextIndex = actionEnd + 2;
                    endRightTrim = rightTrim;
                    return body;
                }
            }

            searchIndex = actionEnd + 2;
        }

        throw new InvalidDataException("template block is missing an end action");
    }

    private static object? EvaluateExpression(
        string expression,
        object? root,
        object? dot,
        Dictionary<string, object?> variables)
    {
        expression = StripEnclosingParentheses(expression.Trim());
        List<string> pipeline = SplitTopLevel(expression, '|');
        if (pipeline.Count > 1)
        {
            object? value = EvaluateExpression(pipeline[0], root, dot, variables);
            for (int i = 1; i < pipeline.Count; i++)
            {
                value = EvaluatePipelineStep(pipeline[i], value, root, dot, variables);
            }

            return value;
        }

        return EvaluateExpressionCore(expression, root, dot, variables);
    }

    private static object? EvaluateExpressionCore(
        string expression,
        object? root,
        object? dot,
        Dictionary<string, object?> variables)
    {
        expression = StripEnclosingParentheses(expression.Trim());
        if (expression.Length == 0)
        {
            return string.Empty;
        }

        foreach (string forbiddenFunction in s_forbiddenFunctions)
        {
            if (IsAction(expression, forbiddenFunction))
            {
                throw new InvalidDataException($"function \"{forbiddenFunction}\" not defined");
            }
        }

        if (expression.Equals("now", StringComparison.Ordinal))
        {
            return DateTimeOffset.Now;
        }

        if (IsAction(expression, "quote"))
        {
            object? value = EvaluateExpression(expression["quote".Length..], root, dot, variables);
            return Quote(FormatTemplateValue(value));
        }

        if (IsAction(expression, "len"))
        {
            object? value = EvaluateExpression(expression["len".Length..], root, dot, variables);
            return GetCollectionCount(value);
        }

        if (IsAction(expression, "sub"))
        {
            List<string> arguments = SplitArguments(expression["sub".Length..]);
            if (arguments.Count != 2)
            {
                throw new InvalidDataException("template function sub requires two arguments");
            }

            int left = ConvertToInt32(EvaluateExpression(arguments[0], root, dot, variables));
            int right = ConvertToInt32(EvaluateExpression(arguments[1], root, dot, variables));
            return left - right;
        }

        if (IsAction(expression, "ne"))
        {
            List<string> arguments = SplitArguments(expression["ne".Length..]);
            if (arguments.Count != 2)
            {
                throw new InvalidDataException("template function ne requires two arguments");
            }

            object? left = EvaluateExpression(arguments[0], root, dot, variables);
            object? right = EvaluateExpression(arguments[1], root, dot, variables);
            return !Equals(left, right);
        }

        if (expression[0] == '$')
        {
            if (variables.TryGetValue(expression, out object? value))
            {
                return value;
            }

            throw new InvalidDataException($"template variable {expression} is not defined");
        }

        if (expression.Equals(".", StringComparison.Ordinal))
        {
            return dot;
        }

        if (expression[0] == '.')
        {
            return ResolvePath(dot, expression[1..]);
        }

        if (expression.Length >= 2 && expression[0] == '"' && expression[^1] == '"')
        {
            return Unquote(expression);
        }

        if (int.TryParse(expression, NumberStyles.Integer, CultureInfo.InvariantCulture, out int integer))
        {
            return integer;
        }

        if (double.TryParse(expression, NumberStyles.Float, CultureInfo.InvariantCulture, out double number))
        {
            return number;
        }

        if (ReferenceEquals(root, dot) && root is IReadOnlyList<Finding> && expression.Equals("nil", StringComparison.Ordinal))
        {
            return null;
        }

        string functionName = ReadIdentifier(expression);
        if (functionName.Length != 0)
        {
            throw new InvalidDataException($"unsupported template function: {functionName}");
        }

        throw new InvalidDataException($"unsupported template expression: {expression}");
    }

    private static object? EvaluatePipelineStep(
        string step,
        object? input,
        object? root,
        object? dot,
        Dictionary<string, object?> variables)
    {
        step = step.Trim();
        if (IsAction(step, "date"))
        {
            List<string> arguments = SplitArguments(step["date".Length..]);
            if (arguments.Count != 1)
            {
                throw new InvalidDataException("template function date requires one argument");
            }

            string format = FormatTemplateValue(EvaluateExpression(arguments[0], root, dot, variables));
            return FormatDate(input, format);
        }

        throw new InvalidDataException($"unsupported template pipeline function: {step}");
    }

    private static object? ResolvePath(object? value, string path)
    {
        object? current = value;
        foreach (string segment in path.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            if (current is Finding finding)
            {
                current = ResolveFindingField(finding, segment);
                continue;
            }

            throw new InvalidDataException($"unsupported template field: {segment}");
        }

        return current;
    }

    private static object? ResolveFindingField(Finding finding, string field)
    {
        return field switch
        {
            "Author" => finding.Author,
            "Commit" => finding.Commit,
            "Date" => finding.Date,
            "Description" => finding.Description,
            "Email" => finding.Email,
            "EndColumn" => finding.EndColumn,
            "EndLine" => finding.EndLine,
            "Entropy" => finding.Entropy,
            "File" => finding.File,
            "Fingerprint" => finding.Fingerprint,
            "Line" => finding.Line,
            "Match" => finding.Match,
            "Message" => finding.Message,
            "RuleID" => finding.RuleID,
            "Secret" => finding.Secret,
            "StartColumn" => finding.StartColumn,
            "StartLine" => finding.StartLine,
            "SymlinkFile" => finding.SymlinkFile,
            "Tags" => finding.Tags,
            _ => throw new InvalidDataException($"unsupported template finding field: {field}"),
        };
    }

    private static int GetCollectionCount(object? value)
    {
        return value switch
        {
            null => 0,
            string text => text.Length,
            IReadOnlyList<Finding> findings => findings.Count,
            IReadOnlyList<string> values => values.Count,
            _ => throw new InvalidDataException($"template value does not have a length: {value.GetType().Name}"),
        };
    }

    private static object? GetCollectionItem(object? value, int index)
    {
        return value switch
        {
            IReadOnlyList<Finding> findings => findings[index],
            IReadOnlyList<string> values => values[index],
            string text => text[index].ToString(),
            _ => throw new InvalidDataException($"template value is not rangeable: {value?.GetType().Name ?? "null"}"),
        };
    }

    private static int ConvertToInt32(object? value)
    {
        return value switch
        {
            int integer => integer,
            double number => (int)number,
            string text when int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out int integer) => integer,
            _ => throw new InvalidDataException($"template value is not an integer: {FormatTemplateValue(value)}"),
        };
    }

    private static bool IsTruthy(object? value)
    {
        return value switch
        {
            null => false,
            bool flag => flag,
            int integer => integer != 0,
            double number => number != 0,
            string text => text.Length != 0,
            IReadOnlyList<Finding> findings => findings.Count != 0,
            IReadOnlyList<string> values => values.Count != 0,
            _ => true,
        };
    }

    private static string FormatTemplateValue(object? value)
    {
        return value switch
        {
            null => string.Empty,
            bool flag => flag ? "true" : "false",
            double number => number.ToString("G17", CultureInfo.InvariantCulture),
            int integer => integer.ToString(CultureInfo.InvariantCulture),
            IReadOnlyList<string> values => string.Concat("[", string.Join(' ', values), "]"),
            DateTimeOffset dateTime => dateTime.ToString("O", CultureInfo.InvariantCulture),
            _ => value.ToString() ?? string.Empty,
        };
    }

    private static string FormatDate(object? value, string goFormat)
    {
        if (value is not DateTimeOffset dateTime)
        {
            throw new InvalidDataException("template function date requires a date input");
        }

        string dotNetFormat = goFormat
            .Replace("2006", "yyyy", StringComparison.Ordinal)
            .Replace("01", "MM", StringComparison.Ordinal)
            .Replace("02", "dd", StringComparison.Ordinal)
            .Replace("15", "HH", StringComparison.Ordinal)
            .Replace("04", "mm", StringComparison.Ordinal)
            .Replace("05", "ss", StringComparison.Ordinal);
        return dateTime.ToString(dotNetFormat, CultureInfo.InvariantCulture);
    }

    private static string ExtractActionText(string action)
    {
        return action.Trim();
    }

    private static bool IsAction(string action, string keyword)
    {
        string text = ExtractActionText(action);
        return text.Equals(keyword, StringComparison.Ordinal)
            || text.StartsWith(string.Concat(keyword, " "), StringComparison.Ordinal);
    }

    private static bool IsBlockAction(string action)
    {
        foreach (string blockAction in s_blockActions)
        {
            if (IsAction(action, blockAction))
            {
                return true;
            }
        }

        return false;
    }

    private static string ReadIdentifier(string text)
    {
        int index = 0;
        while (index < text.Length && char.IsLetter(text[index]))
        {
            index++;
        }

        return text[..index];
    }

    private static List<string> SplitArguments(string text)
    {
        return SplitTopLevel(text.Trim(), ' ');
    }

    private static List<string> SplitTopLevel(string text, char separator)
    {
        var parts = new List<string>();
        int start = -1;
        int depth = 0;
        bool inString = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (inString)
            {
                if (c == '\\')
                {
                    i++;
                }
                else if (c == '"')
                {
                    inString = false;
                }

                continue;
            }

            if (c == '"')
            {
                inString = true;
                if (start < 0)
                {
                    start = i;
                }

                continue;
            }

            if (c == '(')
            {
                depth++;
                if (start < 0)
                {
                    start = i;
                }

                continue;
            }

            if (c == ')')
            {
                depth--;
                continue;
            }

            bool isSeparator = separator == ' ' ? char.IsWhiteSpace(c) : c == separator;
            if (isSeparator && depth == 0)
            {
                if (start >= 0)
                {
                    parts.Add(text[start..i].Trim());
                    start = -1;
                }

                continue;
            }

            if (start < 0)
            {
                start = i;
            }
        }

        if (start >= 0)
        {
            parts.Add(text[start..].Trim());
        }

        parts.RemoveAll(static part => part.Length == 0);
        return parts;
    }

    private static string StripEnclosingParentheses(string expression)
    {
        while (expression.Length >= 2 && expression[0] == '(' && expression[^1] == ')' && EnclosingParenthesesWrapAll(expression))
        {
            expression = expression[1..^1].Trim();
        }

        return expression;
    }

    private static bool EnclosingParenthesesWrapAll(string expression)
    {
        int depth = 0;
        bool inString = false;
        for (int i = 0; i < expression.Length; i++)
        {
            char c = expression[i];
            if (inString)
            {
                if (c == '\\')
                {
                    i++;
                }
                else if (c == '"')
                {
                    inString = false;
                }

                continue;
            }

            if (c == '"')
            {
                inString = true;
                continue;
            }

            if (c == '(')
            {
                depth++;
            }
            else if (c == ')')
            {
                depth--;
                if (depth == 0 && i != expression.Length - 1)
                {
                    return false;
                }
            }
        }

        return depth == 0;
    }

    private static void AppendText(StringBuilder builder, string text, ref bool trimLeadingWhitespace)
    {
        if (trimLeadingWhitespace)
        {
            text = TrimLeadingWhitespace(text);
            trimLeadingWhitespace = false;
        }

        builder.Append(text);
    }

    private static void TrimTrailingWhitespace(StringBuilder builder)
    {
        while (builder.Length > 0 && char.IsWhiteSpace(builder[builder.Length - 1]))
        {
            builder.Length--;
        }
    }

    private static string TrimLeadingWhitespace(string text)
    {
        int index = 0;
        while (index < text.Length && char.IsWhiteSpace(text[index]))
        {
            index++;
        }

        return text[index..];
    }

    private static string TrimTrailingWhitespace(string text)
    {
        int end = text.Length;
        while (end > 0 && char.IsWhiteSpace(text[end - 1]))
        {
            end--;
        }

        return text[..end];
    }

    private static string Quote(string value)
    {
        var builder = new StringBuilder(value.Length + 2);
        AppendJsonString(builder, value);
        return builder.ToString();
    }

    private static string Unquote(string value)
    {
        var builder = new StringBuilder(value.Length);
        for (int i = 1; i < value.Length - 1; i++)
        {
            char c = value[i];
            if (c == '\\' && i + 1 < value.Length - 1)
            {
                char escaped = value[++i];
                builder.Append(escaped switch
                {
                    '"' => '"',
                    '\\' => '\\',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    _ => escaped,
                });
            }
            else
            {
                builder.Append(c);
            }
        }

        return builder.ToString();
    }

    private static void AppendJsonString(StringBuilder builder, string value)
    {
        builder.Append('"');
        foreach (Rune rune in value.EnumerateRunes())
        {
            switch (rune.Value)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if (rune.Value < 0x20)
                    {
                        builder.Append("\\u");
                        builder.Append(rune.Value.ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(rune.ToString());
                    }

                    break;
            }
        }

        builder.Append('"');
    }
}
