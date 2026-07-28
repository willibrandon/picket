using System.Text;

namespace Picket.Engine;

internal static class NativePredicateCompiler
{
    internal const int MaxExpressionUtf8Bytes = 4096;
    internal const int MaxInstructionCount = 512;
    internal const int MaxLiteralUtf8Bytes = 1024;
    internal const int MaxNestingDepth = 16;
    internal const int MaxRegexCount = 32;
    internal const int MaxTokenCount = 256;

    internal static NativePredicateProgram? CompileOptional(
        string expression,
        bool allowFindingFields,
        string context)
    {
        ArgumentNullException.ThrowIfNull(expression);
        ArgumentException.ThrowIfNullOrWhiteSpace(context);
        if (string.IsNullOrWhiteSpace(expression))
        {
            return null;
        }

        if (Encoding.UTF8.GetByteCount(expression) > MaxExpressionUtf8Bytes)
        {
            throw new InvalidDataException(
                $"{context}: native predicate exceeds the {MaxExpressionUtf8Bytes}-byte UTF-8 limit");
        }

        return new NativePredicateParser(expression, allowFindingFields, context).Parse();
    }
}
