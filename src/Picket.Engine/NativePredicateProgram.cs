using Scout.Text.Regex;
using System.Buffers;
using System.Text;

namespace Picket.Engine;

internal sealed class NativePredicateProgram(
    NativePredicateInstruction[] instructions,
    NativePredicateValue[] constants,
    ByteRegex[] regexes)
{
    private const int MaxDynamicStringCharacters = 65_536;
    private const int MaxListItems = 256;
    private const int MaxStackDepth = 64;

    private readonly NativePredicateValue[] _constants =
        constants ?? throw new ArgumentNullException(nameof(constants));
    private readonly NativePredicateInstruction[] _instructions =
        instructions ?? throw new ArgumentNullException(nameof(instructions));
    private readonly ByteRegex[] _regexes =
        regexes ?? throw new ArgumentNullException(nameof(regexes));

    internal bool Evaluate(NativePredicateEvaluationContext context)
    {
        NativePredicateValue[] stack = ArrayPool<NativePredicateValue>.Shared.Rent(MaxStackDepth);
        int stackCount = 0;
        try
        {
            int instructionIndex = 0;
            while (instructionIndex < _instructions.Length)
            {
                NativePredicateInstruction instruction = _instructions[instructionIndex];
                switch (instruction.OpCode)
                {
                    case NativePredicateOpCode.PushField:
                        if (!TryPush(
                            stack,
                            ref stackCount,
                            context.GetValue((NativePredicateField)instruction.Operand)))
                        {
                            return false;
                        }

                        instructionIndex++;
                        break;

                    case NativePredicateOpCode.PushConstant:
                        if (!TryPush(stack, ref stackCount, _constants[instruction.Operand]))
                        {
                            return false;
                        }

                        instructionIndex++;
                        break;

                    case NativePredicateOpCode.Not:
                        if (stackCount == 0
                            || stack[stackCount - 1].Kind != NativePredicateValueKind.Boolean)
                        {
                            return false;
                        }

                        stack[stackCount - 1] =
                            NativePredicateValue.FromBoolean(!stack[stackCount - 1].Boolean);
                        instructionIndex++;
                        break;

                    case NativePredicateOpCode.JumpIfFalse:
                    case NativePredicateOpCode.JumpIfTrue:
                        if (!TryApplyConditionalJump(
                            instruction,
                            stack,
                            ref stackCount,
                            ref instructionIndex))
                        {
                            return false;
                        }

                        break;

                    case NativePredicateOpCode.Matches:
                        if (stackCount == 0
                            || !TryMatch(
                                stack[stackCount - 1],
                                _regexes[instruction.Operand],
                                out bool matches))
                        {
                            return false;
                        }

                        stack[stackCount - 1] = NativePredicateValue.FromBoolean(matches);
                        instructionIndex++;
                        break;

                    default:
                        if (!TryApplyBinary(instruction.OpCode, stack, ref stackCount))
                        {
                            return false;
                        }

                        instructionIndex++;
                        break;
                }
            }

            return stackCount == 1
                && stack[0].Kind == NativePredicateValueKind.Boolean
                && stack[0].Boolean;
        }
        finally
        {
            ArrayPool<NativePredicateValue>.Shared.Return(stack, clearArray: true);
        }
    }

    private static bool TryApplyConditionalJump(
        NativePredicateInstruction instruction,
        NativePredicateValue[] stack,
        ref int stackCount,
        ref int instructionIndex)
    {
        if (stackCount == 0
            || stack[stackCount - 1].Kind != NativePredicateValueKind.Boolean)
        {
            return false;
        }

        bool jump = instruction.OpCode == NativePredicateOpCode.JumpIfTrue
            ? stack[stackCount - 1].Boolean
            : !stack[stackCount - 1].Boolean;
        if (jump)
        {
            instructionIndex = instruction.Operand;
        }
        else
        {
            stackCount--;
            instructionIndex++;
        }

        return true;
    }

    private static bool TryApplyBinary(
        NativePredicateOpCode operation,
        NativePredicateValue[] stack,
        ref int stackCount)
    {
        if (stackCount < 2)
        {
            return false;
        }

        NativePredicateValue right = stack[--stackCount];
        NativePredicateValue left = stack[stackCount - 1];
        if (!TryEvaluateBinary(operation, left, right, out bool result))
        {
            return false;
        }

        stack[stackCount - 1] = NativePredicateValue.FromBoolean(result);
        return true;
    }

    private static bool TryEvaluateBinary(
        NativePredicateOpCode operation,
        NativePredicateValue left,
        NativePredicateValue right,
        out bool result)
    {
        result = false;
        switch (operation)
        {
            case NativePredicateOpCode.Equal:
            case NativePredicateOpCode.NotEqual:
                if (!TryEqual(left, right, out bool equal))
                {
                    return false;
                }

                result = operation == NativePredicateOpCode.Equal ? equal : !equal;
                return true;

            case NativePredicateOpCode.LessThan:
                result = left.Number < right.Number;
                return true;
            case NativePredicateOpCode.LessThanOrEqual:
                result = left.Number <= right.Number;
                return true;
            case NativePredicateOpCode.GreaterThan:
                result = left.Number > right.Number;
                return true;
            case NativePredicateOpCode.GreaterThanOrEqual:
                result = left.Number >= right.Number;
                return true;

            case NativePredicateOpCode.Contains:
                return TryContains(left, right, out result);

            case NativePredicateOpCode.StartsWith:
                if (!TryGetBoundedString(left, out string? startsWithValue)
                    || !TryGetBoundedString(right, out string? startsWithPrefix))
                {
                    return false;
                }

                result = startsWithValue.StartsWith(startsWithPrefix, StringComparison.Ordinal);
                return true;

            case NativePredicateOpCode.EndsWith:
                if (!TryGetBoundedString(left, out string? endsWithValue)
                    || !TryGetBoundedString(right, out string? endsWithSuffix))
                {
                    return false;
                }

                result = endsWithValue.EndsWith(endsWithSuffix, StringComparison.Ordinal);
                return true;

            default:
                return false;
        }
    }

    private static bool TryEqual(
        NativePredicateValue left,
        NativePredicateValue right,
        out bool result)
    {
        result = false;
        if (left.Kind != right.Kind)
        {
            return false;
        }

        switch (left.Kind)
        {
            case NativePredicateValueKind.Boolean:
                result = left.Boolean == right.Boolean;
                return true;
            case NativePredicateValueKind.Number:
                result = left.Number == right.Number;
                return true;
            case NativePredicateValueKind.String:
                if (!TryGetBoundedString(left, out string? leftText)
                    || !TryGetBoundedString(right, out string? rightText))
                {
                    return false;
                }

                result = leftText.Equals(rightText, StringComparison.Ordinal);
                return true;
            default:
                return false;
        }
    }

    private static bool TryContains(
        NativePredicateValue left,
        NativePredicateValue right,
        out bool result)
    {
        result = false;
        if (!TryGetBoundedString(right, out string? expected))
        {
            return false;
        }

        if (left.Kind == NativePredicateValueKind.String)
        {
            if (!TryGetBoundedString(left, out string? value))
            {
                return false;
            }

            result = value.Contains(expected, StringComparison.Ordinal);
            return true;
        }

        IReadOnlyList<string>? values = left.Strings;
        if (left.Kind != NativePredicateValueKind.StringList
            || values is null
            || values.Count > MaxListItems)
        {
            return false;
        }

        for (int i = 0; i < values.Count; i++)
        {
            string value = values[i];
            if (value.Length > MaxDynamicStringCharacters)
            {
                return false;
            }

            if (value.Equals(expected, StringComparison.Ordinal))
            {
                result = true;
                return true;
            }
        }

        return true;
    }

    private static bool TryMatch(
        NativePredicateValue value,
        ByteRegex regex,
        out bool result)
    {
        result = false;
        if (!TryGetBoundedString(value, out string? text))
        {
            return false;
        }

        int byteCount = Encoding.UTF8.GetByteCount(text);
        if (byteCount > MaxDynamicStringCharacters * 4)
        {
            return false;
        }

        byte[] bytes = ArrayPool<byte>.Shared.Rent(Math.Max(byteCount, 1));
        try
        {
            int written = Encoding.UTF8.GetBytes(text, bytes);
            result = regex.IsMatch(bytes.AsSpan(0, written));
            return true;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(bytes, clearArray: true);
        }
    }

    private static bool TryGetBoundedString(
        NativePredicateValue value,
        out string text)
    {
        text = value.Text ?? string.Empty;
        return value.Kind == NativePredicateValueKind.String
            && text.Length <= MaxDynamicStringCharacters;
    }

    private static bool TryPush(
        NativePredicateValue[] stack,
        ref int stackCount,
        NativePredicateValue value)
    {
        if (stackCount >= MaxStackDepth)
        {
            return false;
        }

        stack[stackCount++] = value;
        return true;
    }
}
