using Scout.Text.Regex;
using System.Globalization;
using System.Text;

namespace Picket.Engine;

internal sealed class NativePredicateParser
{
    private readonly bool _allowFindingFields;
    private readonly List<NativePredicateValue> _constants = [];
    private readonly string _context;
    private readonly List<NativePredicateInstruction> _instructions = [];
    private readonly List<ByteRegex> _regexes = [];
    private readonly string _source;
    private NativePredicateToken _current;
    private int _index;
    private int _tokenCount;

    internal NativePredicateParser(
        string source,
        bool allowFindingFields,
        string context)
    {
        _source = source;
        _allowFindingFields = allowFindingFields;
        _context = context;
        _current = ReadToken();
    }

    internal NativePredicateProgram Parse()
    {
        NativePredicateValueKind resultKind = ParseOr(0);
        if (resultKind != NativePredicateValueKind.Boolean)
        {
            Throw(_current.Position, "the complete expression must produce a boolean value");
        }

        Require(NativePredicateTokenKind.End, "unexpected trailing input");
        return new NativePredicateProgram(
            [.. _instructions],
            [.. _constants],
            [.. _regexes]);
    }

    private NativePredicateValueKind ParseOr(int nestingDepth)
    {
        NativePredicateValueKind kind = ParseAnd(nestingDepth);
        while (_current.Kind == NativePredicateTokenKind.Or)
        {
            RequireBoolean(kind, _current.Position, "'||' left operand");
            MoveNext();
            int jumpIndex = Emit(NativePredicateOpCode.JumpIfTrue);
            NativePredicateValueKind rightKind = ParseAnd(nestingDepth);
            RequireBoolean(rightKind, _current.Position, "'||' right operand");
            PatchJump(jumpIndex);
            kind = NativePredicateValueKind.Boolean;
        }

        return kind;
    }

    private NativePredicateValueKind ParseAnd(int nestingDepth)
    {
        NativePredicateValueKind kind = ParseComparison(nestingDepth);
        while (_current.Kind == NativePredicateTokenKind.And)
        {
            RequireBoolean(kind, _current.Position, "'&&' left operand");
            MoveNext();
            int jumpIndex = Emit(NativePredicateOpCode.JumpIfFalse);
            NativePredicateValueKind rightKind = ParseComparison(nestingDepth);
            RequireBoolean(rightKind, _current.Position, "'&&' right operand");
            PatchJump(jumpIndex);
            kind = NativePredicateValueKind.Boolean;
        }

        return kind;
    }

    private NativePredicateValueKind ParseUnary(int nestingDepth)
    {
        if (_current.Kind != NativePredicateTokenKind.Not)
        {
            return ParsePrimary(nestingDepth);
        }

        int position = _current.Position;
        MoveNext();
        NativePredicateValueKind kind = ParseUnary(nestingDepth);
        RequireBoolean(kind, position, "'!' operand");
        Emit(NativePredicateOpCode.Not);
        return NativePredicateValueKind.Boolean;
    }

    private NativePredicateValueKind ParseComparison(int nestingDepth)
    {
        NativePredicateValueKind leftKind = ParseUnary(nestingDepth);
        NativePredicateTokenKind operation = _current.Kind;
        if (!IsComparison(operation))
        {
            return leftKind;
        }

        int operationPosition = _current.Position;
        MoveNext();
        if (operation == NativePredicateTokenKind.Matches)
        {
            if (leftKind != NativePredicateValueKind.String)
            {
                Throw(operationPosition, "'matches' requires a string field or expression on the left");
            }

            if (_current.Kind != NativePredicateTokenKind.String)
            {
                Throw(_current.Position, "'matches' requires a string literal regex on the right");
            }

            int regexIndex = AddRegex(_current.Text, _current.Position);
            MoveNext();
            Emit(NativePredicateOpCode.Matches, regexIndex);
            return NativePredicateValueKind.Boolean;
        }

        NativePredicateValueKind rightKind = ParseUnary(nestingDepth);
        ValidateBinaryOperation(operation, leftKind, rightKind, operationPosition);
        Emit(ToOpCode(operation));
        return NativePredicateValueKind.Boolean;
    }

    private NativePredicateValueKind ParsePrimary(int nestingDepth)
    {
        switch (_current.Kind)
        {
            case NativePredicateTokenKind.LeftParenthesis:
                if (nestingDepth >= NativePredicateCompiler.MaxNestingDepth)
                {
                    Throw(_current.Position, $"parenthesis nesting exceeds {NativePredicateCompiler.MaxNestingDepth}");
                }

                MoveNext();
                NativePredicateValueKind nestedKind = ParseOr(nestingDepth + 1);
                Require(NativePredicateTokenKind.RightParenthesis, "expected ')'");
                MoveNext();
                return nestedKind;

            case NativePredicateTokenKind.Identifier:
                NativePredicateField field = ResolveField(_current.Text, _current.Position);
                MoveNext();
                Emit(NativePredicateOpCode.PushField, (int)field);
                return GetFieldKind(field);

            case NativePredicateTokenKind.String:
                int stringIndex = AddConstant(NativePredicateValue.FromString(_current.Text));
                MoveNext();
                Emit(NativePredicateOpCode.PushConstant, stringIndex);
                return NativePredicateValueKind.String;

            case NativePredicateTokenKind.Number:
                if (!double.TryParse(
                    _current.Text,
                    NumberStyles.Float,
                    CultureInfo.InvariantCulture,
                    out double number)
                    || !double.IsFinite(number))
                {
                    Throw(_current.Position, $"invalid finite number '{_current.Text}'");
                }

                int numberIndex = AddConstant(NativePredicateValue.FromNumber(number));
                MoveNext();
                Emit(NativePredicateOpCode.PushConstant, numberIndex);
                return NativePredicateValueKind.Number;

            case NativePredicateTokenKind.True:
            case NativePredicateTokenKind.False:
                bool boolean = _current.Kind == NativePredicateTokenKind.True;
                int booleanIndex = AddConstant(NativePredicateValue.FromBoolean(boolean));
                MoveNext();
                Emit(NativePredicateOpCode.PushConstant, booleanIndex);
                return NativePredicateValueKind.Boolean;

            default:
                Throw(_current.Position, "expected a field, literal, or parenthesized expression");
                return default;
        }
    }

    private NativePredicateField ResolveField(string name, int position)
    {
        NativePredicateField field = name switch
        {
            "source.path" => NativePredicateField.SourcePath,
            "source.symlink" => NativePredicateField.SourceSymlink,
            "finding.rule_id" => NativePredicateField.FindingRuleId,
            "finding.description" => NativePredicateField.FindingDescription,
            "finding.match" => NativePredicateField.FindingMatch,
            "finding.secret" => NativePredicateField.FindingSecret,
            "finding.line" => NativePredicateField.FindingLine,
            "finding.start_line" => NativePredicateField.FindingStartLine,
            "finding.end_line" => NativePredicateField.FindingEndLine,
            "finding.start_column" => NativePredicateField.FindingStartColumn,
            "finding.end_column" => NativePredicateField.FindingEndColumn,
            "finding.entropy" => NativePredicateField.FindingEntropy,
            "finding.randomness_score" => NativePredicateField.FindingRandomnessScore,
            "finding.decode_depth" => NativePredicateField.FindingDecodeDepth,
            "finding.is_decoded" => NativePredicateField.FindingIsDecoded,
            "finding.tags" => NativePredicateField.FindingTags,
            "finding.decode_path" => NativePredicateField.FindingDecodePath,
            "finding.severity" => NativePredicateField.FindingSeverity,
            "finding.confidence" => NativePredicateField.FindingConfidence,
            "finding.rule_pack" => NativePredicateField.FindingRulePack,
            "finding.provider" => NativePredicateField.FindingProvider,
            _ => throw CreateError(position, $"unknown field '{name}'"),
        };

        if (!_allowFindingFields && IsFindingField(field))
        {
            Throw(position, $"field '{name}' is not available to prefilters");
        }

        return field;
    }

    private int AddRegex(string pattern, int position)
    {
        if (_regexes.Count >= NativePredicateCompiler.MaxRegexCount)
        {
            Throw(position, $"regex count exceeds {NativePredicateCompiler.MaxRegexCount}");
        }

        try
        {
            _regexes.Add(GitleaksRegexCompiler.Compile(pattern));
        }
        catch (ByteRegexParseException exception)
        {
            throw CreateError(position, $"invalid 'matches' regex '{pattern}': {exception.Message}", exception);
        }

        return _regexes.Count - 1;
    }

    private int AddConstant(NativePredicateValue value)
    {
        _constants.Add(value);
        return _constants.Count - 1;
    }

    private int Emit(NativePredicateOpCode opCode, int operand = 0)
    {
        if (_instructions.Count >= NativePredicateCompiler.MaxInstructionCount)
        {
            Throw(_current.Position, $"instruction count exceeds {NativePredicateCompiler.MaxInstructionCount}");
        }

        _instructions.Add(new NativePredicateInstruction(opCode, operand));
        return _instructions.Count - 1;
    }

    private void PatchJump(int instructionIndex)
    {
        NativePredicateInstruction instruction = _instructions[instructionIndex];
        _instructions[instructionIndex] = new NativePredicateInstruction(
            instruction.OpCode,
            _instructions.Count);
    }

    private void MoveNext()
    {
        _current = ReadToken();
    }

    private NativePredicateToken ReadToken()
    {
        SkipWhitespace();
        if (++_tokenCount > NativePredicateCompiler.MaxTokenCount)
        {
            Throw(_index, $"token count exceeds {NativePredicateCompiler.MaxTokenCount}");
        }

        if (_index >= _source.Length)
        {
            return new NativePredicateToken(NativePredicateTokenKind.End, string.Empty, _index);
        }

        int position = _index;
        char ch = _source[_index++];
        return ch switch
        {
            '(' => new NativePredicateToken(NativePredicateTokenKind.LeftParenthesis, "(", position),
            ')' => new NativePredicateToken(NativePredicateTokenKind.RightParenthesis, ")", position),
            '&' => ReadRequiredPair('&', NativePredicateTokenKind.And, position),
            '|' => ReadRequiredPair('|', NativePredicateTokenKind.Or, position),
            '!' => ReadOptionalPair('=', NativePredicateTokenKind.NotEqual, NativePredicateTokenKind.Not, position),
            '=' => ReadRequiredPair('=', NativePredicateTokenKind.Equal, position),
            '<' => ReadOptionalPair('=', NativePredicateTokenKind.LessThanOrEqual, NativePredicateTokenKind.LessThan, position),
            '>' => ReadOptionalPair('=', NativePredicateTokenKind.GreaterThanOrEqual, NativePredicateTokenKind.GreaterThan, position),
            '"' or '\'' => ReadString(ch, position),
            '-' when _index < _source.Length && char.IsAsciiDigit(_source[_index]) => ReadNumber(position),
            >= '0' and <= '9' => ReadNumber(position),
            _ when IsIdentifierStart(ch) => ReadIdentifier(position),
            _ => throw CreateError(position, $"unexpected character '{ch}'"),
        };
    }

    private NativePredicateToken ReadRequiredPair(
        char expected,
        NativePredicateTokenKind kind,
        int position)
    {
        if (_index >= _source.Length || _source[_index] != expected)
        {
            Throw(position, $"expected '{expected}{expected}'");
        }

        _index++;
        return new NativePredicateToken(kind, _source.Substring(position, 2), position);
    }

    private NativePredicateToken ReadOptionalPair(
        char expected,
        NativePredicateTokenKind pairKind,
        NativePredicateTokenKind singleKind,
        int position)
    {
        if (_index < _source.Length && _source[_index] == expected)
        {
            _index++;
            return new NativePredicateToken(pairKind, _source.Substring(position, 2), position);
        }

        return new NativePredicateToken(singleKind, _source.Substring(position, 1), position);
    }

    private NativePredicateToken ReadString(char quote, int position)
    {
        var builder = new StringBuilder();
        while (_index < _source.Length)
        {
            char ch = _source[_index++];
            if (ch == quote)
            {
                string value = builder.ToString();
                if (Encoding.UTF8.GetByteCount(value) > NativePredicateCompiler.MaxLiteralUtf8Bytes)
                {
                    Throw(position, $"string literal exceeds {NativePredicateCompiler.MaxLiteralUtf8Bytes} UTF-8 bytes");
                }

                return new NativePredicateToken(NativePredicateTokenKind.String, value, position);
            }

            if (ch != '\\')
            {
                builder.Append(ch);
                continue;
            }

            if (_index >= _source.Length)
            {
                Throw(position, "unterminated string escape");
            }

            char escaped = _source[_index++];
            builder.Append(escaped switch
            {
                '\\' => '\\',
                '"' => '"',
                '\'' => '\'',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'u' => ReadUnicodeEscape(position),
                _ => throw CreateError(_index - 2, $"unsupported string escape '\\{escaped}'"),
            });
        }

        Throw(position, "unterminated string literal");
        return default;
    }

    private char ReadUnicodeEscape(int stringPosition)
    {
        if (_index + 4 > _source.Length)
        {
            Throw(stringPosition, "incomplete Unicode escape");
        }

        ReadOnlySpan<char> digits = _source.AsSpan(_index, 4);
        if (!ushort.TryParse(digits, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out ushort value))
        {
            Throw(_index, "invalid Unicode escape");
        }

        _index += 4;
        return (char)value;
    }

    private NativePredicateToken ReadNumber(int position)
    {
        while (_index < _source.Length)
        {
            char ch = _source[_index];
            if (char.IsAsciiDigit(ch) || ch is '.' or 'e' or 'E' or '+' or '-')
            {
                _index++;
                continue;
            }

            break;
        }

        return new NativePredicateToken(
            NativePredicateTokenKind.Number,
            _source[position.._index],
            position);
    }

    private NativePredicateToken ReadIdentifier(int position)
    {
        while (_index < _source.Length && IsIdentifierPart(_source[_index]))
        {
            _index++;
        }

        string value = _source[position.._index];
        NativePredicateTokenKind kind = value switch
        {
            "true" => NativePredicateTokenKind.True,
            "false" => NativePredicateTokenKind.False,
            "contains" => NativePredicateTokenKind.Contains,
            "starts_with" => NativePredicateTokenKind.StartsWith,
            "ends_with" => NativePredicateTokenKind.EndsWith,
            "matches" => NativePredicateTokenKind.Matches,
            _ => NativePredicateTokenKind.Identifier,
        };
        return new NativePredicateToken(kind, value, position);
    }

    private void SkipWhitespace()
    {
        while (_index < _source.Length && char.IsWhiteSpace(_source[_index]))
        {
            _index++;
        }
    }

    private void Require(NativePredicateTokenKind kind, string message)
    {
        if (_current.Kind != kind)
        {
            Throw(_current.Position, message);
        }
    }

    private void ValidateBinaryOperation(
        NativePredicateTokenKind operation,
        NativePredicateValueKind left,
        NativePredicateValueKind right,
        int position)
    {
        bool valid = operation switch
        {
            NativePredicateTokenKind.Equal or NativePredicateTokenKind.NotEqual =>
                left == right && left != NativePredicateValueKind.StringList,
            NativePredicateTokenKind.LessThan
                or NativePredicateTokenKind.LessThanOrEqual
                or NativePredicateTokenKind.GreaterThan
                or NativePredicateTokenKind.GreaterThanOrEqual =>
                left == NativePredicateValueKind.Number && right == NativePredicateValueKind.Number,
            NativePredicateTokenKind.Contains =>
                (left == NativePredicateValueKind.String || left == NativePredicateValueKind.StringList)
                && right == NativePredicateValueKind.String,
            NativePredicateTokenKind.StartsWith or NativePredicateTokenKind.EndsWith =>
                left == NativePredicateValueKind.String && right == NativePredicateValueKind.String,
            _ => false,
        };

        if (!valid)
        {
            Throw(
                position,
                $"operator '{GetOperatorText(operation)}' does not accept {left} and {right} operands");
        }
    }

    private void RequireBoolean(NativePredicateValueKind kind, int position, string operand)
    {
        if (kind != NativePredicateValueKind.Boolean)
        {
            Throw(position, $"{operand} must produce a boolean value");
        }
    }

    private void Throw(int position, string message)
    {
        throw CreateError(position, message);
    }

    private InvalidDataException CreateError(
        int position,
        string message,
        Exception? innerException = null)
    {
        string fullMessage =
            $"{_context}: invalid native predicate at column {position + 1}: {message}";
        return innerException is null
            ? new InvalidDataException(fullMessage)
            : new InvalidDataException(fullMessage, innerException);
    }

    private static bool IsComparison(NativePredicateTokenKind kind)
    {
        return kind is NativePredicateTokenKind.Equal
            or NativePredicateTokenKind.NotEqual
            or NativePredicateTokenKind.LessThan
            or NativePredicateTokenKind.LessThanOrEqual
            or NativePredicateTokenKind.GreaterThan
            or NativePredicateTokenKind.GreaterThanOrEqual
            or NativePredicateTokenKind.Contains
            or NativePredicateTokenKind.StartsWith
            or NativePredicateTokenKind.EndsWith
            or NativePredicateTokenKind.Matches;
    }

    private static bool IsFindingField(NativePredicateField field)
    {
        return field is not NativePredicateField.SourcePath
            and not NativePredicateField.SourceSymlink;
    }

    private static NativePredicateValueKind GetFieldKind(NativePredicateField field)
    {
        return field switch
        {
            NativePredicateField.FindingStartLine
                or NativePredicateField.FindingEndLine
                or NativePredicateField.FindingStartColumn
                or NativePredicateField.FindingEndColumn
                or NativePredicateField.FindingEntropy
                or NativePredicateField.FindingRandomnessScore
                or NativePredicateField.FindingDecodeDepth => NativePredicateValueKind.Number,
            NativePredicateField.FindingIsDecoded => NativePredicateValueKind.Boolean,
            NativePredicateField.FindingTags
                or NativePredicateField.FindingDecodePath => NativePredicateValueKind.StringList,
            _ => NativePredicateValueKind.String,
        };
    }

    private static NativePredicateOpCode ToOpCode(NativePredicateTokenKind kind)
    {
        return kind switch
        {
            NativePredicateTokenKind.Equal => NativePredicateOpCode.Equal,
            NativePredicateTokenKind.NotEqual => NativePredicateOpCode.NotEqual,
            NativePredicateTokenKind.LessThan => NativePredicateOpCode.LessThan,
            NativePredicateTokenKind.LessThanOrEqual => NativePredicateOpCode.LessThanOrEqual,
            NativePredicateTokenKind.GreaterThan => NativePredicateOpCode.GreaterThan,
            NativePredicateTokenKind.GreaterThanOrEqual => NativePredicateOpCode.GreaterThanOrEqual,
            NativePredicateTokenKind.Contains => NativePredicateOpCode.Contains,
            NativePredicateTokenKind.StartsWith => NativePredicateOpCode.StartsWith,
            NativePredicateTokenKind.EndsWith => NativePredicateOpCode.EndsWith,
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown native predicate operator."),
        };
    }

    private static string GetOperatorText(NativePredicateTokenKind kind)
    {
        return kind switch
        {
            NativePredicateTokenKind.Equal => "==",
            NativePredicateTokenKind.NotEqual => "!=",
            NativePredicateTokenKind.LessThan => "<",
            NativePredicateTokenKind.LessThanOrEqual => "<=",
            NativePredicateTokenKind.GreaterThan => ">",
            NativePredicateTokenKind.GreaterThanOrEqual => ">=",
            NativePredicateTokenKind.Contains => "contains",
            NativePredicateTokenKind.StartsWith => "starts_with",
            NativePredicateTokenKind.EndsWith => "ends_with",
            NativePredicateTokenKind.Matches => "matches",
            _ => kind.ToString(),
        };
    }

    private static bool IsIdentifierStart(char ch)
    {
        return char.IsAsciiLetter(ch) || ch == '_';
    }

    private static bool IsIdentifierPart(char ch)
    {
        return char.IsAsciiLetterOrDigit(ch) || ch is '_' or '.';
    }
}
