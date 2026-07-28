namespace Picket.Engine;

internal enum NativePredicateTokenKind
{
    End,
    Identifier,
    String,
    Number,
    True,
    False,
    LeftParenthesis,
    RightParenthesis,
    And,
    Or,
    Not,
    Equal,
    NotEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    Contains,
    StartsWith,
    EndsWith,
    Matches,
}
