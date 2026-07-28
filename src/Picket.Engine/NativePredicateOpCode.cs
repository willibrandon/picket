namespace Picket.Engine;

internal enum NativePredicateOpCode
{
    PushField,
    PushConstant,
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
    Not,
    JumpIfFalse,
    JumpIfTrue,
}
