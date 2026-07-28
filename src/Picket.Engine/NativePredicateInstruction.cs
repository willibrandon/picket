namespace Picket.Engine;

internal readonly struct NativePredicateInstruction(
    NativePredicateOpCode opCode,
    int operand = 0)
{
    internal NativePredicateOpCode OpCode { get; } = opCode;

    internal int Operand { get; } = operand;
}
