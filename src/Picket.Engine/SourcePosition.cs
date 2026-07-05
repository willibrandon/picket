namespace Picket.Engine;

/// <summary>
/// Represents a one-based source line and column.
/// </summary>
/// <param name="line">The one-based line.</param>
/// <param name="column">The one-based column.</param>
public readonly struct SourcePosition(int line, int column) : IEquatable<SourcePosition>
{
    /// <summary>
    /// Gets the one-based line.
    /// </summary>
    public int Line { get; } = line;

    /// <summary>
    /// Gets the one-based column.
    /// </summary>
    public int Column { get; } = column;

    /// <summary>
    /// Maps a zero-based byte offset to a one-based line and column.
    /// </summary>
    /// <param name="input">The input bytes.</param>
    /// <param name="offset">The zero-based byte offset.</param>
    /// <returns>The source position.</returns>
    public static SourcePosition FromOffset(ReadOnlySpan<byte> input, int offset)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(offset, input.Length);

        int line = 1;
        int column = 1;
        for (int i = 0; i < offset; i++)
        {
            if (input[i] == (byte)'\n')
            {
                line++;
                column = 1;
                continue;
            }

            column++;
        }

        return new SourcePosition(line, column);
    }

    /// <summary>
    /// Returns a value indicating whether two positions are equal.
    /// </summary>
    /// <param name="left">The left position.</param>
    /// <param name="right">The right position.</param>
    /// <returns><see langword="true" /> when both positions are equal.</returns>
    public static bool operator ==(SourcePosition left, SourcePosition right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Returns a value indicating whether two positions differ.
    /// </summary>
    /// <param name="left">The left position.</param>
    /// <param name="right">The right position.</param>
    /// <returns><see langword="true" /> when the positions differ.</returns>
    public static bool operator !=(SourcePosition left, SourcePosition right)
    {
        return !left.Equals(right);
    }

    /// <summary>
    /// Returns a value indicating whether this position equals another position.
    /// </summary>
    /// <param name="other">The other position.</param>
    /// <returns><see langword="true" /> when the positions are equal.</returns>
    public bool Equals(SourcePosition other)
    {
        return Line == other.Line && Column == other.Column;
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is SourcePosition other && Equals(other);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        return HashCode.Combine(Line, Column);
    }
}
