namespace Picket.Engine;

[Flags]
internal enum DecodedEncoding
{
    None = 0,
    Percent = 1,
    Hex = 2,
    Base64 = 4,
}
