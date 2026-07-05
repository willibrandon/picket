namespace Picket.Engine;

[Flags]
internal enum DecodedEncoding
{
    None = 0,
    Percent = 1,
    Unicode = 2,
    Hex = 4,
    Base64 = 8,
}
