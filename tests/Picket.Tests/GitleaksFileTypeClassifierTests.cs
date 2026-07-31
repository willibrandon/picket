using Picket.Compat;

namespace Picket.Tests;

/// <summary>
/// Tests the Gitleaks-compatible file-type classification boundary.
/// </summary>
[TestClass]
public sealed class GitleaksFileTypeClassifierTests
{
    /// <summary>
    /// Verifies that application MIME signatures are skipped by compatibility scans.
    /// </summary>
    [TestMethod]
    public void IsApplicationRecognizesApplicationMimeSignatures()
    {
        Assert.IsTrue(GitleaksFileTypeClassifier.IsApplication(Convert.FromHexString("0061736D01000000")));
        Assert.IsTrue(GitleaksFileTypeClassifier.IsApplication("MZ"u8));
        Assert.IsTrue(GitleaksFileTypeClassifier.IsApplication("%PDF"u8));
        Assert.IsTrue(GitleaksFileTypeClassifier.IsApplication("{\\rtf"u8));
        Assert.IsTrue(GitleaksFileTypeClassifier.IsApplication(Convert.FromHexString("504B0304")));
        Assert.IsTrue(GitleaksFileTypeClassifier.IsApplication("SQLi"u8));
        Assert.IsTrue(GitleaksFileTypeClassifier.IsApplication(Convert.FromHexString("28B52FFD")));
        Assert.IsTrue(GitleaksFileTypeClassifier.IsApplication(
            Convert.FromHexString("502A4D180000000028B52FFD")));
        Assert.IsTrue(GitleaksFileTypeClassifier.IsApplication(
            CreatePaddedInput(Convert.FromHexString("7F454C46"), 53)));
        Assert.IsTrue(GitleaksFileTypeClassifier.IsApplication(
            Convert.FromHexString("0001000000")));
        Assert.IsTrue(GitleaksFileTypeClassifier.IsApplication(
            Convert.FromHexString("D0CF11E0")));
    }

    /// <summary>
    /// Verifies that NUL-containing and non-application MIME signatures remain scannable.
    /// </summary>
    [TestMethod]
    public void IsApplicationKeepsNonApplicationMimeSignatures()
    {
        Assert.IsFalse(GitleaksFileTypeClassifier.IsApplication(Convert.FromHexString("00010203")));
        Assert.IsFalse(GitleaksFileTypeClassifier.IsApplication(Convert.FromHexString("30820100")));
        Assert.IsFalse(GitleaksFileTypeClassifier.IsApplication(Convert.FromHexString("89504E47")));
        Assert.IsFalse(GitleaksFileTypeClassifier.IsApplication(Convert.FromHexString("00000000667479706D703432")));
        Assert.IsFalse(GitleaksFileTypeClassifier.IsApplication("ID3"u8));
    }

    /// <summary>
    /// Verifies that image matching takes precedence over an overlapping application signature.
    /// </summary>
    [TestMethod]
    public void IsApplicationHonorsGitleaksMatcherPrecedence()
    {
        byte[] input = CreatePaddedInput(Convert.FromHexString("89504E47"), 36);
        input[8] = 0x02;
        input[9] = 0x00;
        input[10] = 0x01;
        input[34] = 0x4C;
        input[35] = 0x50;

        Assert.IsFalse(GitleaksFileTypeClassifier.IsApplication(input));
    }

    private static byte[] CreatePaddedInput(
        ReadOnlySpan<byte> prefix,
        int length)
    {
        var input = new byte[length];
        prefix.CopyTo(input);
        return input;
    }
}
