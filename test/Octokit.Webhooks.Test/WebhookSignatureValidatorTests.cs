namespace Octokit.Webhooks.Test;

using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using AwesomeAssertions;
using Xunit;

public class WebhookSignatureValidatorTests
{
    [Fact]
    public void NoSignatureAndNoSecret_ReturnsValid()
    {
        var result = WebhookSignatureValidator.Verify(null, null, "{}");

        result.Should().Be(WebhookSignatureValidationResult.Valid);
    }

    [Fact]
    public void EmptySignatureAndEmptySecret_ReturnsValid()
    {
        var result = WebhookSignatureValidator.Verify(string.Empty, string.Empty, "{}");

        result.Should().Be(WebhookSignatureValidationResult.Valid);
    }

    [Fact]
    public void NoSignatureButSecretExpected_ReturnsMissingSignature()
    {
        var result = WebhookSignatureValidator.Verify(null, "my-secret", "{}");

        result.Should().Be(WebhookSignatureValidationResult.MissingSignature);
    }

    [Fact]
    public void EmptySignatureButSecretExpected_ReturnsMissingSignature()
    {
        var result = WebhookSignatureValidator.Verify(string.Empty, "my-secret", "{}");

        result.Should().Be(WebhookSignatureValidationResult.MissingSignature);
    }

    [Fact]
    public void SignedButNoSecretConfigured_ReturnsMissingSecret()
    {
        var signature = ComputeSignature("my-secret", "{}");

        var result = WebhookSignatureValidator.Verify(signature, null, "{}");

        result.Should().Be(WebhookSignatureValidationResult.MissingSecret);
    }

    [Fact]
    public void SignedButEmptySecretConfigured_ReturnsMissingSecret()
    {
        var signature = ComputeSignature("my-secret", "{}");

        var result = WebhookSignatureValidator.Verify(signature, string.Empty, "{}");

        result.Should().Be(WebhookSignatureValidationResult.MissingSecret);
    }

    [Fact]
    public void ValidSignature_ReturnsValid()
    {
        var signature = ComputeSignature("my-secret", "{}");

        var result = WebhookSignatureValidator.Verify(signature, "my-secret", "{}");

        result.Should().Be(WebhookSignatureValidationResult.Valid);
    }

    [Fact]
    public void InvalidSignature_ReturnsSignatureMismatch()
    {
        var signature = ComputeSignature("wrong-secret", "{}");

        var result = WebhookSignatureValidator.Verify(signature, "my-secret", "{}");

        result.Should().Be(WebhookSignatureValidationResult.SignatureMismatch);
    }

    [Fact]
    public void MalformedSignature_ReturnsSignatureMismatch()
    {
        var result = WebhookSignatureValidator.Verify("not-a-valid-signature", "my-secret", "{}");

        result.Should().Be(WebhookSignatureValidationResult.SignatureMismatch);
    }

    [Fact]
    public void NullBody_ThrowsArgumentNullException()
    {
        var act = () => WebhookSignatureValidator.Verify(null, null, (string)null!);

        act.Should().Throw<ArgumentNullException>().WithMessage("*body*");
    }

    [Fact]
    public void GetPreHashValidationResult_NoSignatureAndNoSecret_ReturnsValid()
    {
        var result = WebhookSignatureValidator.GetPreHashValidationResult(null, null);

        result.Should().Be(WebhookSignatureValidationResult.Valid);
    }

    [Fact]
    public void GetPreHashValidationResult_EmptySignatureAndEmptySecret_ReturnsValid()
    {
        var result = WebhookSignatureValidator.GetPreHashValidationResult(string.Empty, string.Empty);

        result.Should().Be(WebhookSignatureValidationResult.Valid);
    }

    [Fact]
    public void GetPreHashValidationResult_NoSignatureButSecretExpected_ReturnsMissingSignature()
    {
        var result = WebhookSignatureValidator.GetPreHashValidationResult(null, "my-secret");

        result.Should().Be(WebhookSignatureValidationResult.MissingSignature);
    }

    [Fact]
    public void GetPreHashValidationResult_SignedButNoSecretConfigured_ReturnsMissingSecret()
    {
        var signature = ComputeSignature("my-secret", "{}");

        var result = WebhookSignatureValidator.GetPreHashValidationResult(signature, null);

        result.Should().Be(WebhookSignatureValidationResult.MissingSecret);
    }

    [Fact]
    public void GetPreHashValidationResult_BothPresentAndValid_ReturnsNull()
    {
        var signature = ComputeSignature("my-secret", "{}");

        var result = WebhookSignatureValidator.GetPreHashValidationResult(signature, "my-secret");

        result.Should().BeNull();
    }

    [Fact]
    public void VerifyFromHash_ValidHash_ReturnsValid()
    {
        var body = "{}";
        var secret = "my-secret";
        var signature = ComputeSignature(secret, body);
        var computedHash = HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(secret),
            Encoding.UTF8.GetBytes(body));

        var result = WebhookSignatureValidator.VerifyFromHash(signature, computedHash);

        result.Should().Be(WebhookSignatureValidationResult.Valid);
    }

    [Fact]
    public void VerifyFromHash_WrongHash_ReturnsSignatureMismatch()
    {
        var signature = ComputeSignature("my-secret", "{}");
        var wrongHash = new byte[32];

        var result = WebhookSignatureValidator.VerifyFromHash(signature, wrongHash);

        result.Should().Be(WebhookSignatureValidationResult.SignatureMismatch);
    }

    [Fact]
    public void VerifyFromHash_MalformedSignature_ReturnsSignatureMismatch()
    {
        var result = WebhookSignatureValidator.VerifyFromHash("not-a-valid-signature", new byte[32]);

        result.Should().Be(WebhookSignatureValidationResult.SignatureMismatch);
    }

    [Fact]
    public void VerifyFromHash_NullOrEmptyHeader_ThrowsArgumentException()
    {
        var act = () => WebhookSignatureValidator.VerifyFromHash(string.Empty, new byte[32]);

        act.Should().Throw<ArgumentException>();
    }

    private static string ComputeSignature(string secret, string body)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        var hash = HMACSHA256.HashData(keyBytes, bodyBytes);
        var hashHex = Convert.ToHexString(hash);
        return $"sha256={hashHex.ToLower(CultureInfo.InvariantCulture)}";
    }
}
