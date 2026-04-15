namespace Octokit.Webhooks;

using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Provides methods to verify GitHub webhook payload signatures.
/// </summary>
[PublicAPI]
public static class WebhookSignatureValidator
{
    private const string Prefix = "sha256=";

    /// <summary>
    /// Verifies the signature of a GitHub webhook payload.
    /// </summary>
    /// <param name="signatureHeader">The value of the <c>X-Hub-Signature-256</c> header, or <see langword="null"/> or an empty string if not present.</param>
    /// <param name="secret">The configured webhook secret, or <see langword="null"/> or an empty string if not configured.</param>
    /// <param name="body">The raw request body.</param>
    /// <returns>A <see cref="WebhookSignatureValidationResult"/> indicating the outcome of the validation.</returns>
    public static WebhookSignatureValidationResult Verify(string? signatureHeader, string? secret, string body)
    {
        ArgumentNullException.ThrowIfNull(body);

        var bodyByteCount = Encoding.UTF8.GetByteCount(body);
        var bodyBytesArray = ArrayPool<byte>.Shared.Rent(bodyByteCount);
        try
        {
            var bodyBytes = bodyBytesArray.AsSpan(0, bodyByteCount);
            Encoding.UTF8.GetBytes(body, bodyBytes);
            return Verify(signatureHeader, secret, bodyBytes);
        }
        finally
        {
            bodyBytesArray.AsSpan(0, bodyByteCount).Clear();
            ArrayPool<byte>.Shared.Return(bodyBytesArray);
        }
    }

    /// <summary>
    /// Verifies the signature of a GitHub webhook payload from raw UTF-8 bytes.
    /// </summary>
    /// <param name="signatureHeader">The value of the <c>X-Hub-Signature-256</c> header, or <see langword="null"/> or an empty string if not present.</param>
    /// <param name="secret">The configured webhook secret, or <see langword="null"/> or an empty string if not configured.</param>
    /// <param name="bodyUtf8">The raw request body as UTF-8 bytes.</param>
    /// <returns>A <see cref="WebhookSignatureValidationResult"/> indicating the outcome of the validation.</returns>
    public static WebhookSignatureValidationResult Verify(string? signatureHeader, string? secret, ReadOnlySpan<byte> bodyUtf8)
    {
        var preResult = GetPreHashValidationResult(signatureHeader, secret);
        if (preResult.HasValue)
        {
            return preResult.Value;
        }

        var keyByteCount = Encoding.UTF8.GetByteCount(secret!);
        var keyBuffer = keyByteCount <= 256
            ? stackalloc byte[keyByteCount]
            : new byte[keyByteCount];

        try
        {
            if (Encoding.UTF8.GetBytes(secret!, keyBuffer) != keyByteCount)
            {
                return WebhookSignatureValidationResult.SignatureMismatch;
            }

            Span<byte> computedHash = stackalloc byte[32];
            if (!HMACSHA256.TryHashData(keyBuffer, bodyUtf8, computedHash, out var bytesWritten)
                || bytesWritten != computedHash.Length)
            {
                return WebhookSignatureValidationResult.SignatureMismatch;
            }

            return VerifyFromHash(signatureHeader!, computedHash);
        }
        finally
        {
            keyBuffer.Clear();
        }
    }

    /// <summary>
    /// Checks the signature header and secret for early-exit conditions, before reading or hashing the request body.
    /// </summary>
    /// <param name="signatureHeader">The value of the <c>X-Hub-Signature-256</c> header, or <see langword="null"/> or an empty string if not present.</param>
    /// <param name="secret">The configured webhook secret, or <see langword="null"/> or an empty string if not configured.</param>
    /// <returns>
    /// <see cref="WebhookSignatureValidationResult.Valid"/> if neither a signature nor a secret is present and no verification is needed;
    /// <see cref="WebhookSignatureValidationResult.MissingSignature"/> if a secret is configured but no signature header was provided;
    /// <see cref="WebhookSignatureValidationResult.MissingSecret"/> if a signature header is present but no secret is configured;
    /// or <see langword="null"/> if both are present and the body must be hashed to complete verification.
    /// </returns>
    [PublicAPI]
    public static WebhookSignatureValidationResult? GetPreHashValidationResult(string? signatureHeader, string? secret)
    {
        var isSigned = !string.IsNullOrEmpty(signatureHeader);
        var isSignatureExpected = !string.IsNullOrEmpty(secret);

        if (!isSigned && !isSignatureExpected)
        {
            return WebhookSignatureValidationResult.Valid;
        }

        if (!isSigned && isSignatureExpected)
        {
            return WebhookSignatureValidationResult.MissingSignature;
        }

        if (isSigned && !isSignatureExpected)
        {
            return WebhookSignatureValidationResult.MissingSecret;
        }

        return null;
    }

    /// <summary>
    /// Compares a pre-computed HMAC-SHA256 hash against the value in the signature header.
    /// Call this after reading and incrementally hashing the request body.
    /// </summary>
    /// <param name="signatureHeader">The value of the <c>X-Hub-Signature-256</c> header. Must be non-null and non-empty.</param>
    /// <param name="computedHash">The HMAC-SHA256 hash computed over the request body.</param>
    /// <returns>A <see cref="WebhookSignatureValidationResult"/> indicating the outcome of the comparison.</returns>
    [PublicAPI]
    public static WebhookSignatureValidationResult VerifyFromHash(string signatureHeader, ReadOnlySpan<byte> computedHash)
    {
        ArgumentException.ThrowIfNullOrEmpty(signatureHeader);

        if (!signatureHeader.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        {
            return WebhookSignatureValidationResult.SignatureMismatch;
        }

        var signatureHex = signatureHeader[Prefix.Length..];

        if (signatureHex.Length != 64)
        {
            return WebhookSignatureValidationResult.SignatureMismatch;
        }

        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromHexString(signatureHex);
        }
        catch (FormatException)
        {
            return WebhookSignatureValidationResult.SignatureMismatch;
        }

        return CryptographicOperations.FixedTimeEquals(computedHash, signatureBytes)
            ? WebhookSignatureValidationResult.Valid
            : WebhookSignatureValidationResult.SignatureMismatch;
    }
}
