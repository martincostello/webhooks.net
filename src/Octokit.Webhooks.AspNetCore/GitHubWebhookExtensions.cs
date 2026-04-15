namespace Octokit.Webhooks.AspNetCore;

using System;
using System.Buffers;
using System.IO;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// A class containing extension methods for <see cref="IEndpointRouteBuilder"/>
/// for adding an HTTP endpoint for processing GitHub webhook payloads.
/// </summary>
public static partial class GitHubWebhookExtensions
{
    public static IEndpointConventionBuilder MapGitHubWebhooks(
        this IEndpointRouteBuilder endpoints,
        string path = "/api/github/webhooks",
        string? secret = null)
    {
        var options = endpoints.ServiceProvider.GetService<IOptionsMonitor<GitHubWebhookOptions>>();
        return endpoints.MapPost(
            path,
            async context =>
            {
                var logger = context.RequestServices.GetRequiredService<ILogger<WebhookEventProcessor>>();

                // Verify content type
                if (!VerifyContentType(context, MediaTypeNames.Application.Json))
                {
                    Log.IncorrectContentType(logger);
                    return;
                }

                // Verify event type
                if (!VerifyEventType(context))
                {
                    Log.MissingEventType(logger);
                    return;
                }

                IncrementalHash? hmac = null;
                try
                {
                    if (secret is null && options is not null)
                    {
                        secret = options.CurrentValue.Secret;
                    }

                    _ = context.Request.Headers.TryGetValue("X-Hub-Signature-256", out var signatureSha256);
                    var signatureHeader = signatureSha256.ToString();

                    // Pre-validate signature/secret presence before reading the body
                    var preResult = WebhookSignatureValidator.GetPreHashValidationResult(signatureHeader, secret);
                    if (preResult.HasValue && preResult.Value != WebhookSignatureValidationResult.Valid)
                    {
                        Log.SignatureValidationFailed(logger);
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsync(GetSignatureErrorMessage(preResult.Value))
                            .ConfigureAwait(false);
                        return;
                    }

                    // Set up incremental HMAC when both signature header and secret are present (preResult is null)
                    var bodyStream = context.Request.Body;
                    if (!preResult.HasValue)
                    {
                        var keyByteCount = Encoding.UTF8.GetByteCount(secret!);
                        var keyBuffer = ArrayPool<byte>.Shared.Rent(keyByteCount);
                        try
                        {
                            Encoding.UTF8.GetBytes(secret!, keyBuffer.AsSpan(0, keyByteCount));
                            hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, keyBuffer.AsSpan(0, keyByteCount));
                        }
                        finally
                        {
                            keyBuffer.AsSpan(0, keyByteCount).Clear();
                            ArrayPool<byte>.Shared.Return(keyBuffer);
                        }

                        bodyStream = new HashingStream(context.Request.Body, hmac);
                    }

                    // Deserialize the webhook event from the stream.
                    // If using a HashingStream, the HMAC is updated incrementally as bytes are read.
                    var service = context.RequestServices.GetRequiredService<WebhookEventProcessor>();
                    var webhookHeaders = WebhookHeaders.Parse(context.Request.Headers);
                    var webhookEvent = await service.DeserializeWebhookEventAsync(webhookHeaders, bodyStream, context.RequestAborted)
                        .ConfigureAwait(false);

                    // Verify signature after the body has been fully consumed
                    if (hmac is not null)
                    {
                        var computedHash = new byte[32];
                        hmac.TryGetHashAndReset(computedHash, out _);

                        var result = WebhookSignatureValidator.VerifyFromHash(signatureHeader, computedHash);
                        if (result != WebhookSignatureValidationResult.Valid)
                        {
                            Log.SignatureValidationFailed(logger);
                            context.Response.StatusCode = 400;
                            await context.Response.WriteAsync(GetSignatureErrorMessage(result))
                                .ConfigureAwait(false);
                            return;
                        }
                    }

                    // Process the verified webhook event
                    await service.ProcessWebhookAsync(webhookHeaders, webhookEvent, context.RequestAborted)
                        .ConfigureAwait(false);
                    context.Response.StatusCode = 200;
                }
                catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
                {
                    Log.RequestCancelled(logger);
                }
                catch (Exception ex)
                {
                    Log.ProcessingFailed(logger, ex);
                    context.Response.StatusCode = 500;
                }
                finally
                {
                    hmac?.Dispose();
                }
            });
    }

    private static bool VerifyContentType(HttpContext context, string expectedContentType)
    {
        if (context.Request.ContentType is null)
        {
            return false;
        }

        var contentType = new ContentType(context.Request.ContentType);
        if (contentType.MediaType != expectedContentType)
        {
            context.Response.StatusCode = 400;
            return false;
        }

        return true;
    }

    private static bool VerifyEventType(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue("X-GitHub-Event", out var eventType)
            || eventType.Count != 1
            || string.IsNullOrWhiteSpace(eventType.ToString()))
        {
            context.Response.StatusCode = 400;
            return false;
        }

        return true;
    }

    private static string GetSignatureErrorMessage(WebhookSignatureValidationResult result) => result switch
    {
        WebhookSignatureValidationResult.MissingSignature =>
            "Expected an X-Hub-Signature-256 header but none was provided. Configure a webhook secret on the sender, or remove the secret from the receiver.",
        WebhookSignatureValidationResult.MissingSecret =>
            "Request includes an X-Hub-Signature-256 header but no secret is configured on the receiver.",
        _ =>
            "X-Hub-Signature-256 does not match the expected signature. Verify that the webhook secret matches on both sender and receiver.",
    };

    /// <summary>
    /// Log messages for the class.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static partial class Log
    {
        [LoggerMessage(
            EventId = 1,
            Level = LogLevel.Error,
            Message = "GitHub event does not have the correct content type.")]
        public static partial void IncorrectContentType(ILogger logger);

        [LoggerMessage(
            EventId = 2,
            Level = LogLevel.Error,
            Message = "GitHub event failed signature validation.")]
        public static partial void SignatureValidationFailed(ILogger logger);

        [LoggerMessage(
            EventId = 3,
            Level = LogLevel.Error,
            Message = "Exception processing GitHub event.")]
        public static partial void ProcessingFailed(ILogger logger, Exception exception);

        [LoggerMessage(
            EventId = 4,
            Level = LogLevel.Warning,
            Message = "GitHub event request was cancelled.")]
        public static partial void RequestCancelled(ILogger logger);

        [LoggerMessage(
            EventId = 5,
            Level = LogLevel.Error,
            Message = "GitHub event has a missing or invalid event type header.")]
        public static partial void MissingEventType(ILogger logger);
    }
}
