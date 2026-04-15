namespace Octokit.Webhooks.AzureFunctions;

using System;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

/// <summary>
/// A class containing an Azure Function that processes GitHub webhooks.
/// </summary>
public sealed partial class GitHubWebhooksHttpFunction(IOptions<GitHubWebhooksOptions> options)
{
    [Function(nameof(MapGitHubWebhooksAsync))]
    public async Task<HttpResponseData?> MapGitHubWebhooksAsync(
        [HttpTrigger(AuthorizationLevel.Anonymous, "POST", Route = "github/webhooks")] HttpRequestData req,
        FunctionContext ctx)
    {
        var logger = ctx.GetLogger(nameof(GitHubWebhooksHttpFunction));

        // Verify content type
        if (!VerifyContentType(req, MediaTypeNames.Application.Json))
        {
            Log.IncorrectContentType(logger);
            return req.CreateResponse(HttpStatusCode.BadRequest);
        }

        // Verify event type
        if (!VerifyEventType(req))
        {
            Log.MissingEventType(logger);
            return req.CreateResponse(HttpStatusCode.BadRequest);
        }

        IncrementalHash? hmac = null;
        try
        {
            _ = req.Headers.TryGetValues("X-Hub-Signature-256", out var signatureValues);
            var signatureHeader = signatureValues?.FirstOrDefault() ?? string.Empty;
            var secret = options.Value.Secret;

            // Pre-validate signature/secret presence before reading the body
            var preResult = WebhookSignatureValidator.GetPreHashValidationResult(signatureHeader, secret);
            if (preResult.HasValue && preResult.Value != WebhookSignatureValidationResult.Valid)
            {
                Log.SignatureValidationFailed(logger);
                var errorResponse = req.CreateResponse(HttpStatusCode.BadRequest);
                await errorResponse.WriteStringAsync(GetSignatureErrorMessage(preResult.Value)).ConfigureAwait(false);
                return errorResponse;
            }

            // Set up incremental HMAC when both signature header and secret are present (preResult is null)
            var bodyStream = req.Body;
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

                bodyStream = new HashingStream(req.Body, hmac);
            }

            // Deserialize the webhook event from the stream.
            // If using a HashingStream, the HMAC is updated incrementally as bytes are read.
            var service = ctx.InstanceServices.GetRequiredService<WebhookEventProcessor>();
            var headers = req.Headers.ToDictionary(
                kv => kv.Key,
                kv => new StringValues([.. kv.Value]),
                StringComparer.OrdinalIgnoreCase);
            var webhookHeaders = WebhookHeaders.Parse(headers);
            var webhookEvent = await service.DeserializeWebhookEventAsync(webhookHeaders, bodyStream, ctx.CancellationToken)
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
                    var errorResponse = req.CreateResponse(HttpStatusCode.BadRequest);
                    await errorResponse.WriteStringAsync(GetSignatureErrorMessage(result)).ConfigureAwait(false);
                    return errorResponse;
                }
            }

            // Process the verified webhook event
            await service.ProcessWebhookAsync(webhookHeaders, webhookEvent, ctx.CancellationToken)
                .ConfigureAwait(false);
            return req.CreateResponse(HttpStatusCode.OK);
        }
        catch (OperationCanceledException) when (ctx.CancellationToken.IsCancellationRequested)
        {
            Log.RequestCancelled(logger);
            return null;
        }
        catch (Exception ex)
        {
            Log.ProcessingFailed(logger, ex);
            return req.CreateResponse(HttpStatusCode.InternalServerError);
        }
        finally
        {
            hmac?.Dispose();
        }
    }

    private static bool VerifyContentType(HttpRequestData req, string expectedContentType)
    {
        var contentHeader = req.Headers.GetValues("Content-Type").FirstOrDefault();
        if (contentHeader is null)
        {
            return false;
        }

        var contentType = new ContentType(contentHeader);
        return contentType.MediaType == expectedContentType;
    }

    private static bool VerifyEventType(HttpRequestData req)
    {
        if (!req.Headers.TryGetValues("X-GitHub-Event", out var eventValues))
        {
            return false;
        }

        var values = eventValues.ToList();
        return values.Count == 1 && !string.IsNullOrWhiteSpace(values[0]);
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
