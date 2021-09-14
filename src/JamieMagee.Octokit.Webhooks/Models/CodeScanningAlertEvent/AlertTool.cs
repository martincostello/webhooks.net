﻿namespace JamieMagee.Octokit.Webhooks.Models.CodeScanningAlertEvent
{
    using System.Text.Json.Serialization;

    public sealed record AlertTool
    {
        [JsonPropertyName("name")]
        public string Name { get; init; } = null!;

        [JsonPropertyName("version")]
        public string? Version { get; init; }

        [JsonPropertyName("guid")]
        public string? Guid { get; init; }
    }
}