﻿namespace JamieMagee.Octokit.Webhooks.Models
{
    using System.Text.Json.Serialization;

    public sealed record PullRequestEditedEventChanges
    {
        [JsonPropertyName("body")]
        public PullRequestEditedEventChangesBody? Body { get; init; }

        [JsonPropertyName("title")]
        public PullRequestEditedEventChangesTitle? Title { get; init; }
    }
}
