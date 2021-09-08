﻿namespace JamieMagee.Octokit.Webhooks.Models
{
    using System.Runtime.Serialization;
    using System.Text.Json.Serialization;

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum AuthorAssociation
    {
        [EnumMember(Value = "COLLABORATOR")] Collaborator,
        [EnumMember(Value = "CONTRIBUTOR")] Contributor,
        [EnumMember(Value = "FIRST_TIMER")] FirstTimer,

        [EnumMember(Value = "FIRST_TIME_CONTRIBUTOR")]
        FirstTimeContributor,
        [EnumMember(Value = "MANNEQUIN")] Mannequin,
        [EnumMember(Value = "MEMBER")] Member,
        [EnumMember(Value = "NONE")] None,
        [EnumMember(Value = "OWNER")] Owner
    }
}
