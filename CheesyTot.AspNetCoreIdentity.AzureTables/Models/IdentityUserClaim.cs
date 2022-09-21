using Azure;
using Azure.Data.Tables;
using CheesyTot.AspNetCoreIdentity.AzureTables.Helpers;
using CheesyTot.AzureTables.SimpleIndex.Attributes;
using System;
using System.Runtime.Serialization;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.Models
{
    [TableName("AspNetUserClaim")]
    public class IdentityUserClaim : ITableEntity
    {
        public IdentityUserClaim() { }

        public IdentityUserClaim(string userId, string claimType, string claimValue)
        {
            PartitionKey = userId;
            RowKey = ClaimKeyHelper.ToKey(claimType, claimValue);
        }

        public string PartitionKey { get; set; }

        [SimpleIndex]
        public string RowKey { get; set; }

        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }

        [IgnoreDataMember]
        public string UserId => PartitionKey;

        [IgnoreDataMember]
        public string ClaimType => ClaimKeyHelper.GetClaimTypeFromKey(RowKey);

        [IgnoreDataMember]
        public string ClaimValue => ClaimKeyHelper.GetClaimValueFromKey(RowKey);
    }
}
