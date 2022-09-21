using Azure;
using Azure.Data.Tables;
using System;
using System.Runtime.Serialization;
using CheesyTot.AspNetCoreIdentity.AzureTables.Helpers;
using CheesyTot.AzureTables.SimpleIndex.Attributes;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.Models
{
    [TableName("AspNetRoleClaim")]
    public class IdentityRoleClaim : ITableEntity
    {
        public IdentityRoleClaim() { }

        public IdentityRoleClaim(string roleId, string claimType, string claimValue)
        {
            PartitionKey = roleId;
            RowKey = ClaimKeyHelper.ToKey(claimType, claimValue);
        }

        public string PartitionKey { get; set; }

        [SimpleIndex]
        public string RowKey { get; set; }

        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }

        [IgnoreDataMember]
        public string RoleId => PartitionKey;

        [IgnoreDataMember]
        public string ClaimType => ClaimKeyHelper.GetClaimTypeFromKey(RowKey);

        [IgnoreDataMember]
        public string ClaimValue => ClaimKeyHelper.GetClaimValueFromKey(RowKey);
    }
}
