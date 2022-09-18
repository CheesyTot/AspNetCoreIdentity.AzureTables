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

        public string PartitionKey { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        [SimpleIndex]
        public string RowKey { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public DateTimeOffset? Timestamp { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ETag ETag { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        [IgnoreDataMember]
        public string RoleId => PartitionKey;

        [IgnoreDataMember]
        public string ClaimType => ClaimKeyHelper.GetClaimTypeFromKey(RowKey);

        [IgnoreDataMember]
        public string ClaimValue => ClaimKeyHelper.GetClaimValueFromKey(RowKey);
    }
}
