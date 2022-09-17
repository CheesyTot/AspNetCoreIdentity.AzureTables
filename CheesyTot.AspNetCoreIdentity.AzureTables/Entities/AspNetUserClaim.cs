using Azure;
using Azure.Data.Tables;
using CheesyTot.AspNetCoreIdentity.AzureTables.Helpers;
using CheesyTot.AzureTables.SimpleIndex.Attributes;
using System;
using System.Runtime.Serialization;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.Entities
{
    internal class AspNetUserClaim : ITableEntity
    {
        public AspNetUserClaim() { }

        public AspNetUserClaim(string userId, string claimType, string claimValue)
        {
            PartitionKey = userId;
            RowKey = ClaimKeyHelper.ToKey(claimType, claimValue);
        }

        public string PartitionKey { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        [SimpleIndex]
        public string RowKey { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        
        public DateTimeOffset? Timestamp { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ETag ETag { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        [IgnoreDataMember]
        public string UserId => PartitionKey;

        [IgnoreDataMember]
        public string ClaimType => ClaimKeyHelper.GetClaimTypeFromKey(RowKey);

        [IgnoreDataMember]
        public string ClaimValue => ClaimKeyHelper.GetClaimValueFromKey(RowKey);
    }
}
