using Azure;
using Azure.Data.Tables;
using CheesyTot.AzureTables.SimpleIndex.Attributes;
using System;
using System.Runtime.Serialization;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.Models
{
    [TableName("AspNetUserLogin")]
    public class IdentityUserLogin : ITableEntity
    {
        public IdentityUserLogin() { }

        public IdentityUserLogin(string userId, string loginProvider, string providerKey)
        {
            PartitionKey = userId;
            RowKey = GetRowKey(loginProvider, providerKey);
        }

        public string PartitionKey { get; set; }

        [SimpleIndex]
        public string RowKey { get; set; }

        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }

        [IgnoreDataMember]
        public string UserId => PartitionKey;

        [IgnoreDataMember]
        public string LoginProvider => RowKey.Split(new[] { ":" }, 2, StringSplitOptions.None)[0];

        [IgnoreDataMember]
        public string ProviderKey => RowKey.Split(new[] { ":" }, 2, StringSplitOptions.None)[1];

        public string ProviderDisplayName { get; set; }

        public static string GetRowKey(string loginProvider, string providerKey) => $"{loginProvider}:{providerKey}";
    }
}
