using Azure;
using Azure.Data.Tables;
using CheesyTot.AzureTables.SimpleIndex.Attributes;
using System;
using System.Runtime.Serialization;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.Models
{
    [TableName("AspNetUserToken")]
    public class IdentityUserToken : ITableEntity
    {
        public IdentityUserToken() { }

        public IdentityUserToken(string userId, string loginProvider, string name)
        {
            PartitionKey = userId;
            RowKey = GetRowKey(loginProvider, name);
        }

        public string PartitionKey { get; set; }

        [SimpleIndex]
        public string RowKey { get; set; }

        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }

        [IgnoreDataMember]
        public string UserId => PartitionKey;

        [IgnoreDataMember]
        public string LoginProvider => RowKey.Split(new[] { "|" }, 2, StringSplitOptions.None)[0];

        [IgnoreDataMember]
        public string Name => RowKey.Split(new[] { "|" }, 2, StringSplitOptions.None)[1];

        public string Value { get; set; }

        public static string GetRowKey(string loginProvider, string name) => $"{loginProvider}|{name}";
    }
}
