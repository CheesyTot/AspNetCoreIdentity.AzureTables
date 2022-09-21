using Azure;
using Azure.Data.Tables;
using CheesyTot.AzureTables.SimpleIndex.Attributes;
using System;
using System.Runtime.Serialization;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.Models
{
    [TableName("AspNetUserRole")]
    public class IdentityUserRole : ITableEntity
    {
        public IdentityUserRole() { }

        public IdentityUserRole(string userId, string roleId)
        {
            PartitionKey = userId;
            RowKey = RoleId;
        }

        public string PartitionKey { get; set; }

        [SimpleIndex]
        public string RowKey { get; set; }

        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }

        [IgnoreDataMember]
        public string UserId => PartitionKey;

        [IgnoreDataMember]
        public string RoleId => RowKey;
    }
}
