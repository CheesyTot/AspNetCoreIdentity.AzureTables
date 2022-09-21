using Azure;
using Azure.Data.Tables;
using CheesyTot.AzureTables.SimpleIndex.Attributes;
using System;
using System.Runtime.Serialization;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.Models
{
    [TableName("AspNetRole")]
    public class IdentityRole : Microsoft.AspNetCore.Identity.IdentityRole<string>, ITableEntity
    {
        public IdentityRole()
            : base()
        {
            Id = Guid.NewGuid().ToString();
        }

        public IdentityRole(string roleName)
            : base(roleName)
        {
            Id = Guid.NewGuid().ToString();
        }

        public IdentityRole(string id, string roleName)
            : base(roleName)
        {
            Id = id;
        }

        [IgnoreDataMember]
        public override string Id
        {
            get => PartitionKey;
            set => RowKey = PartitionKey = value;
        }

        [SimpleIndex]
        public override string NormalizedName { get => base.NormalizedName; set => base.NormalizedName = value; }

        public string PartitionKey { get; set; }
        public string RowKey { get; set; }
        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }
    }
}
