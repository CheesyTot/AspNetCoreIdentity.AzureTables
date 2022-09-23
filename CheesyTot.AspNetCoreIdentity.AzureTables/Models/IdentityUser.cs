using Azure;
using Azure.Data.Tables;
using CheesyTot.AzureTables.SimpleIndex.Attributes;
using System;
using System.Runtime.Serialization;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.Models
{
    [TableName("AspNetUser")]
    public class IdentityUser : Microsoft.AspNetCore.Identity.IdentityUser<string>, ITableEntity
    {
        public IdentityUser()
            : base()
        {
            Id = Guid.NewGuid().ToString();
        }

        public IdentityUser(string userName)
            : base(userName)
        {
            Id = Guid.NewGuid().ToString();
        }

        public IdentityUser(string id, string userName)
            : base(userName)
        {
            Id = id;
        }

        [IgnoreDataMember]
        public override string Id
        {
            get => PartitionKey;
            set
            {
                PartitionKey = value;
                RowKey = value;
            }
        }

        [SimpleIndex]
        public override string NormalizedEmail { get => base.NormalizedEmail; set => base.NormalizedEmail = value; }

        [SimpleIndex]
        public override string NormalizedUserName { get => base.NormalizedUserName; set => base.NormalizedUserName = value; }

        public string PartitionKey { get; set; }
        public string RowKey { get; set; }
        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }
        public string AuthenticatorKey { get; set; }
    }
}
