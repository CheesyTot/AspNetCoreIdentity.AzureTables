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
        public IdentityUser() : base() { }
        public IdentityUser(string userName) : base(userName) { }
        public IdentityUser(string id, string userName) : base(userName)
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
        public override string NormalizedEmail { get => base.NormalizedEmail; set => base.NormalizedEmail = value; }

        [SimpleIndex]
        public override string NormalizedUserName { get => base.NormalizedUserName; set => base.NormalizedUserName = value; }

        public string PartitionKey { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public string RowKey { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public DateTimeOffset? Timestamp { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ETag ETag { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
    }
}
