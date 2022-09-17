﻿using Azure;
using Azure.Data.Tables;
using CheesyTot.AzureTables.SimpleIndex.Attributes;
using System;
using System.Runtime.Serialization;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.Entities
{
    internal class AspNetUserRole : ITableEntity
    {
        public AspNetUserRole() { }

        public AspNetUserRole(string userId, string roleId)
        {
            PartitionKey = userId;
            RowKey = RoleId;
        }

        public string PartitionKey { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        [SimpleIndex]
        public string RowKey { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public DateTimeOffset? Timestamp { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
        public ETag ETag { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        [IgnoreDataMember]
        public string UserId => PartitionKey;

        [IgnoreDataMember]
        public string RoleId => RowKey;
    }
}
