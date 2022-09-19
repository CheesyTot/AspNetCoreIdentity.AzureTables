namespace CheesyTot.AspNetCoreIdentity.AzureTables.DI
{
    public class IdentityAzureTablesOptions
    {
        public string StorageConnectionString { get; set; }
        public string TablePrefix { get; set; }
        public string IndexTableSuffix { get; set; }
        public int ChunkSize { get; set; }
    }
}
