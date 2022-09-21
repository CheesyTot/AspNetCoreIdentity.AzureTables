using CheesyTot.AspNetCoreIdentity.AzureTables.Stores;
using CheesyTot.AzureTables.SimpleIndex.Repositories;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.DI
{
    public static class IdentityAzureTablesExtensions
    {
        public static IdentityBuilder AddAzureTableStorageStores(this IdentityBuilder builder, Action<IdentityAzureTablesOptions> startupAction)
        {
            var options = new IdentityAzureTablesOptions();
            startupAction(options);

            builder.Services.Configure<SimpleIndexRepositoryOptions>(o =>
            {
                o.TablePrefix = options.TablePrefix;
                o.IndexTableSuffix = options.IndexTableSuffix;
                o.StorageConnectionString = options.StorageConnectionString;
            });

            builder.Services.AddScoped<ISimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUser>, SimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUser>>();
            builder.Services.AddScoped<ISimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUserClaim>, SimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUserClaim>>();
            builder.Services.AddScoped<ISimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUserLogin>, SimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUserLogin>>();
            builder.Services.AddScoped<ISimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUserRole>, SimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUserRole>>();
            builder.Services.AddScoped<ISimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityRole>, SimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityRole>>();
            builder.Services.AddScoped<ISimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityRoleClaim>, SimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityRoleClaim>>();
            builder.Services.AddScoped<ISimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUserToken>, SimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUserToken>>();

            builder.AddUserStore<AzureTablesUserStore>();
            builder.AddRoleStore<AzureTablesRoleStore>();

            return builder;
        }
    }
}
