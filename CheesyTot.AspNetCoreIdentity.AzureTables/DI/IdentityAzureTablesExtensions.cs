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
            var services = builder.Services;
            var options = new IdentityAzureTablesOptions();
            startupAction(options);

            services.Configure<IdentityAzureTablesOptions>(o =>
            {
                o.TablePrefix = options.TablePrefix;
                o.ChunkSize = options.ChunkSize;
                o.IndexTableSuffix = options.IndexTableSuffix;
                o.StorageConnectionString = options.StorageConnectionString;
            });

            services.AddScoped<ISimpleIndexRepository<Models.IdentityUser>, SimpleIndexRepository<Models.IdentityUser>>();
            services.AddScoped<ISimpleIndexRepository<Models.IdentityUserClaim>, SimpleIndexRepository<Models.IdentityUserClaim>>();
            services.AddScoped<ISimpleIndexRepository<Models.IdentityUserLogin>, SimpleIndexRepository<Models.IdentityUserLogin>>();
            services.AddScoped<ISimpleIndexRepository<Models.IdentityUserRole>, SimpleIndexRepository<Models.IdentityUserRole>>();
            services.AddScoped<ISimpleIndexRepository<Models.IdentityRole>, SimpleIndexRepository<Models.IdentityRole>>();
            services.AddScoped<ISimpleIndexRepository<Models.IdentityRoleClaim>, SimpleIndexRepository<Models.IdentityRoleClaim>>();
            services.AddScoped<ISimpleIndexRepository<Models.IdentityUserToken>, SimpleIndexRepository<Models.IdentityUserToken>>();

            builder.AddUserStore<AzureTablesUserStore>();
            builder.AddRoleStore<AzureTablesRoleStore>();

            return builder;
        }
    }
}
