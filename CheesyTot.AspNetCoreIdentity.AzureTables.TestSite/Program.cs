using Microsoft.AspNetCore.Identity;
using CheesyTot.AspNetCoreIdentity.AzureTables.DI;
using CheesyTot.AzureTables.SimpleIndex.Repositories;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

var identityBuilder = builder.Services.AddDefaultIdentity<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUser>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
    options.User.RequireUniqueEmail = true;
});
identityBuilder.AddRoles<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityRole>();
identityBuilder.AddAzureTableStorageStores(options =>
{
    options.TablePrefix = builder.Configuration.GetValue<string>("CheesyTot:TablePrefix");
    options.StorageConnectionString = builder.Configuration.GetValue<string>("CheesyTot:StorageConnectionString");
    options.IndexTableSuffix = builder.Configuration.GetValue<string>("CheesyTot:IndexTableSuffix");
});

identityBuilder.AddDefaultTokenProviders();
identityBuilder.AddUserManager<UserManager<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUser>>();
identityBuilder.AddSignInManager<SignInManager<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUser>>();
identityBuilder.AddRoleManager<RoleManager<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityRole>>();

builder.Services.AddRazorPages();

//var qq = builder.Services.Where(x => x.ServiceType == typeof(ISimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUser>)).ToList();
//var sp = builder.Services.BuildServiceProvider();
//var ww = sp.GetRequiredService<ISimpleIndexRepository<CheesyTot.AspNetCoreIdentity.AzureTables.Models.IdentityUser>>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();
