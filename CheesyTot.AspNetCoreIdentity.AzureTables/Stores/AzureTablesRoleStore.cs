using CheesyTot.AspNetCoreIdentity.AzureTables.Models;
using CheesyTot.AzureTables.SimpleIndex.Repositories;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.Stores
{
    public class AzureTablesRoleStore : IRoleStore<Models.IdentityRole>, IRoleClaimStore<Models.IdentityRole>
    {
        private readonly ISimpleIndexRepository<Models.IdentityRole> _roleRepository;
        private readonly ISimpleIndexRepository<IdentityRoleClaim> _roleClaimRepository;

        public AzureTablesRoleStore(ISimpleIndexRepository<Models.IdentityRole> roleRepository,
            ISimpleIndexRepository<IdentityRoleClaim> roleClaimRepository)
        {
            _roleRepository = roleRepository;
            _roleClaimRepository = roleClaimRepository;
        }

        public async Task AddClaimAsync(Models.IdentityRole role, Claim claim, CancellationToken cancellationToken = default)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            var roleEntity = _roleRepository.GetAsync(role.PartitionKey, role.RowKey);
            if (roleEntity == null)
                throw new ArgumentOutOfRangeException(nameof(role), "IdentityRole does not exist.");

            var entity = new IdentityRoleClaim(role.Id, claim.Type, claim.Value);

            await _roleClaimRepository.AddAsync(entity);
        }

        public async Task<IdentityResult> CreateAsync(Models.IdentityRole role, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken != null)
                    cancellationToken.ThrowIfCancellationRequested();

                if (role == null)
                    throw new ArgumentNullException(nameof(role));

                await _roleRepository.AddAsync(role);

                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError { Code = ex.Message, Description = ex.Message });
            }
        }

        public async Task<IdentityResult> DeleteAsync(Models.IdentityRole role, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken != null)
                    cancellationToken.ThrowIfCancellationRequested();

                if (role == null)
                    throw new ArgumentNullException(nameof(role));

                var entity = await _roleRepository.GetAsync(role.Id, role.Id);

                if (entity != null)
                    await _roleRepository.DeleteAsync(entity);

                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError { Code = ex.Message, Description = ex.Message });
            }
        }

        public void Dispose() { }

        public async Task<Models.IdentityRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            var entity = await _roleRepository.GetAsync(roleId, roleId);

            return entity;
        }

        public async Task<Models.IdentityRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            var entity = await _roleRepository.GetSingleOrDefaultByIndexedPropertyAsync(nameof(Models.IdentityRole.NormalizedName), normalizedRoleName);

            return entity;
        }

        public async Task<IList<Claim>> GetClaimsAsync(Models.IdentityRole role, CancellationToken cancellationToken = default)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return (await _roleClaimRepository.GetAsync(role.Id))
                .Select(x => new Claim(x.ClaimType, x.ClaimValue)).ToList();
        }

        public Task<string> GetNormalizedRoleNameAsync(Models.IdentityRole role, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.NormalizedName);
        }

        public Task<string> GetRoleIdAsync(Models.IdentityRole role, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.Id);
        }

        public Task<string> GetRoleNameAsync(Models.IdentityRole role, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.Name);
        }

        public async Task RemoveClaimAsync(Models.IdentityRole role, Claim claim, CancellationToken cancellationToken = default)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            var entity = new IdentityRoleClaim(role.Id, claim.Type, claim.Value);

            await _roleClaimRepository.DeleteAsync(entity);
        }

        public Task SetNormalizedRoleNameAsync(Models.IdentityRole role, string normalizedName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            role.NormalizedName = normalizedName;

            return Task.CompletedTask;
        }

        public Task SetRoleNameAsync(Models.IdentityRole role, string roleName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            role.Name = roleName;

            return Task.CompletedTask;
        }

        public async Task<IdentityResult> UpdateAsync(Models.IdentityRole role, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken != null)
                    cancellationToken.ThrowIfCancellationRequested();

                if (role == null)
                    throw new ArgumentNullException(nameof(role));

                await _roleRepository.UpdateAsync(role);

                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError { Code = ex.Message, Description = ex.Message });
            }
        }
    }
}
