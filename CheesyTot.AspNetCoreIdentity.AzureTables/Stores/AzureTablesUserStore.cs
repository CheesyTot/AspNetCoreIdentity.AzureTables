using CheesyTot.AspNetCoreIdentity.AzureTables.Models;
using CheesyTot.AzureTables.SimpleIndex.Repositories;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.Stores
{
    public class AzureTablesUserStore :
        IUserStore<Models.IdentityUser>,
        IUserPasswordStore<Models.IdentityUser>,
        IUserEmailStore<Models.IdentityUser>,
        IUserLoginStore<Models.IdentityUser>,
        IUserRoleStore<Models.IdentityUser>,
        IUserSecurityStampStore<Models.IdentityUser>,
        IUserClaimStore<Models.IdentityUser>,
        IUserAuthenticationTokenStore<Models.IdentityUser>,
        IUserTwoFactorStore<Models.IdentityUser>,
        IUserPhoneNumberStore<Models.IdentityUser>,
        IUserLockoutStore<Models.IdentityUser>,
        IQueryableUserStore<Models.IdentityUser>
    {
        private readonly SimpleIndexRepository<Models.IdentityUser> _userRepository;
        private readonly SimpleIndexRepository<IdentityUserClaim> _userClaimRepository;
        private readonly SimpleIndexRepository<IdentityUserLogin> _userLoginRepository;
        private readonly SimpleIndexRepository<IdentityUserRole> _userRoleRepository;
        private readonly SimpleIndexRepository<Models.IdentityRole> _roleRepository;
        private readonly SimpleIndexRepository<IdentityUserToken> _userTokenRepository;

        public AzureTablesUserStore(SimpleIndexRepository<Models.IdentityUser> userRepository,
            SimpleIndexRepository<IdentityUserClaim> userClaimRepository,
            SimpleIndexRepository<IdentityUserLogin> userLoginRepository,
            SimpleIndexRepository<IdentityUserRole> userRoleRepository,
            SimpleIndexRepository<Models.IdentityRole> roleRepository,
            SimpleIndexRepository<IdentityUserToken> userTokenRepository)
        {
            _userRepository = userRepository;
            _userClaimRepository = userClaimRepository;
            _userLoginRepository = userLoginRepository;
            _userRoleRepository = userRoleRepository;
            _roleRepository = roleRepository;
            _userTokenRepository = userTokenRepository;
        }

        public IQueryable<Models.IdentityUser> Users => _userRepository.GetAsync()
            .ConfigureAwait(false)
            .GetAwaiter()
            .GetResult()
            .AsQueryable();

        public async Task AddClaimsAsync(Models.IdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (claims == null)
                throw new ArgumentNullException(nameof(claims));

            var existing = await _userRepository.GetAsync(user.Id, user.Id);
            if (existing == null)
                throw new ArgumentOutOfRangeException(nameof(user), "User does not exist");

            var claimEntities = claims.Select(x => new IdentityUserClaim(user.Id, x.Type, x.Value));

            foreach (var claimEntity in claimEntities)
                await _userClaimRepository.AddAsync(claimEntity);
        }

        public async Task AddLoginAsync(Models.IdentityUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (login == null)
                throw new ArgumentNullException(nameof(login));

            if (string.IsNullOrWhiteSpace(login.LoginProvider))
                throw new ArgumentNullException(nameof(login.LoginProvider));

            if (string.IsNullOrWhiteSpace(login.ProviderKey))
                throw new ArgumentNullException(nameof(login.ProviderKey));

            var existing = await _userRepository.GetAsync(user.Id, user.Id);
            if (existing == null)
                throw new ArgumentOutOfRangeException(nameof(user), "User does not exist");

            var loginEntity = new IdentityUserLogin(user.Id, login.LoginProvider, login.ProviderKey)
            {
                ProviderDisplayName = login.ProviderDisplayName
            };

            await _userLoginRepository.AddAsync(loginEntity);
        }

        public async Task AddToRoleAsync(Models.IdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentNullException(nameof(roleName));

            var role = await _roleRepository.GetSingleOrDefaultByIndexedPropertyAsync(nameof(Models.IdentityRole.NormalizedName), roleName);
            if (role == null)
                throw new ArgumentOutOfRangeException(nameof(roleName), "Role does not exist");

            var userRole = await _userRoleRepository.GetAsync(user.Id, role.Id);
            if (userRole != null)
                return;

            var existingUser = await _userRepository.GetAsync(user.Id, user.Id);
            if (existingUser == null)
                throw new ArgumentOutOfRangeException(nameof(user), "User does not exist");

            userRole = new IdentityUserRole(user.Id, role.Id);

            await _userRoleRepository.AddAsync(userRole);
        }

        public Task<IdentityResult> CreateAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityResult> DeleteAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public Task<Models.IdentityUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<Models.IdentityUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<Models.IdentityUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<Models.IdentityUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<int> GetAccessFailedCountAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IList<Claim>> GetClaimsAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetEmailAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetEmailConfirmedAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetLockoutEnabledAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetNormalizedEmailAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetNormalizedUserNameAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetPasswordHashAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetPhoneNumberAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IList<string>> GetRolesAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetSecurityStampAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetTokenAsync(Models.IdentityUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<bool> GetTwoFactorEnabledAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetUserIdAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetUserNameAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IList<Models.IdentityUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IList<Models.IdentityUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<bool> HasPasswordAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<int> IncrementAccessFailedCountAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<bool> IsInRoleAsync(Models.IdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task RemoveClaimsAsync(Models.IdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task RemoveFromRoleAsync(Models.IdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task RemoveLoginAsync(Models.IdentityUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task RemoveTokenAsync(Models.IdentityUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task ReplaceClaimAsync(Models.IdentityUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task ResetAccessFailedCountAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetEmailAsync(Models.IdentityUser user, string email, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetEmailConfirmedAsync(Models.IdentityUser user, bool confirmed, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetLockoutEnabledAsync(Models.IdentityUser user, bool enabled, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetLockoutEndDateAsync(Models.IdentityUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetNormalizedEmailAsync(Models.IdentityUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetNormalizedUserNameAsync(Models.IdentityUser user, string normalizedName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetPasswordHashAsync(Models.IdentityUser user, string passwordHash, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetPhoneNumberAsync(Models.IdentityUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetPhoneNumberConfirmedAsync(Models.IdentityUser user, bool confirmed, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetSecurityStampAsync(Models.IdentityUser user, string stamp, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetTokenAsync(Models.IdentityUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetTwoFactorEnabledAsync(Models.IdentityUser user, bool enabled, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetUserNameAsync(Models.IdentityUser user, string userName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityResult> UpdateAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }
}
