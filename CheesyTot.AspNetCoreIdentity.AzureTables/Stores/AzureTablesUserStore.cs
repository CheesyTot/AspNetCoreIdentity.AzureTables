using CheesyTot.AspNetCoreIdentity.AzureTables.Helpers;
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
        private readonly ISimpleIndexRepository<Models.IdentityUser> _userRepository;
        private readonly ISimpleIndexRepository<Models.IdentityUserClaim> _userClaimRepository;
        private readonly ISimpleIndexRepository<Models.IdentityUserLogin> _userLoginRepository;
        private readonly ISimpleIndexRepository<Models.IdentityUserRole> _userRoleRepository;
        private readonly ISimpleIndexRepository<Models.IdentityRole> _roleRepository;
        private readonly ISimpleIndexRepository<Models.IdentityUserToken> _userTokenRepository;

        public AzureTablesUserStore(ISimpleIndexRepository<Models.IdentityUser> userRepository,
            ISimpleIndexRepository<Models.IdentityUserClaim> userClaimRepository,
            ISimpleIndexRepository<Models.IdentityUserLogin> userLoginRepository,
            ISimpleIndexRepository<Models.IdentityUserRole> userRoleRepository,
            ISimpleIndexRepository<Models.IdentityRole> roleRepository,
            ISimpleIndexRepository<Models.IdentityUserToken> userTokenRepository)
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

        public async Task<IdentityResult> CreateAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken != null)
                    cancellationToken.ThrowIfCancellationRequested();

                if (user == null)
                    throw new ArgumentNullException(nameof(user));

                await _userRepository.AddAsync(user);

                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError { Code = ex.Message, Description = ex.Message });
            }
        }

        public async Task<IdentityResult> DeleteAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken != null)
                    cancellationToken.ThrowIfCancellationRequested();

                if (user == null)
                    throw new ArgumentNullException(nameof(user));

                var entity = await _userRepository.GetAsync(user.Id, user.Id);

                if (entity != null)
                {
                    await _userRepository.DeleteAsync(entity);
                }

                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError { Code = ex.Message, Description = ex.Message });
            }
        }

        public void Dispose() { }

        public async Task<Models.IdentityUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(normalizedEmail))
                throw new ArgumentNullException(nameof(normalizedEmail));

            var userEntity = await _userRepository.GetFirstOrDefaultByIndexedPropertyAsync(nameof(Models.IdentityUser.NormalizedEmail), normalizedEmail);

            return userEntity;
        }

        public async Task<Models.IdentityUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(userId))
                throw new ArgumentNullException(nameof(userId));

            var userEntity = await _userRepository.GetAsync(userId, userId);

            return userEntity;
        }

        public async Task<Models.IdentityUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentNullException(nameof(loginProvider));

            if (string.IsNullOrWhiteSpace(providerKey))
                throw new ArgumentNullException(nameof(providerKey));

            var login = await _userLoginRepository.GetFirstOrDefaultByIndexedPropertyAsync(nameof(IdentityUserLogin.RowKey), IdentityUserLogin.GetRowKey(loginProvider, providerKey));

            if (login == null)
                return default;

            var entity = await _userRepository.GetAsync(login.UserId, login.UserId);

            return entity;
        }

        public async Task<Models.IdentityUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(normalizedUserName))
                throw new ArgumentNullException(nameof(normalizedUserName));

            var userEntity = await _userRepository.GetSingleOrDefaultByIndexedPropertyAsync(nameof(Models.IdentityUser.NormalizedUserName), normalizedUserName);

            return userEntity;
        }

        public Task<int> GetAccessFailedCountAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.AccessFailedCount);
        }

        public async Task<IList<Claim>> GetClaimsAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return (await _userClaimRepository.GetAsync(user.Id)).Select(x => new Claim(x.ClaimType, x.ClaimValue)).ToList();
        }

        public Task<string> GetEmailAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.EmailConfirmed);
        }

        public Task<bool> GetLockoutEnabledAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.LockoutEnabled);
        }

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.LockoutEnd);
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return (await _userLoginRepository.GetAsync(user.Id))
                .Select(x => new UserLoginInfo(x.LoginProvider, x.ProviderKey, x.ProviderDisplayName))
                .ToList();
        }

        public Task<string> GetNormalizedEmailAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.NormalizedEmail);
        }

        public Task<string> GetNormalizedUserNameAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.NormalizedUserName);
        }

        public Task<string> GetPasswordHashAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.PasswordHash);
        }

        public Task<string> GetPhoneNumberAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public async Task<IList<string>> GetRolesAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var roleIds = (await _userRoleRepository.GetAsync(user.Id)).Select(x => x.RoleId);
            var roleNames = new List<string>();

            foreach(var roleId in roleIds)
            {
                var role = await _roleRepository.GetAsync(roleId, roleId);
                if (role != null)
                    roleNames.Add(role.Name);
            }

            return (roleNames).ToList();
        }

        public Task<string> GetSecurityStampAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.SecurityStamp);
        }

        public async Task<string> GetTokenAsync(Models.IdentityUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentNullException(nameof(loginProvider));

            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));

            var entity = await _userTokenRepository.GetAsync(user.Id, IdentityUserToken.GetRowKey(loginProvider, name));

            return entity?.Value;
        }

        public Task<bool> GetTwoFactorEnabledAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.TwoFactorEnabled);
        }

        public Task<string> GetUserIdAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Id);
        }

        public Task<string> GetUserNameAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.UserName);
        }

        public async Task<IList<Models.IdentityUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            var userIds = (await _userClaimRepository
                .GetByIndexedPropertyAsync(nameof(Models.IdentityUserClaim.RowKey), ClaimKeyHelper.ToKey(claim.Type, claim.Value)))
                .Select(x => x.UserId);

            var result = new List<Models.IdentityUser>();
            foreach(var userId in userIds)
            {
                var user = await _userRepository.GetAsync(userId, userId);
                if (user != null)
                    result.Add(user);
            }

            return result;
        }

        public async Task<IList<Models.IdentityUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentNullException(nameof(roleName));

            var role = await _roleRepository.GetSingleOrDefaultByIndexedPropertyAsync(nameof(Models.IdentityRole.NormalizedName), roleName);
            if (role == null)
                return new List<Models.IdentityUser>();

            var userIds = (await _userRoleRepository.GetByIndexedPropertyAsync(nameof(IdentityUserRole.RowKey), role.Id)).Select(x => x.UserId);

            var result = new List<Models.IdentityUser>();
            foreach (var userId in userIds)
            {
                var user = await _userRepository.GetAsync(userId, userId);
                if (user != null)
                    result.Add(user);
            }

            return result;
        }

        public Task<bool> HasPasswordAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(!string.IsNullOrWhiteSpace(user.PasswordHash));
        }

        public Task<int> IncrementAccessFailedCountAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(++user.AccessFailedCount);
        }

        public async Task<bool> IsInRoleAsync(Models.IdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentNullException(nameof(roleName));

            var role = await _roleRepository.GetSingleOrDefaultByIndexedPropertyAsync(nameof(Models.IdentityRole.NormalizedName), roleName);
            if (role == null)
                return false;

            var userRole = await _userRoleRepository.GetAsync(user.Id, role.Id);

            return userRole != null;
        }

        public async Task RemoveClaimsAsync(Models.IdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (claims == null)
                throw new ArgumentNullException(nameof(claims));

            if (claims.Any())
            {
                var claimEntities = claims.Select(x => new Models.IdentityUserClaim(user.Id, x.Type, x.Value));
                foreach (var claimEntity in claimEntities)
                    await _userClaimRepository.DeleteAsync(claimEntity);
            }
        }

        public async Task RemoveFromRoleAsync(Models.IdentityUser user, string roleName, CancellationToken cancellationToken)
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

            var userRole = new Models.IdentityUserRole(user.Id, role.Id);

            await _userRoleRepository.DeleteAsync(userRole);
        }

        public async Task RemoveLoginAsync(Models.IdentityUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentNullException(nameof(loginProvider));

            if (string.IsNullOrWhiteSpace(providerKey))
                throw new ArgumentNullException(nameof(providerKey));

            var loginEntity = new Models.IdentityUserLogin(user.Id, loginProvider, providerKey);

            await _userLoginRepository.DeleteAsync(loginEntity);
        }

        public async Task RemoveTokenAsync(Models.IdentityUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentNullException(nameof(loginProvider));

            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));

            var entity = await _userTokenRepository.GetAsync(user.Id, Models.IdentityUserToken.GetRowKey(loginProvider, name));

            if (entity != null)
                await _userTokenRepository.DeleteAsync(entity);
        }

        public async Task ReplaceClaimAsync(Models.IdentityUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            if (newClaim == null)
                throw new ArgumentNullException(nameof(newClaim));

            var oldClaimEntity = await _userClaimRepository.GetAsync(user.Id, ClaimKeyHelper.ToKey(claim));
            var newClaimEntity = new Models.IdentityUserClaim(user.Id, newClaim.Type, newClaim.Value);

            await _userClaimRepository.DeleteAsync(oldClaimEntity);
            await _userClaimRepository.AddAsync(newClaimEntity);
        }

        public Task ResetAccessFailedCountAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.AccessFailedCount = 0;

            return Task.CompletedTask;
        }

        public Task SetEmailAsync(Models.IdentityUser user, string email, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.Email = email;

            return Task.CompletedTask;
        }

        public Task SetEmailConfirmedAsync(Models.IdentityUser user, bool confirmed, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.EmailConfirmed = confirmed;

            return Task.CompletedTask;
        }

        public Task SetLockoutEnabledAsync(Models.IdentityUser user, bool enabled, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.LockoutEnabled = enabled;

            return Task.CompletedTask;
        }

        public Task SetLockoutEndDateAsync(Models.IdentityUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.LockoutEnd = lockoutEnd;

            return Task.CompletedTask;
        }

        public Task SetNormalizedEmailAsync(Models.IdentityUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.NormalizedEmail = normalizedEmail;

            return Task.CompletedTask;
        }

        public Task SetNormalizedUserNameAsync(Models.IdentityUser user, string normalizedName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.NormalizedUserName = normalizedName;

            return Task.CompletedTask;
        }

        public Task SetPasswordHashAsync(Models.IdentityUser user, string passwordHash, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.PasswordHash = passwordHash;

            return Task.CompletedTask;
        }

        public Task SetPhoneNumberAsync(Models.IdentityUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.PhoneNumber = phoneNumber;

            return Task.CompletedTask;
        }

        public Task SetPhoneNumberConfirmedAsync(Models.IdentityUser user, bool confirmed, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.PhoneNumberConfirmed = confirmed;

            return Task.CompletedTask;
        }

        public Task SetSecurityStampAsync(Models.IdentityUser user, string stamp, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.SecurityStamp = stamp;

            return Task.CompletedTask;
        }

        public async Task SetTokenAsync(Models.IdentityUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentNullException(nameof(loginProvider));

            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));

            var entity = await _userTokenRepository.GetAsync(user.Id, Models.IdentityUserToken.GetRowKey(loginProvider, name));

            if (entity != null)
            {
                entity.Value = value;
                await _userTokenRepository.UpdateAsync(entity);
            }
            else
            {
                entity = new Models.IdentityUserToken(user.Id, loginProvider, name) { Value = value };
                await _userTokenRepository.AddAsync(entity);
            }
        }

        public Task SetTwoFactorEnabledAsync(Models.IdentityUser user, bool enabled, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.TwoFactorEnabled = enabled;

            return Task.CompletedTask;
        }

        public Task SetUserNameAsync(Models.IdentityUser user, string userName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.UserName = userName;

            return Task.CompletedTask;
        }

        public async Task<IdentityResult> UpdateAsync(Models.IdentityUser user, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken != null)
                    cancellationToken.ThrowIfCancellationRequested();

                if (user == null)
                    throw new ArgumentNullException(nameof(user));

                await _userRepository.UpdateAsync(user);

                return IdentityResult.Success;

            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError { Code = ex.Message, Description = ex.Message });
            }
        }
    }
}
