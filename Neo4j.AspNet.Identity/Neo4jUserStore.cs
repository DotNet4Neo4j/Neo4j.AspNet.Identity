namespace Neo4j.AspNet.Identity
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Identity;
    using Neo4jClient;
    using Neo4jClient.Cypher;

    public class Neo4jUserStore<TUser> :
            IUserLoginStore<TUser>,
            IUserClaimStore<TUser>,
            IUserRoleStore<TUser>,
            IUserPasswordStore<TUser>,
            IUserSecurityStampStore<TUser>,
            IUserStore<TUser>,
            IUserEmailStore<TUser>,
            IUserLockoutStore<TUser, object>,
            IUserTwoFactorStore<TUser, string>,
            IUserPhoneNumberStore<TUser>
        where TUser : IdentityUser, IUser<string>, new()
    {
        private readonly IGraphClient _graphClient;
        private bool _disposed;

        public Neo4jUserStore(IGraphClient graphClient, string userLabel = null)
        {
            _graphClient = graphClient;
            UserLabel = string.IsNullOrWhiteSpace(userLabel) ? ApplicationUser.Labels : userLabel;
        }

        private string UserLabel { get; }

        /// <inheritdoc />
        public async Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            return DateTimeOffset.UtcNow;
        }

        /// <inheritdoc />
        public async Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
        }

        /// <inheritdoc />
        public async Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            return 0;
        }

        /// <inheritdoc />
        public async Task ResetAccessFailedCountAsync(TUser user)
        {
        }

        /// <inheritdoc />
        public async Task<int> GetAccessFailedCountAsync(TUser user)
        {
            return 0;
        }

        /// <inheritdoc />
        public async Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            return false;
        }

        /// <inheritdoc />
        public async Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
        }

        /// <inheritdoc />
        public async Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            Throw.ArgumentException.IfNull(user, "user");
            Throw.ArgumentException.IfNull(phoneNumber, "phoneNumber");
            ThrowIfDisposed();
            user.PhoneNumber = phoneNumber;
        }

        /// <inheritdoc />
        public async Task<string> GetPhoneNumberAsync(TUser user)
        {
            Throw.ArgumentException.IfNull(user, "user");
            return user.PhoneNumber;
        }

        /// <inheritdoc />
        public async Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            Throw.ArgumentException.IfNull(user, "user");
            return user.PhoneNumberConfirmed;
        }

        /// <inheritdoc />
        public async Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            Throw.ArgumentException.IfNull(user, "user");
            user.PhoneNumberConfirmed = confirmed;
        }

        /// <inheritdoc />
        public async Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
        }

        /// <inheritdoc />
        public async Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            return false;
        }

        /// <summary>
        ///     Gets: MATCH (
        /// </summary>
        private ICypherFluentQuery UserMatch(string userIdentifier = "u")
        {
            return new CypherFluentQuery(_graphClient).Match($"({userIdentifier}:{UserLabel})");
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        #region Internal Classes for Serialization

        internal class FindUserResult<T>
            where T : IdentityUser, new()
        {
            public T User { private get; set; }
            public IEnumerable<Neo4jUserLoginInfo> Logins { private get; set; }
            public IEnumerable<IdentityUserClaim> Claims { private get; set; }

            public T Combine()
            {
                var output = User;
                if (Logins != null)
                    output.Logins = new List<UserLoginInfo>(Logins.Select(l => l.ToUserLoginInfo()));
                if (Claims != null)
                    output.Claims = new List<IdentityUserClaim>(Claims);

                return output;
            }
        }

        // ReSharper disable once ClassNeverInstantiated.Local
        internal class Role
        {
            public string Name { get; set; }
        }

        // ReSharper disable once ClassNeverInstantiated.Local
        internal class Neo4jUserLoginInfo
        {
            /// <summary>
            ///     Provider for the linked login, i.e. Facebook, Google, etc.
            /// </summary>
            public string LoginProvider { get; set; }

            /// <summary>
            ///     User specific key for the login provider
            /// </summary>
            public string ProviderKey { get; set; }

            public UserLoginInfo ToUserLoginInfo()
            {
                return new UserLoginInfo(LoginProvider, ProviderKey);
            }
        }

        #endregion Internal Classes for Serialization

        #region IUserLoginStore

        /// <inheritdoc />
        public async Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            Throw.ArgumentException.IfNull(user, "user");
            Throw.ArgumentException.IfNull(login, "login");

            ThrowIfDisposed();
            await Task.Run(() =>
            {
                if (!user.Logins.Any(x => (x.LoginProvider == login.LoginProvider) && (x.ProviderKey == login.ProviderKey)))
                    user.Logins.Add(login);
            });
        }

        /// <inheritdoc />
        public async Task<TUser> FindAsync(UserLoginInfo login)
        {
            Throw.ArgumentException.IfNull(login, "login");
            ThrowIfDisposed();

            var results = await _graphClient.Cypher
                .Match($"(l:{Labels.Login})<-[:{Relationship.HasLogin}]-(u:{UserLabel})")
                .Where((UserLoginInfo l) => l.ProviderKey == login.ProviderKey)
                .AndWhere((UserLoginInfo l) => l.LoginProvider == login.LoginProvider)
                .OptionalMatch($"(u)-[:{Relationship.HasClaim}]->(c:{Labels.Claim})")
                .Return((u, c, l) => new FindUserResult<TUser>
                {
                    User = u.As<TUser>(),
                    Logins = l.CollectAs<Neo4jUserLoginInfo>(),
                    Claims = c.CollectAs<IdentityUserClaim>()
                }).ResultsAsync;

            var result = results.SingleOrDefault();
            return result?.Combine();
        }

        /// <inheritdoc />
        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            Throw.ArgumentException.IfNull(user, "user");
            ThrowIfDisposed();

            return await Task.Run(() => user.Logins as IList<UserLoginInfo>);
        }

        /// <inheritdoc />
        public async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            Throw.ArgumentException.IfNull(user, "user");
            Throw.ArgumentException.IfNull(login, "login");
            ThrowIfDisposed();

            await Task.Run(() => user.Logins.RemoveAll(x => (x.LoginProvider == login.LoginProvider) && (x.ProviderKey == login.ProviderKey)));
        }

        /// <inheritdoc />
        public async Task CreateAsync(TUser user)
        {
            Throw.ArgumentException.IfNull(user, "user");
            Throw.ArgumentException.IfNull(user, "user");
            ThrowIfDisposed();

            if (string.IsNullOrWhiteSpace(user.Id))
                user.Id = Guid.NewGuid().ToString();

            var query = _graphClient.Cypher
                .Create("(u:User { user })")
                .WithParams(new {user});

            await query.ExecuteWithoutResultsAsync();
        }

        /// <inheritdoc />
        public async Task DeleteAsync(TUser user)
        {
            Throw.ArgumentException.IfNull(user, "user");
            ThrowIfDisposed();

            await UserMatch()
                .Where((TUser u) => u.Id == user.Id)
                .OptionalMatch($"(u)-[lr:{Relationship.HasLogin}]->(l)")
                .OptionalMatch($"(u)-[cr:{Relationship.HasClaim}]->(c)")
                .Delete("u,lr,cr,l,c")
                .ExecuteWithoutResultsAsync();
        }

        /// <inheritdoc />
        public async Task<TUser> FindByIdAsync(object userId)
        {
            Throw.ArgumentException.IfNull(userId, "userId");
            return await FindByIdAsync(userId.ToString());
        }

        /// <inheritdoc />
        public async Task<TUser> FindByIdAsync(string userId)
        {
            Throw.ArgumentException.IfNull(userId, "userId");
            ThrowIfDisposed();

            var query = UserMatch()
                .Where((TUser u) => u.Id == userId)
                .OptionalMatch($"(u)-[lr:{Relationship.HasLogin}]->(l:{Labels.Login})")
                .OptionalMatch($"(u)-[cr:{Relationship.HasClaim}]->(c:{Labels.Claim})")
                .Return((u, c, l) => new FindUserResult<TUser>
                {
                    User = u.As<TUser>(),
                    Logins = l.CollectAs<Neo4jUserLoginInfo>(),
                    Claims = c.CollectAs<IdentityUserClaim>()
                });

            var user = (await query.ResultsAsync).SingleOrDefault();

            return user?.Combine();
        }

        /// <inheritdoc />
        public async Task<TUser> FindByNameAsync(string userName)
        {
            Throw.ArgumentException.IfNullOrWhiteSpace(userName, "userName");
            ThrowIfDisposed();

            userName = userName.ToLowerInvariant().Trim();

            var query = UserMatch()
                .Where((TUser u) => u.UserName == userName)
                .OptionalMatch($"(u)-[lr:{Relationship.HasLogin}]->(l:{Labels.Login})")
                .OptionalMatch($"(u)-[cr:{Relationship.HasClaim}]->(c:{Labels.Claim})")
                .Return((u, c, l) => new FindUserResult<TUser>
                {
                    User = u.As<TUser>(),
                    Logins = l.CollectAs<Neo4jUserLoginInfo>(),
                    Claims = c.CollectAs<IdentityUserClaim>()
                });

            var results = await query.ResultsAsync;
            var findUserResult = results.SingleOrDefault();
            return findUserResult?.Combine();
        }

        /// <inheritdoc />
        public async Task UpdateAsync(TUser user)
        {
            Throw.ArgumentException.IfNull(user, "user");
            ThrowIfDisposed();

            var query = UserMatch()
                .Where((TUser u) => u.Id == user.Id)
                .Set("u = {userParam}")
                .WithParam("userParam", user)
                .With("u").OptionalMatch("(u)-[cr:HAS_CLAIM]->(c:Claim)").Delete("c,cr")
                .With("u").OptionalMatch("(u)-[lr:HAS_LOGIN]->(l:Login)").Delete("l,lr")
                .With("u").OptionalMatch("(u)-[rl:IN_ROLE]->(r:Role)").Delete("rl");

            query = AddClaims(query, user.Claims);
            query = AddLogins(query, user.Logins);

            await query.ExecuteWithoutResultsAsync();
        }

        private static ICypherFluentQuery AddClaims(ICypherFluentQuery query, IList<IdentityUserClaim> claims)
        {
            if ((claims == null) || (claims.Count == 0))
                return query;

            for (var i = 0; i < claims.Count; i++)
            {
                var claimName = $"claim{i}";
                var claimParam = claims[i];
                query = query.With("u")
                    .Create($"(u)-[:HAS_CLAIM]->(c{i}:claim {{{claimName}}})")
                    .WithParam(claimName, claimParam);
            }
            return query;
        }

        private static ICypherFluentQuery AddLogins(ICypherFluentQuery query, IList<UserLoginInfo> logins)
        {
            if ((logins == null) || (logins.Count == 0))
                return query;

            for (var i = 0; i < logins.Count; i++)
            {
                var loginName = $"login{i}";
                var loginParam = logins[i];
                query = query.With("u")
                    .Create($"(u)-[:HAS_LOGIN]->(l{i}:Login {{{loginName}}})")
                    .WithParam(loginName, loginParam);
            }
            return query;
        }


        /// <inheritdoc />
        public void Dispose()
        {
            _disposed = true;
        }

        #endregion

        #region IUserClaimStore

        /// <inheritdoc />
        public async Task AddClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            Throw.ArgumentException.IfNull(claim, "claim");
            Throw.ArgumentException.IfNull(user, "user");

            await Task.Run(() =>
            {
                if (!user.Claims.Any(x => (x.ClaimType == claim.Type) && (x.ClaimValue == claim.Value)))
                    user.Claims.Add(new IdentityUserClaim
                    {
                        ClaimType = claim.Type,
                        ClaimValue = claim.Value
                    });
            });
        }

        /// <inheritdoc />
        public async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            ThrowIfDisposed();
            Throw.ArgumentException.IfNull(user, "user");

            return await Task.Run(() => user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList());
        }

        /// <inheritdoc />
        public async Task RemoveClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            Throw.ArgumentException.IfNull(user, "user");

            await Task.Run(() => user.Claims.RemoveAll(x => (x.ClaimType == claim.Type) && (x.ClaimValue == claim.Value)));
        }

        #endregion

        #region IUserRoleStore

        /// <inheritdoc />
        public async Task AddToRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            Throw.ArgumentException.IfNull(user, "user");

            await Task.Run(() =>
            {
                if (!user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase))
                    user.Roles.Add(roleName);
            });
        }

        /// <inheritdoc />
        public async Task<IList<string>> GetRolesAsync(TUser user)
        {
            ThrowIfDisposed();
            Throw.ArgumentException.IfNull(user, "user");

            return await Task.Run(() => user.Roles);
        }

        /// <inheritdoc />
        public async Task<bool> IsInRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            Throw.ArgumentException.IfNull(user, "user");

            return await Task.Run(() => user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase));
        }

        /// <inheritdoc />
        public async Task RemoveFromRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            Throw.ArgumentException.IfNull(user, "user");

            await Task.Run(() => user.Roles.RemoveAll(r => string.Equals(r, roleName, StringComparison.InvariantCultureIgnoreCase)));
        }

        #endregion

        #region IUserPasswordStore

        /// <inheritdoc />
        public async Task<string> GetPasswordHashAsync(TUser user)
        {
            ThrowIfDisposed();
            Throw.ArgumentException.IfNull(user, "user");

            return await Task.Run(() => user.PasswordHash);
        }

        /// <inheritdoc />
        public async Task<bool> HasPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            Throw.ArgumentException.IfNull(user, "user");

            return await Task.Run(() => user.PasswordHash != null);
        }

        /// <inheritdoc />
        public async Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            ThrowIfDisposed();
            Throw.ArgumentException.IfNull(user, "user");

            await Task.Run(() => user.PasswordHash = passwordHash);
        }

        #endregion

        #region IUserSecurityStampStore

        /// <inheritdoc />
        public async Task<string> GetSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            Throw.ArgumentException.IfNull(user, "user");

            return await Task.Run(() => user.SecurityStamp);
        }

        /// <inheritdoc />
        public async Task SetSecurityStampAsync(TUser user, string stamp)
        {
            ThrowIfDisposed();
            Throw.ArgumentException.IfNull(user, "user");

            await Task.Run(() => user.SecurityStamp = stamp);
        }

        #endregion

        #region IUserEmailStore

        /// <inheritdoc />
        public async Task<TUser> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();
            email = email.ToLowerInvariant().Trim();

            var query = UserMatch()
                .Where((TUser u) => u.Email == email)
                .Return(u => u.As<TUser>());

            return (await query.ResultsAsync).SingleOrDefault();
        }

        /// <inheritdoc />
        public async Task<string> GetEmailAsync(TUser user)
        {
            ThrowIfDisposed();

            if (user.Id == null)
                return user.Email;

            var results = await UserMatch()
                .Where((TUser u) => u.Id == user.Id)
                .Return(u => u.As<TUser>())
                .ResultsAsync;

            var dbUser = results.SingleOrDefault();
            return dbUser?.Email;
        }

        /// <inheritdoc />
        public async Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public async Task SetEmailAsync(TUser user, string email)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public async Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}