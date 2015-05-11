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
        private bool _disposed;
        private readonly IGraphClient _graphClient;

        public Neo4jUserStore(IGraphClient graphClient)
        {
            _graphClient = graphClient;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        #region IUserLoginStore

        public async Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            Throw.ArgumentException.IfNull(user, "user");
            Throw.ArgumentException.IfNull(login, "login");

            ThrowIfDisposed();

            if (!user.Logins.Any(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey))
                user.Logins.Add(login);
        }

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


        public async Task<TUser> FindAsync(UserLoginInfo login)
        {
            Throw.ArgumentException.IfNull(login, "login");
            ThrowIfDisposed();

            var results = await _graphClient.Cypher
                .Match("(l:" + Labels.Login + ")<-[:" + Relationship.HasLogin + "]-(u:" + Labels.User + ")")
                .Where((UserLoginInfo l) => l.ProviderKey == login.ProviderKey)
                .AndWhere((UserLoginInfo l) => l.LoginProvider == login.LoginProvider)
                .OptionalMatch("(u)-[:"+ Relationship.HasClaim + "]->(c:" + Labels.Claim + ")")
                .Return((u,c,l) => new FindUserResult<TUser>
                {
                    User = u.As<TUser>(),
                    Logins = l.CollectAs<Neo4jUserLoginInfo>(),
                    Claims = c.CollectAs<IdentityUserClaim>()
                }).ResultsAsync;

            var result = results.SingleOrDefault();
            if (result == null)
                return null;
            return result.Combine();
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            Throw.ArgumentException.IfNull(user, "user");
            ThrowIfDisposed();
            return user.Logins as IList<UserLoginInfo>;
        }

        public async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            Throw.ArgumentException.IfNull(user, "user");
            Throw.ArgumentException.IfNull(login, "login");
            ThrowIfDisposed();
            user.Logins.RemoveAll(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey);
        }

        public async Task CreateAsync(TUser user)
        {
            Throw.ArgumentException.IfNull(user, "user");
            Throw.ArgumentException.IfNull(user, "user");
            ThrowIfDisposed();

            user.Id = Guid.NewGuid().ToString();
            await _graphClient.Cypher.Create("(u:User { user })")
                .WithParams(new {user})
                .ExecuteWithoutResultsAsync();
        }

        public async Task DeleteAsync(TUser user)
        {
            Throw.ArgumentException.IfNull(user, "user");
            ThrowIfDisposed();

            await _graphClient.Cypher
                .Match("(u:User)")
                .Where((TUser u) => u.Id == user.Id)
                .OptionalMatch(string.Format("(u)-[lr:{0}]->(l)", Relationship.HasLogin))
                .OptionalMatch(string.Format("(u)-[cr:{0}]->(c)", Relationship.HasClaim))
                .Delete("u,lr,cr,l,c")
                .ExecuteWithoutResultsAsync();
        }

        public async Task<TUser> FindByIdAsync(object userId)
        {
            Throw.ArgumentException.IfNull(userId, "userId");
            return await FindByIdAsync(userId.ToString());
        }

        public async Task<TUser> FindByIdAsync(string userId)
        {
            Throw.ArgumentException.IfNull(userId, "userId");
            ThrowIfDisposed();
            
            var query = new CypherFluentQuery(_graphClient)
                .Match("(u:User)")
                .Where((TUser u) => u.Id == userId)
                .OptionalMatch(string.Format("(u)-[lr:{0}]->(l:{1})", Relationship.HasLogin, Labels.Login))
                .OptionalMatch(string.Format("(u)-[cr:{0}]->(c:{1})", Relationship.HasClaim, Labels.Claim))
                .Return((u, c, l) => new FindUserResult<TUser>
                {
                    User = u.As<TUser>(),
                    Logins = l.CollectAs<Neo4jUserLoginInfo>(),
                    Claims = c.CollectAs<IdentityUserClaim>()
                });

            var user = (await query.ResultsAsync).SingleOrDefault();

            if (user == null)
                return null;

            return user.Combine();
        }

        private class FindUserResult<T> 
            where T : IdentityUser, new()
        {
            public T User { private get; set; } 
            public IEnumerable<Node<Neo4jUserLoginInfo>> Logins { private get; set; }
            public IEnumerable<Node<IdentityUserClaim>> Claims { private get; set; }

            public T Combine()
            {
                var output = User;
                if (Logins != null)
                    output.Logins = new List<UserLoginInfo>(Logins.Select(l => l.Data.ToUserLoginInfo()));
                if (Claims != null)
                    output.Claims = new List<IdentityUserClaim>(Claims.Select(l => l.Data));
                return output;
            }
        }



        public async Task<TUser> FindByNameAsync(string userName)
        {
            Throw.ArgumentException.IfNull(userName, "userName");
            ThrowIfDisposed();

            var query = new CypherFluentQuery(_graphClient)
                .Match("(u:User)")
                .Where((TUser u) => u.UserName == userName)
                .OptionalMatch(string.Format("(u)-[lr:{0}]->(l:{1})", Relationship.HasLogin, Labels.Login))
                .OptionalMatch(string.Format("(u)-[cr:{0}]->(c:{1})", Relationship.HasClaim, Labels.Claim))
                .Return((u, c, l) => new FindUserResult<TUser>
                {
                    User = u.As<TUser>(),
                    Logins = l.CollectAs<Neo4jUserLoginInfo>(),
                    Claims = c.CollectAs<IdentityUserClaim>()
                });

            var results = await query.ResultsAsync;
            var findUserResult = results.SingleOrDefault();
//
//            var user = (await _graphClient.Cypher
//                .Match("(u:User)")
//                .OptionalMatch(string.Format("(u)-[lr:{0}]->(l:{1})", Relationship.HasLogin, Labels.Login))
//                .OptionalMatch(string.Format("(u)-[cr:{0}]->(c:{1})", Relationship.HasClaim, Labels.Claim))
//                .Where((TUser u) => u.UserName == userName)
//                .Return((u, c, l) => new FindUserResult<TUser>
//                {
//                    User = u.As<TUser>(),
//                    Logins = l.CollectAs<Neo4jUserLoginInfo>(),
//                    Claims = c.CollectAs<IdentityUserClaim>()
//                })
//                .ResultsAsync)
//                .SingleOrDefault();

            if (findUserResult == null)
                return null;

            return findUserResult.Combine();
        }

        public async Task UpdateAsync(TUser user)
        {
            Throw.ArgumentException.IfNull(user, "user");
            ThrowIfDisposed();
            
            var query = new CypherFluentQuery(_graphClient)
                .Match("(u:User)")
                .Where((TUser u) => u.Id == user.Id)
                .Set("u = {userParam}")
                .WithParam("userParam", user);

            if (user.Claims != null && user.Claims.Count > 0)
            {
                //CDS: There must be a better way - using proper ForEach mebbe?
                query = query.With("u").OptionalMatch("(u)-[cr:HAS_CLAIM]->(c:Claim)").Delete("c,cr");
                for (int i = 0; i < user.Claims.Count; i++)
                {
                    var claimName = string.Format("claim{0}", i);
                    var claimParam = user.Claims[i];
                    query = query.With("u")
                        .Create("(u)-[:HAS_CLAIM]->(c" + i + ":claim {" + claimName + "})")
                        .WithParam(claimName, claimParam);
                }
            }
            if (user.Logins != null && user.Logins.Count > 0)
            {
                query = query.With("u").OptionalMatch("(u)-[lr:HAS_LOGIN]->(l:Login)").Delete("l,lr");
                for(int i = 0; i< user.Logins.Count; i++)
                {
                    var loginName = string.Format("login{0}", i);
                    var loginParam = user.Logins[i];
                    query = query.With("u")
                        .Create("(u)-[:HAS_LOGIN]->(l" + i +":Login {" + loginName + "})")
                        .WithParam(loginName, loginParam);
                }
            }
//            if (user.Roles != null && user.Roles.Count > 0)
//            {
//                //string -- stored automagically
//            }

            await query.ExecuteWithoutResultsAsync();

        }

        public void Dispose()
        {
            _disposed = true;
        }

        #endregion

        #region IUserClaimStore

        public async Task AddClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            if (!user.Claims.Any(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value))
            {
                user.Claims.Add(new IdentityUserClaim
                {
                    ClaimType = claim.Type,
                    ClaimValue = claim.Value
                });
            }
        }

        public async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            IList<Claim> result = user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
            return result;
        }

        public async Task RemoveClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Claims.RemoveAll(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);
            //CDS: Update DB???
        }

        #endregion

        #region IUserRoleStore

        public async Task AddToRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            if (!user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase))
                user.Roles.Add(roleName);

            //CDS: Update DB???
        }

        public async Task<IList<string>> GetRolesAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return user.Roles;
        }

        public async Task<bool> IsInRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase);
        }

        public async Task RemoveFromRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Roles.RemoveAll(r => String.Equals(r, roleName, StringComparison.InvariantCultureIgnoreCase));

            //CDS: Update DB???
        }

        #endregion

        #region IUserPasswordStore

        public async Task<string> GetPasswordHashAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return user.PasswordHash;
        }

        public async Task<bool> HasPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return user.PasswordHash != null;
        }

        public async Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.PasswordHash = passwordHash;
            //CDS: Update DB???
        }

        #endregion

        #region IUserSecurityStampStore

        public async Task<string> GetSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return user.SecurityStamp;
        }

        public async Task SetSecurityStampAsync(TUser user, string stamp)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.SecurityStamp = stamp;
            //CDS: Surely this needs to be stored in DB?
        }

        #endregion

        #region IUserEmailStore

        public async Task<TUser> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();

            var user = _graphClient.Cypher
                .Match("(u:User)")
                .Where((TUser u) => u.Email == email)
                .Return(u => u.As<TUser>())
                .Results
                .SingleOrDefault();

            //TUser user = db.GetCollection<TUser>(collectionName).FindOne((Query.EQ("email", email)));
            return user;
        }

        public async Task<string> GetEmailAsync(TUser user)
        {
            ThrowIfDisposed();

            var results = await _graphClient.Cypher
                .Match("(u:User)")
                .Where((TUser u) => u.Id == user.Id)
                .Return(u => u.As<TUser>())
                .ResultsAsync;

            var dbUser = results.SingleOrDefault();
            return dbUser == null ? null : dbUser.Email;
        }

        public async Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public async Task SetEmailAsync(TUser user, string email)
        {
            throw new NotImplementedException();
        }

        public async Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            throw new NotImplementedException();
        }

        #endregion

        public async Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
        {
            return DateTimeOffset.UtcNow;
        }

        public async Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
        {
            
        }

        public async Task<int> IncrementAccessFailedCountAsync(TUser user)
        {
            return 0;
        }

        public async Task ResetAccessFailedCountAsync(TUser user)
        {
        }

        public async Task<int> GetAccessFailedCountAsync(TUser user)
        {
            return 0;
        }

        public async Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            return false;
        }

        public async Task SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            return;
        }

        public async Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            
        }

        public async Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            return false;
        }

        public async Task SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            Throw.ArgumentException.IfNull(user, "user");
            Throw.ArgumentException.IfNull(phoneNumber, "phoneNumber");
            ThrowIfDisposed();
            user.PhoneNumber = phoneNumber;
        }

        public async Task<string> GetPhoneNumberAsync(TUser user)
        {
            Throw.ArgumentException.IfNull(user, "user");
            return user.PhoneNumber;
        }

        public async Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
        {
            Throw.ArgumentException.IfNull(user, "user");
            return user.PhoneNumberConfirmed;
        }

        public async Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
        {
            Throw.ArgumentException.IfNull(user, "user");
            user.PhoneNumberConfirmed = confirmed;
        }
    }
}