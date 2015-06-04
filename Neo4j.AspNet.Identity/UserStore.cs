using Microsoft.AspNet.Identity;
using Neo4jClient;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Neo4j.AspNet.Identity
{
    [Obsolete("Please switch to using the Neo4j.AspNet.Identity.Neo4jUserStore class instead", true)]
    public class UserStore<TUser> : IUserLoginStore<TUser>, IUserClaimStore<TUser>, IUserRoleStore<TUser>,
        IUserPasswordStore<TUser>, IUserSecurityStampStore<TUser>, IUserStore<TUser>, IUserEmailStore<TUser>
        where TUser : IdentityUser
    {
        private readonly GraphClient db;
        private bool _disposed;

        private GraphClient GetGraphDatabaseFromUri(string serverUriOrName)
        {
            if (serverUriOrName.ToLower().Contains("http://"))
            {
                return new GraphClient(new Uri(serverUriOrName));
            }
            else
            {
                return new GraphClient(new Uri(ConfigurationManager.ConnectionStrings[serverUriOrName].ConnectionString));
            }
        }

        public UserStore()
            :this("DefaultConnection")
        {

        }

        public UserStore(string connectionNameOrUri)
        {
            db = GetGraphDatabaseFromUri(connectionNameOrUri);
            db.Connect();
        }

        public UserStore(GraphClient neoDb)
        {
            db = neoDb;
        }

        #region IUserLoginStore

        public Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            if (!user.Logins.Any(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey))
            {
                user.Logins.Add(login);
            }

            return Task.FromResult(true);
        }

        public Task<TUser> FindAsync(UserLoginInfo login)
        {
            throw new NotImplementedException();
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.Logins as IList<UserLoginInfo>);
        }

        public Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Logins.RemoveAll(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey);

            return Task.FromResult(0);
        }

        public Task CreateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Id = Guid.NewGuid().ToString();
            //db.GetCollection<TUser>(collectionName).Insert(user);

            db.Cypher.Create("(u:User { user })")
                                      .WithParams(new { user })
                                      .ExecuteWithoutResults();



            return Task.FromResult(user);
        }

        public Task DeleteAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task<TUser> FindByIdAsync(string userId)
        {
            ThrowIfDisposed();

            TUser user = db.Cypher
                      .Match("(u:User)")
                      .Where((TUser u) => u.Id == userId)
                      .Return(u => u.As<TUser>())
                      .Results
                      .SingleOrDefault();

            //   TUser user = db.GetCollection<TUser>(collectionName).FindOne((Query.EQ("_id", ObjectId.Parse(userId))));
            return Task.FromResult(user);
        }

        public Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();

            TUser user = db.Cypher
                        .Match("(u:User)")
                        .Where((TUser u) => u.UserName == userName)
                        .Return(u => u.As<TUser>())
                        .Results
                        .SingleOrDefault();


            // TUser user = db.GetCollection<TUser>(collectionName).FindOne((Query.EQ("UserName", userName)));
            return Task.FromResult(user);
        }

        public Task UpdateAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            _disposed = true;
        } 
        #endregion

        #region IUserClaimStore

        public Task AddClaimAsync(TUser user, System.Security.Claims.Claim claim)
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


            return Task.FromResult(0);
        }

        public Task<IList<System.Security.Claims.Claim>> GetClaimsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            IList<Claim> result = user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
            return Task.FromResult(result);
        }

        public Task RemoveClaimAsync(TUser user, System.Security.Claims.Claim claim)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Claims.RemoveAll(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);
            return Task.FromResult(0);
        } 
        #endregion

        #region IUserRoleStore
        public Task AddToRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            if (!user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase))
                user.Roles.Add(roleName);

            return Task.FromResult(true);
        }

        public Task<IList<string>> GetRolesAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult<IList<string>>(user.Roles);
        }

        public Task<bool> IsInRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase));
        }

        public Task RemoveFromRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Roles.RemoveAll(r => String.Equals(r, roleName, StringComparison.InvariantCultureIgnoreCase));

            return Task.FromResult(0);
        } 
        #endregion

        #region IUserPasswordStore
        public Task<string> GetPasswordHashAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.PasswordHash != null);
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        } 
        #endregion

        #region IUserSecurityStampStore
        public Task<string> GetSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.SecurityStamp);
        }

        public Task SetSecurityStampAsync(TUser user, string stamp)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        } 
        #endregion

        #region IUserEmailStore
        public Task<TUser> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();

            TUser user = db.Cypher
                      .Match("(u:User)")
                      .Where((TUser u) => u.Email == email)
                      .Return(u => u.As<TUser>())
                      .Results
                      .SingleOrDefault();

            //TUser user = db.GetCollection<TUser>(collectionName).FindOne((Query.EQ("email", email)));
            return Task.FromResult(user);
        }

        public Task<string> GetEmailAsync(TUser user)
        {
            ThrowIfDisposed();

            string email = db.Cypher
                      .Match("(u:User)")
                      .Where((TUser u) => u.Id == user.Id)
                      .Return(u => u.As<TUser>())
                      .Results
                      .SingleOrDefault()
                      .Email;

            //TUser user = db.GetCollection<TUser>(collectionName).FindOne((Query.EQ("email", email)));

            return Task.FromResult<string>(email);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetEmailAsync(TUser user, string email)
        {
            throw new NotImplementedException();
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            throw new NotImplementedException();
        } 
        #endregion

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }
    }

}
