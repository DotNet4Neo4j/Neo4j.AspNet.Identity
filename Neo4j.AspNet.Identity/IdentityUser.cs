namespace Neo4j.AspNet.Identity
{
    using System;
    using System.Collections.Generic;
    using Microsoft.AspNet.Identity;
    using Newtonsoft.Json;

    public class IdentityUser : IUser
    {
        public IdentityUser()
        {
            Claims = new List<IdentityUserClaim>();
            Roles = new List<string>();
            Logins = new List<UserLoginInfo>();
            CreateDateUtc = DateTimeOffset.UtcNow;
        }

        public IdentityUser(string username)
            : this()
        {
            UserName = username.ToLowerInvariant().Trim();
        }

        public string DisplayName { get; set; }
        public DateTimeOffset LastLoginDateUtc { get; set; }
        public DateTimeOffset CreateDateUtc { get; set; }
        public string PhoneNumber { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public virtual string PasswordHash { get; set; }
        public virtual string SecurityStamp { get; set; }
        public virtual string Email { get; set; }
        public virtual List<string> Roles { get; set; }

        [JsonIgnore]
        public virtual List<IdentityUserClaim> Claims { get; set; }

        [JsonIgnore]
        public virtual List<UserLoginInfo> Logins { get; set; }

        public virtual string Id { get; set; }
        public virtual string UserName { get; set; }
    }
}