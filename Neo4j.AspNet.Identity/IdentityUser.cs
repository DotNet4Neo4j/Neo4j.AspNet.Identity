namespace Neo4j.AspNet.Identity
{
    using System;
    using System.CodeDom;
    using System.Collections.Generic;
    using Microsoft.AspNet.Identity;
    using Newtonsoft.Json;

    public class IdentityUser : IUser
    {
        private string _userName;

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
            Throw.ArgumentException.IfNullOrWhiteSpace(username, "username");
            UserName = username.ToLowerInvariant().Trim();
        }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string DisplayName { get; set; }
        public DateTimeOffset LastLoginDateUtc { get; set; }
        public DateTimeOffset CreateDateUtc { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string PhoneNumber { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public virtual string PasswordHash { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public virtual string SecurityStamp { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public virtual string Email { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public virtual List<string> Roles { get; set; }

        [JsonIgnore]
        public virtual List<IdentityUserClaim> Claims { get; set; }

        [JsonIgnore]
        public virtual List<UserLoginInfo> Logins { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public virtual string Id { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public virtual string UserName
        {
            get { return _userName; }
            set
            {
                Throw.ArgumentException.IfNullOrWhiteSpace(value, "value");
                _userName = value.ToLowerInvariant().Trim();
            }
        }
    }
}