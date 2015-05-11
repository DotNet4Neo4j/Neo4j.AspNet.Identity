using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Neo4j.AspNet.Identity
{
    public class IdentityUser : IUser
    {


        public IdentityUser()
        {
            this.Claims = new List<IdentityUserClaim>();
            this.Roles = new List<string>();
            this.Logins = new List<UserLoginInfo>();
        }

        public IdentityUser(string username) :  this()
        {
            this.UserName = username;
        }
        public virtual string Id
        {
            get;
            set;
        }

        public virtual string UserName
        {
            get;
            set;
        }

        public virtual string PasswordHash { get; set; }

        public virtual string SecurityStamp { get; set; }

        public virtual string Email { get; set; }

        public virtual List<string> Roles { get; set; }

        public virtual List<IdentityUserClaim> Claims { get; set; }

        public virtual List<UserLoginInfo> Logins { get; set; }
    }
}
