using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Neo4j.AspNet.Identity
{
    public class IdentityUserClaim
    {
     
        public virtual string Id { get; set; }
     
        public virtual string UserId { get; set; }
       
        public virtual string ClaimType { get; set; }
      
        public virtual string ClaimValue { get; set; }
    }
}
