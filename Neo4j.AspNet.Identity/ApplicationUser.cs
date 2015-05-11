namespace Neo4j.AspNet.Identity
{
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Identity;

    public class ApplicationUser : IdentityUser
    {
        public static string Labels { get { return "User"; } }
        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(Neo4jUserManager manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }
    }
}