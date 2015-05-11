namespace Neo4j.AspNet.Identity
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.Owin;
    using Microsoft.Owin;

    public class Neo4jUserManager : UserManager<ApplicationUser>
    {
        public Neo4jUserManager(IUserStore<ApplicationUser> store)
            : base(store)
        {
        }

        public async Task SetLastLogin()
        {
            //            Store.FindByIdAsync()
        }

        public static Neo4jUserManager Create(IdentityFactoryOptions<Neo4jUserManager> options, IOwinContext context)
        {
            var graphClientWrapper = context.Get<GraphClientWrapper>();
            var manager = new Neo4jUserManager(new Neo4jUserStore<ApplicationUser>(graphClientWrapper.GraphClient));

            // Configure validation logic for usernames
            //            manager.UserValidator = new UserValidator<Neo4jUser>(manager)
            //            {
            //                AllowOnlyAlphanumericUserNames = false,
            //                RequireUniqueEmail = true
            //            };

            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true
            };

            // Configure user lockout defaults
            manager.UserLockoutEnabledByDefault = false;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;

            // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            // You can write your own provider and plug it in here.
            //            manager.RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<Neo4jUser>
            //            {
            //                MessageFormat = "Your security code is {0}"
            //            });
            //            manager.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<Neo4jUser>
            //            {
            //                Subject = "Security Code",
            //                BodyFormat = "Your security code is {0}"
            //            });
            //            manager.EmailService = new EmailService();
            //            manager.SmsService = new SmsService();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider =
                    new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }
    }
}