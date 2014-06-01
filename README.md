Neo4j.AspNet.Identity
=====================

Custom ASP.NET Identity provider for the Neo4j Graph Database

###### Purpose

ASP.NET MVC 5 shipped with a new Identity system (in the Microsoft.AspNet.Identity.Core package) in order to support both local login and remote logins via OpenID/OAuth, but only ships with an Entity Framework provider (Microsoft.AspNet.Identity.EntityFramework).

###### Features

- Drop-in replacement ASP.NET Identity with Neo4j as the backing store.
- Contains the same IdentityUser class used by the EntityFramework provider in the MVC 5 project template
- Supports additional profile properties on your application's user model.
- Provides UserStore implementation that implements the same interfaces as the EntityFramework version:
  - IUserStore
  - IUserLoginStore
  - IUserRoleStore
  - IUserClaimStore
  - IUserPasswordStore
  - IUserSecurityStampStore
 

###### Instructions

These instructions assume you know how to set up Neo4j within an MVC application.

1. Create a new ASP.NET MVC 5 project, choosing the Individual User Accounts authentication type.
  1.1 Remove the Entity Framework packages and replace with Neo4j Identity:
  1.2 Uninstall-Package Microsoft.AspNet.Identity.EntityFramework
  1.3 Uninstall-Package EntityFramework
  1.4 Install-Package Neo4j.AspNet.Identity

2. In ~/Models/IdentityModels.cs:
  2.1 Remove the namespace: Microsoft.AspNet.Identity.EntityFramework
  2.2 Add the namespace: Neo4j.AspNet.Identity
  2.3 Remove the ApplicationDbContext class completely.
3. In ~/Controllers/AccountController.cs
  3.1 Remove the namespace: Microsoft.AspNet.Identity.EntityFramework
  3.2 Add the connection string name to the constructor of the UserStore. Or empty constructor will use DefaultConnection

        public AccountController()
        {
            this.UserManager = new UserManager<ApplicationUser>(
                new UserStore<ApplicationUser>("http://localhost:7474/db/data" /* or use the Web.config connectionstrings key*/);
        }
        
###### Credits

A special thank to [David Boike](https://github.com/DavidBoike) and [Jonathan Sheely](https://github.com/jsheely) for the inspiration provided with their projects. [RavenDB ASP.NET Identity](https://github.com/ILMServices/RavenDB.AspNet.Identity.) and [MongoDB ASP.NET Identity](https://github.com/InspectorIT/MongoDB.AspNet.Identity) respectively. Much love!
