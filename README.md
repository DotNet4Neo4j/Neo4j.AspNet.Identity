Neo4j.AspNet.Identity
=====================

Custom ASP.NET Identity provider for the Neo4j Graph Database

## Purpose

ASP.NET MVC 5 shipped with a new Identity system (in the Microsoft.AspNet.Identity.Core package) in order to support both local login and remote logins via OpenID/OAuth, but only ships with an Entity Framework provider (Microsoft.AspNet.Identity.EntityFramework).

### Current Builds

[![Neo4j.AspNet.Identity Version Number](https://img.shields.io/nuget/v/Neo4j.AspNet.Identity.svg)](https://www.nuget.org/packages/Neo4j.AspNet.Identity/)
[![cskardon MyGet Build Status](https://www.myget.org/BuildSource/Badge/cskardon?identifier=2ee7d34b-7177-47c2-abd4-ec9ec179b926)](https://www.myget.org/)

### Features

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
 

### Instructions

These instructions assume you know how to set up Neo4j within an MVC application.

#### Using 

1. Create a new ASP.NET MVC 5 project, choosing the Individual User Accounts authentication type.
    1. Update all Nuget packages to latest versions (in particular 'Microsoft ASP.NET Identity Core')
    2. Install-Package Neo4j.Aspnet.Identity
    3. Remove the Entity Framework packages and replace with Neo4j Identity:
        1. Uninstall-Package Microsoft.AspNet.Identity.EntityFramework
        2. Uninstall-Package EntityFramework

2. Delete ~/Models/IdentityModels.cs
3. In ~/App_Start/IndentityConfig.cs
    1. Change the 'ApplicationUserManager' to use the Neo4jUserStore (as below)
    2. Change the 'ApplicationUserManager' to get the GraphClient from Owin (as below)

    `var manager = new ApplicationUserManager(new Neo4jUserStore<ApplicationUser>(context.Get<GraphClientWrapper>().GraphClient));`

4. In ~/App_Start/Startup.Auth.cs
    1. Add 'using Neo4j.AspNet.Identity'
    2. Add the following Method:

    ```
    private void ConfigureNeo4j(IAppBuilder app)
    {
        app.CreatePerOwinContext(() => {
            var gc = new GraphClient(new Uri("http://localhost.:7474/db/data"));
            gc.Connect();
            var gcw = new GraphClientWrapper(gc);
            return gcw;
        });
    }
    ```

    3. Replace the line about creating the ApplicationDbContext (app.CreatePerOwinContext(ApplicationDbContext.Create);) with:

    `ConfigureNeo4j(app);`

5. In ~/Controllers/AccountController.cs
    1. Remove the namespace: Microsoft.AspNet.Identity.EntityFramework
    2. Add the namespace: using Neo4j.AspNet.Identity


###### Credits

A special thank you to [David Boike](https://github.com/DavidBoike) and [Jonathan Sheely](https://github.com/jsheely) for the inspiration provided with their projects. [RavenDB ASP.NET Identity](https://github.com/ILMServices/RavenDB.AspNet.Identity.) and [MongoDB ASP.NET Identity](https://github.com/InspectorIT/MongoDB.AspNet.Identity) respectively. 

A big thank you to [Antonio Sergio Simoes](https://github.com/assimoes), for starting this whole thing up :)
