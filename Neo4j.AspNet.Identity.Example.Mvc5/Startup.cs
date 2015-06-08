using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Neo4j.AspNet.Identity.Example.Mvc5.Startup))]
namespace Neo4j.AspNet.Identity.Example.Mvc5
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
