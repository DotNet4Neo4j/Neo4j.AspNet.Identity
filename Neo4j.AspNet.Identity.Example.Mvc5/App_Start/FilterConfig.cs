using System.Web;
using System.Web.Mvc;

namespace Neo4j.AspNet.Identity.Example.Mvc5
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
