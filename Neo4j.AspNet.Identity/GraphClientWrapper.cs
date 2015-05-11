namespace Neo4j.AspNet.Identity
{
    using System;
    using Neo4jClient;

    /// <summary>A wrapper class to allow the GraphClient to be used within the OWIN framework (must implement <see cref="IDisposable"/>)</summary>
    public class GraphClientWrapper : IDisposable
    {
        public GraphClientWrapper(IGraphClient graphClient)
        {
            GraphClient = graphClient;
        }

        public IGraphClient GraphClient { get; set; }

        public void Dispose()
        {
        }
    }
}