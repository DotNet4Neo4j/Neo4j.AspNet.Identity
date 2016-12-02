namespace Neo4j.AspNet.Identity
{
    using System;
    using Neo4jClient;

    /// <summary>A wrapper class to allow the GraphClient to be used within the OWIN framework (must implement <see cref="IDisposable"/>)</summary>
    public class GraphClientWrapper : IDisposable
    {
        /// <summary>
        /// Construct a new GraphClientWrapper instance
        /// </summary>
        /// <param name="graphClient">The <see cref="IGraphClient"/> instance to wrap.</param>
        public GraphClientWrapper(IGraphClient graphClient)
        {
            GraphClient = graphClient;
        }

        /// <summary>
        /// Gets the <see cref="IGraphClient"/> instance.
        /// </summary>
        public IGraphClient GraphClient { get; set; }

        /// <inheritdoc />
        public void Dispose()
        {
        }
    }
}