namespace Neo4j.AspNet.Identity.Tests
{
    using Neo4jClient.Cypher;

    public static class CypherQueryTestingExtensions
    {
        public static bool ContainsParameter(this CypherQuery query, string parameterKey, object parameterValue)
        {
            return query.QueryParameters.ContainsKey(parameterKey) && query.QueryParameters[parameterKey].Equals(parameterValue);
        }
    }
}