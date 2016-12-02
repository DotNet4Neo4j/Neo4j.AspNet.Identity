namespace Neo4j.AspNet.Identity.Tests
{
    using System;
    using System.Threading.Tasks;
    using FluentAssertions;
    using Moq;
    using Neo4jClient;
    using Neo4jClient.Cypher;
    using Xunit;

    public class Neo4jUserStoreTests
    {
        public class Constructor
        {
            [Fact]
            public async Task UserLabelPassedInIsUsed()
            {
                const string newUserLabel = "Foo";
                var mockGraphClient = new Mock<IRawGraphClient>();
                var userStore = new Neo4jUserStore<IdentityUser>(mockGraphClient.Object, newUserLabel);

                await userStore.FindByEmailAsync("n.e@email.com");
                mockGraphClient.Verify(gc => gc.ExecuteGetCypherResultsAsync<IdentityUser>(It.Is<CypherQuery>(actual => actual.DebugQueryText.Contains("(u:Foo)"))), Times.Once);
            }

            [Theory]
            [InlineData("")]
            [InlineData(" ")]
            [InlineData(null)]
            public async Task DefaultLabelUsedIfPassedInIsNullOrWhiteSpace(string label)
            {
                var mockGraphClient = new Mock<IRawGraphClient>();
                var userStore = new Neo4jUserStore<IdentityUser>(mockGraphClient.Object, label);

                await userStore.FindByEmailAsync("n.e@email.com");
                mockGraphClient.Verify(gc => gc.ExecuteGetCypherResultsAsync<IdentityUser>(It.Is<CypherQuery>(actual => actual.DebugQueryText.Contains("(u:User)"))), Times.Once);
            }
        }

        public class FindByEmailAsyncMethod
        {
            [Theory]
            [InlineData("A@A.COM", "a@a.com")]
            [InlineData("A@a.com", "a@a.com")]
            [InlineData("a@a.com", "a@a.com")]
            public async Task LooksForEmailIgnoringCase(string email, string expectedEmail)
            {
                var mockGraphClient = new Mock<IRawGraphClient>();
                var userStore = new Neo4jUserStore<IdentityUser>(mockGraphClient.Object);

                await userStore.FindByEmailAsync(email);
                
                mockGraphClient.Verify(gc => gc.ExecuteGetCypherResultsAsync<IdentityUser>(It.Is<CypherQuery>(actual => actual.ContainsParameter("p0", expectedEmail))), Times.Once);
            }

            [Theory]
            [InlineData(" a@a.com", "a@a.com")]
            [InlineData("a@a.com ", "a@a.com")]
            [InlineData(" a@a.com ", "a@a.com")]
            public async Task TrimsEmailAskedFor(string email, string expectedEmail)
            {
                var mockGraphClient = new Mock<IRawGraphClient>();
                var userStore = new Neo4jUserStore<IdentityUser>(mockGraphClient.Object);

                await userStore.FindByEmailAsync(email);

                mockGraphClient.Verify(gc => gc.ExecuteGetCypherResultsAsync<IdentityUser>(It.Is<CypherQuery>(actual => actual.ContainsParameter("p0", expectedEmail))), Times.Once);
            }
        }

        private static Mock<IRawGraphClient> MockGraphClient => new Mock<IRawGraphClient>();
        private static IGraphClient GraphClient => MockGraphClient.Object;

        public class FindByNameAsyncMethod
        {
            [Theory]
            [InlineData(null)]
            [InlineData("")]
            [InlineData(" ")]
            public async Task ThrowsArgumentException_WhenUsernameIsNullOrWhitespace(string username)
            {
                var userStore = new Neo4jUserStore<IdentityUser>(GraphClient);
                var ex = await Record.ExceptionAsync(() => userStore.FindByNameAsync(username));
                ex.Should().BeOfType<ArgumentException>();
            }

            [Theory]
            [InlineData("A@A.COM", "a@a.com")]
            [InlineData("A@a.com", "a@a.com")]
            [InlineData("a@a.com", "a@a.com")]
            public async Task LooksForUsernameIgnoringCase(string username, string expectedUsername)
            {
                var mockGraphClient = new Mock<IRawGraphClient>();
                var userStore = new Neo4jUserStore<IdentityUser>(mockGraphClient.Object);

                await userStore.FindByNameAsync(username);

                mockGraphClient.Verify(gc => gc.ExecuteGetCypherResultsAsync<Neo4jUserStore<IdentityUser>.FindUserResult<IdentityUser>>(It.Is<CypherQuery>(actual => actual.ContainsParameter("p0", expectedUsername))), Times.Once);
            }

            [Theory]
            [InlineData(" a@a.com", "a@a.com")]
            [InlineData("a@a.com ", "a@a.com")]
            [InlineData(" a@a.com ", "a@a.com")]
            public async Task TrimsUsernameAskedFor(string username, string expectedUsername)
            {
                var mockGraphClient = new Mock<IRawGraphClient>();
                var userStore = new Neo4jUserStore<IdentityUser>(mockGraphClient.Object);

                await userStore.FindByNameAsync(username);

                mockGraphClient.Verify(gc => gc.ExecuteGetCypherResultsAsync<Neo4jUserStore<IdentityUser>.FindUserResult<IdentityUser>>(It.Is<CypherQuery>(actual => actual.ContainsParameter("p0", expectedUsername))), Times.Once);
            }
        }
    }
}