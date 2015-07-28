namespace Neo4j.AspNet.Identity.Tests
{
    using FluentAssertions;
    using Xunit;

    public class IdentityUserTests
    {
        [Theory]
        [InlineData("A@A.COM", "a@a.com")]
        [InlineData("a@A.com", "a@a.com")]
        [InlineData("a@a.com", "a@a.com")]
        public void IgnoresCaseForUserName(string username, string expectedUsername)
        {
            var user = new IdentityUser(username);
            user.UserName.Should().Be(expectedUsername);
        }
    }
}