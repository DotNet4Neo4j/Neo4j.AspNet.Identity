namespace Neo4j.AspNet.Identity.Tests
{
    using System;
    using FluentAssertions;
    using Xunit;

    public class IdentityUserTests
    {
        public class Constructor
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

            [Theory]
            [InlineData(null)]
            [InlineData("")]
            [InlineData(" ")]
            public void ThrowsArgumentException_WhenUsernameIsNullOrWhitespace(string username)
            {
                var ex = Record.Exception(() => new IdentityUser(username));
                ex.Should().BeOfType<ArgumentException>();
            }
        }

        public class UsernameProperty
        {
            [Theory]
            [InlineData("A@A.COM", "a@a.com")]
            [InlineData("a@A.com", "a@a.com")]
            [InlineData("a@a.com", "a@a.com")]
            public void IgnoresCaseForUserName(string username, string expectedUsername)
            {
                var user = new IdentityUser {UserName = username};
                user.UserName.Should().Be(expectedUsername);
            }

            [Theory]
            [InlineData(null)]
            [InlineData("")]
            [InlineData(" ")]
            public void ThrowsArgumentException_WhenUsernameIsNullOrWhitespace(string username)
            {
                var ex = Record.Exception(() => new IdentityUser {UserName = username});
                ex.Should().BeOfType<ArgumentException>();
            }
        }
    }
}