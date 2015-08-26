namespace Neo4j.AspNet.Identity
{
    using Microsoft.AspNet.Identity;

    /// <summary>Consts for the Relationships used throughout Neo4j.</summary>
    public static class Relationship
    {
        /// <summary>Relationship representing whether a user has another Login - HAS_LOGIN</summary>
        public const string HasLogin = "HAS_LOGIN";
        /// <summary>Relationship representing whether a user has a claim - HAS_LOGIN</summary>
        public const string HasClaim = "HAS_CLAIM";
    }

    /// <summary>Consts for the Labels used throughout Neo4j.</summary>
    public static class Labels
    {
        /// <summary>Login label, used by <see cref="UserLoginInfo"/> class.</summary>
        public const string Login = "Login";
        /// <summary>User label, used by <see cref="ApplicationUser"/> class.</summary>
        public const string User = "User";

        /// <summary>Claim label, used by <see cref="IdentityUserClaim"/> class.</summary>
        public const string Claim = "Claim";
    }
}