using System;
using System.Security.Claims;

namespace CheesyTot.AspNetCoreIdentity.AzureTables.Helpers
{
    internal static class ClaimKeyHelper
    {
        public static string ToKey(Claim claim)
        {
            return ToKey(claim.Type, claim.Value);
        }

        public static string ToKey(string claimType, string claimValue)
        {
            return $"{claimType}|{claimValue}";
        }

        public static Claim FromKey(string input)
        {
            var parts = input.Split(new[] { "|" }, 2, StringSplitOptions.None);
            return new Claim(parts[0], parts[1]);
        }

        public static string GetClaimTypeFromKey(string input)
        {
            return FromKey(input).Type;
        }

        public static string GetClaimValueFromKey(string input)
        {
            return FromKey(input).Value;
        }
    }
}
