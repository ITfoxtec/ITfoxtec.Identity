using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Infrastructure
{
    /// <summary>
    /// Scope authorization requirement.
    /// </summary>
    public class ScopeAuthorizationRequirement : AuthorizationHandler<ScopeAuthorizationRequirement>, IAuthorizationRequirement
    {
        /// <summary>
        /// Creates a new instance of <see cref="ScopeAuthorizationRequirement"/>.
        /// </summary>
        /// <param name="allowedScopes">The list of scope values the scope must match one or more of.</param>
        public ScopeAuthorizationRequirement(IEnumerable<string> allowedScopes)
        {
            if (allowedScopes?.Any() != true)
            {
                throw new ArgumentNullException(nameof(allowedScopes), "The list of scope values is null or empty.");
            }

            AllowedScopes = allowedScopes;
        }

        /// <summary>
        /// Gets the list of scope values the scope must match one or more of.
        /// </summary>
        public IEnumerable<string> AllowedScopes { get; }

        /// <summary>
        /// Makes a decision if authorization is allowed based on the scopes requirements specified.
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ScopeAuthorizationRequirement requirement)
        {
            if (context.User != null)
            {
                var scopeClaimValue = context.User.Claims.Where(c => string.Equals(c.Type, JwtClaimTypes.Scope, StringComparison.OrdinalIgnoreCase)).Select(c => c.Value).FirstOrDefault();
                if (!scopeClaimValue.IsNullOrWhiteSpace())
                {
                    var scopes = scopeClaimValue.ToSpaceList();
                    foreach (var scope in scopes)
                    {
                        if (requirement.AllowedScopes.Contains(scope, StringComparer.Ordinal))
                        {
                            context.Succeed(requirement);
                            break;
                        }
                    }
                }
            }
            return Task.CompletedTask;
        }
    }
}
