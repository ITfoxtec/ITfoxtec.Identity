using ITfoxtec.Identity.Models;
using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Infrastructure
{
    /// <summary>
    /// Scope and roles authorization requirement.
    /// </summary>
    public class ScopeAndRolesAuthorizationRequirement : AuthorizationHandler<ScopeAndRolesAuthorizationRequirement>, IAuthorizationRequirement
    {
        public ScopeAndRolesAuthorizationRequirement(IEnumerable<ScopeAndRoles> allowedScopeRolesList)
        {
            if (allowedScopeRolesList?.Any() != true)
            {
                throw new ArgumentNullException(nameof(allowedScopeRolesList), "The list of scope and roles pairs is null or empty.");
            }

            AllowedScopeRolesList = allowedScopeRolesList;
        }

        /// <summary>
        /// List of scope and roles pairs. One or more scope and roles links must match.
        /// </summary>
        public IEnumerable<ScopeAndRoles> AllowedScopeRolesList { get; }

        /// <summary>
        /// Makes a decision if authorization is allowed based on the scope and role list requirements specified.
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ScopeAndRolesAuthorizationRequirement requirement)
        {
            if (context.User != null)
            {
                var scopeClaimValue = context.User.Claims.Where(c => string.Equals(c.Type, JwtClaimTypes.Scope, StringComparison.OrdinalIgnoreCase)).Select(c => c.Value).FirstOrDefault();
                if (!scopeClaimValue.IsNullOrWhiteSpace())
                {
                    var scopes = scopeClaimValue.ToSpaceList();
                    foreach (var scope in scopes)
                    {
                        var scopeRoleItem = requirement.AllowedScopeRolesList.Where(sr => scope.Equals(sr.Scope, StringComparison.OrdinalIgnoreCase)).SingleOrDefault();
                        if (scopeRoleItem != null)
                        {
                            if (scopeRoleItem.Roles?.Any() != true)
                            {
                                context.Succeed(requirement);
                                break;
                            }
                            else
                            {
                                if (context.User.Claims.Where(c => string.Equals(c.Type, JwtClaimTypes.Role, StringComparison.OrdinalIgnoreCase) && scopeRoleItem.Roles.Any(r => r.Equals(c.Value, StringComparison.OrdinalIgnoreCase))).Any())
                                {
                                    context.Succeed(requirement);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            return Task.CompletedTask;
        }
    }
}
