#if !NETSTANDARD
using Microsoft.AspNetCore.Authorization;
using ITfoxtec.Identity.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using ITfoxtec.Identity.Models;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Authorization policy builder extensions.
    /// </summary>
    public static class AuthorizationPolicyBuilderExtensions
    {
        /// <summary>
        /// Add scope requirement.
        /// </summary>
        /// <param name="policy">Extending <see cref="AuthorizationPolicyBuilder"/> policy.</param>
        /// <param name="allowedScopes">The list of scope values the scope must match one or more of.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static AuthorizationPolicyBuilder RequireScope(this AuthorizationPolicyBuilder policy, params string[] allowedScopes)
        {
            return RequireScope(policy, (IEnumerable<string>)allowedScopes);

        }

        /// <summary>
        /// Add scope requirement.
        /// </summary>
        /// <param name="policy">Extending <see cref="AuthorizationPolicyBuilder"/> policy.</param>
        /// <param name="allowedScopes">The list of scope values the scope must match one or more of.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static AuthorizationPolicyBuilder RequireScope(this AuthorizationPolicyBuilder policy, IEnumerable<string> allowedScopes)
        {
            if (allowedScopes?.Any() != true)
            {
                throw new ArgumentNullException(nameof(allowedScopes), "The list of scope values is null or empty.");
            }

            policy.Requirements.Add(new ScopeAuthorizationRequirement(allowedScopes));
            return policy;
        }

        /// <summary>
        /// Add scope and roles requirement.
        /// </summary>
        /// <param name="policy">Extending <see cref="AuthorizationPolicyBuilder"/> policy.</param>
        /// <param name="allowedScopeRolesList">The list of scope and roles values. The scope must match one or more of the items in combination with one or more of the user's roles.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static AuthorizationPolicyBuilder RequireScopeAndRoles(this AuthorizationPolicyBuilder policy, params ScopeAndRoles[] allowedScopeRolesList)
        {
            return RequireScopeAndRoles(policy, (IEnumerable<ScopeAndRoles>)allowedScopeRolesList);
        }

        /// <summary>
        /// Add scope and roles requirement.
        /// </summary>
        /// <param name="policy">Extending <see cref="AuthorizationPolicyBuilder"/> policy.</param>
        /// <param name="allowedScopeRolesList">The list of scope and roles values. The scope must match one or more of the items in combination with one or more of the user's roles.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static AuthorizationPolicyBuilder RequireScopeAndRoles(this AuthorizationPolicyBuilder policy, IEnumerable<ScopeAndRoles> allowedScopeRolesList)
        {
            if (allowedScopeRolesList?.Any() != true)
            {
                throw new ArgumentNullException(nameof(allowedScopeRolesList), "The list of scope and roles pairs is null or empty.");
            }

            policy.Requirements.Add(new ScopeAndRolesAuthorizationRequirement(allowedScopeRolesList));
            return policy;
        }
    }
}
#endif