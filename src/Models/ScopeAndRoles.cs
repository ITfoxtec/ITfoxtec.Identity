using System.Collections.Generic;

namespace ITfoxtec.Identity.Models
{
    /// <summary>
    /// Scope and roles authorization model.
    /// </summary>
    public class ScopeAndRoles
    {
        /// <summary>
        /// The scope value to match.
        /// </summary>
        public string Scope { get; set; }

        /// <summary>
        /// The list of role values the user's roles must match one or more of. The user is not required to possess a role if the list is null or empty.
        /// </summary>
        public IEnumerable<string> Roles { get; set; }
    }
}
