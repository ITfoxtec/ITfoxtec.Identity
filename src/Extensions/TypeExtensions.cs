using System;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for Type.
    /// </summary>
    public static class TypeExtensions
    {
        /// <summary>
        /// Get type name.
        /// </summary>
        public static string GetTypeName(this object obj)
        {
            return obj.GetType().Name;
        }
    }
}
