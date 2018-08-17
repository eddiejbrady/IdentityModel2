// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;

namespace IdentityModel.Internal
{
    internal static class InternalStringExtensions
    {
        [DebuggerStepThrough]
        public static bool IsMissing(this string value)
        {
            return string.IsNullOrWhiteSpace(value);
        }

        [DebuggerStepThrough]
        public static bool IsPresent(this string value)
        {
            return !(value.IsMissing());
        }

        [DebuggerStepThrough]
        public static string EnsureTrailingSlash(this string url)
        {
            return url.RemoveTrailingSlash() + "/";
        }

        [DebuggerStepThrough]
        public static string RemoveTrailingSlash(this string url)
        {
            return url.TrimEnd('/');
        }
    }
}