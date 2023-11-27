using System;
using System.Runtime.InteropServices;
using System.Text;

namespace U2fWin10
{
    internal static class Utils
    {
        public static byte[] ToBytes(this string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        public static byte[] DecodeBase64UrlSafe(this string encoded)
        {
            var regularBase64 = encoded
                .Replace('-', '+')
                .Replace('_', '/')
                .TrimEnd('=');

            switch (regularBase64.Length % 4)
            {
                case 2:
                    regularBase64 += "==";
                    break;
                case 3:
                    regularBase64 += "=";
                    break;
            }

            return Convert.FromBase64String(regularBase64);
        }

        public static string ToBaseBase64UrlSafe(this byte[] raw)
        {
            return Convert.ToBase64String(raw)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }

        public static void ThrowIfNotOnWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return;

            throw new NotSupportedException("This platform is not supported");
        }
    }
}
