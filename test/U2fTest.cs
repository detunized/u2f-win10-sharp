using System;
using System.Runtime.InteropServices;
using Xunit;

namespace U2fWin10.Test
{
    public class U2fTest
    {
        [Fact]
        public void Size_of_WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_is_correct()
        {
            var size = Marshal.SizeOf<WinApi.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS>();
            switch (IntPtr.Size)
            {
            case 4:
                Assert.Equal(52, size);
                break;
            case 8:
                Assert.Equal(88, size);
                break;
            }
        }
    }
}
