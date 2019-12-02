// Copyright (C) 2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Runtime.InteropServices;

namespace U2fWin10
{
    public static class U2f
    {
        public static byte[] Sign(string appId, byte[] challenge, byte[] keyHandle)
        {
            var result = AuthenticatorGetAssertion(GetForegroundWindow(),
                                                   appId,
                                                   new RawClientData(challenge),
                                                   new RawAuthenticatorGetAssertionOptions(),
                                                   out var assertion);
            return null;
        }

        //
        // Internal
        //

        [DllImport("user32.dll")]
        internal static extern IntPtr GetForegroundWindow();

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNAuthenticatorGetAssertion", CharSet = CharSet.Unicode)]
        internal static extern WebAuthnResult AuthenticatorGetAssertion(
            [In] IntPtr hWnd,
            [In, Optional] string rpId,
            [In] RawClientData rawClientData,
            [In, Optional] RawAuthenticatorGetAssertionOptions rawGetAssertionOptions,
            [Out] out IntPtr rawAssertionPtr);


        internal enum WebAuthnResult : uint
        {
            Ok = 0,
            Canceled = 0x800704C7
        }

        // Information about client data.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal class RawClientData
        {
            // Version of this structure, to allow for modifications in the future.
            // This field is required and should be set to CURRENT_VERSION above.
            private int StructVersion = 1;

            // Size of the pbClientDataJSON field.
            private int ClientDataJSONSize;

            // UTF-8 encoded JSON serialization of the client data.
            [MarshalAs(UnmanagedType.LPArray)]
            private byte[] ClientDataJSON;

            // Hash algorithm ID used to hash the pbClientDataJSON field.
            private string HashAlgId = "SHA-256";

            public RawClientData(byte[] challenge)
            {
                ClientDataJSONSize = challenge.Length;
                ClientDataJSON = challenge;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct RawAuthenticatorGetAssertionOptions
        {
            // TODO: Implement this!
        }
    }
}
