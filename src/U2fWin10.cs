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
            var challengePtr = CopyToUnmanaged(challenge);
            var keyHandlePtr = CopyToUnmanaged(keyHandle);
            var credentialPtr = CopyToUnmanaged(new WEBAUTHN_CREDENTIAL { cbId = keyHandle.Length, pbId = keyHandlePtr });

            // TODO: Remove
            var size = Marshal.SizeOf<WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS>();
            if (size != 88)
                throw new InvalidOperationException();

            var result = WebAuthNAuthenticatorGetAssertion(GetForegroundWindow(),
                                                   appId,
                                                   new WEBAUTHN_CLIENT_DATA() { cbClientDataJSON = challenge.Length, pbClientDataJSON = challengePtr } ,
                                                   new WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS()
                                                   {
                                                       CredentialList = new WEBAUTHN_CREDENTIALS
                                                       {
                                                           cCredentials = 1,
                                                           pCredentials = credentialPtr,
                                                       }
                                                   },
                                                   out var assertion);

            Marshal.FreeHGlobal(credentialPtr);
            Marshal.FreeHGlobal(keyHandlePtr);
            Marshal.FreeHGlobal(challengePtr);
            Marshal.FreeHGlobal(assertion);

            return null;
        }

        private static IntPtr CopyToUnmanaged(byte[] src)
        {
            var ptr = Marshal.AllocHGlobal(src.Length);
            Marshal.Copy(src, 0, ptr, src.Length);
            return ptr;
        }

        private static IntPtr CopyToUnmanaged<T>(T src)
        {
            var ptr = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
            Marshal.StructureToPtr(src, ptr, false);
            return ptr;
        }

        //
        // Internal
        //

        [DllImport("user32.dll")]
        internal static extern IntPtr GetForegroundWindow();

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNAuthenticatorGetAssertion", CharSet = CharSet.Unicode)]
        internal static extern WebAuthnResult WebAuthNAuthenticatorGetAssertion(
            [In] IntPtr hWnd,
            [In, Optional] string rpId,
            [In] WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
            [In, Optional] WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pWebAuthNGetAssertionOptions,
            [Out] out IntPtr ppWebAuthNAssertion);

        internal enum WebAuthnResult : uint
        {
            Ok = 0,
            Canceled = 0x800704C7
        }

        // Information about client data.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal class WEBAUTHN_CLIENT_DATA
        {
            // Version of this structure, to allow for modifications in the future.
            // This field is required and should be set to CURRENT_VERSION above.
            public readonly /* DWORD */ int dwVersion = 1;

            // Size of the pbClientDataJSON field.
            public /* DWORD */ int cbClientDataJSON;

            // UTF-8 encoded JSON serialization of the client data.
            public /* PBYTE */ IntPtr pbClientDataJSON;

            // Hash algorithm ID used to hash the pbClientDataJSON field.
            public readonly /* LPCWSTR */ string pwszHashAlgId = "SHA-256";
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal class WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
        {
            // Version of this structure, to allow for modifications in the future.
            public /* DWORD */ int dwVersion = 4; // WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2

            // Time that the operation is expected to complete within.
            // This is used as guidance, and can be overridden by the platform.
            public /* DWORD */ int dwTimeoutMilliseconds = 30_000; // 30 seconds

            // Allowed Credentials List.
            public /* WEBAUTHN_CREDENTIALS */ WEBAUTHN_CREDENTIALS CredentialList;

            // Optional extensions to parse when performing the operation.
            public /* WEBAUTHN_EXTENSIONS */ WEBAUTHN_EXTENSIONS Extensions = new WEBAUTHN_EXTENSIONS { cExtensions = 0, pExtensions = IntPtr.Zero };

            // Optional. Platform vs Cross-Platform Authenticators.
            public /* DWORD */ int dwAuthenticatorAttachment = 3; // WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2

            // User Verification Requirement.
            public /* DWORD */ int dwUserVerificationRequirement = 3; // WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED

            // Reserved for future Use
            public /* DWORD */ int dwFlags = 0;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_2
            //

            // Optional identifier for the U2F AppId. Converted to UTF8 before being hashed. Not lower cased.
            public /* PCWSTR */ string pwszU2fAppId = null; // Not used in U2F

            // If the following is non-NULL, then, set to TRUE if the above pwszU2fAppid was used instead of
            // PCWSTR pwszRpId;
            public /* BOOL* */ IntPtr pbU2fAppId = IntPtr.Zero; // Not used in U2F

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3
            //

            // Cancellation Id - Optional - See WebAuthNGetCancellationId
            public /* GUID* */ IntPtr pCancellationId = IntPtr.Zero; // Not used in U2F

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4
            //

            // Allow Credential List. If present, "CredentialList" will be ignored.
            public /* PWEBAUTHN_CREDENTIAL_LIST */ IntPtr pAllowCredentialList = IntPtr.Zero; // Not used in U2F
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal class WEBAUTHN_CREDENTIAL
    {
        // Version of this structure, to allow for modifications in the future.
        public /* DWORD */ int dwVersion = 1;

        // Size of pbID.
        public /* DWORD */ int cbId;

        // Unique ID for this particular credential.
        public /* PBYTE */ IntPtr pbId;

        // Well-known credential type specifying what this particular credential is.
        public /* LPCWSTR */ string pwszCredentialType = "public-key";
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_CREDENTIALS
    {
        public /* DWORD */ int cCredentials;
        public /* PWEBAUTHN_CREDENTIAL */ IntPtr pCredentials;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_EXTENSIONS
    {
        public /* DWORD */ int cExtensions;
        public /* PWEBAUTHN_EXTENSION */ IntPtr pExtensions;
    }
}
