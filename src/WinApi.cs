using System;
using System.Runtime.InteropServices;

namespace U2fWin10
{
    internal static class WinApi
    {
        public static (byte[] Signature, byte[] AuthData) Sign(int version, string appId, byte[] clientData, byte[] keyHandle, IntPtr windowHandle)
        {
            // It's all a bit ugly here with the unmanaged memory management.
            // It's easier to allocate all at the top and then free when we're
            // done instead of having each data structure manage its own memory.
            // Some objects exist only in the managed heap, some entirely in the
            // unmanaged and some have parts in both. This makes it very
            // difficult to track nested structures with IntPtr's in them that
            // have to be freed.

            var clientDataPtr = CopyToUnmanaged(clientData);
            var keyHandlePtr = CopyToUnmanaged(keyHandle);
            var credentialPtr = CopyToUnmanaged(new WEBAUTHN_CREDENTIAL(keyHandle.Length, keyHandlePtr));
            var assertionPtr = IntPtr.Zero;

            try
            {
                var result = WebAuthNAuthenticatorGetAssertion(
                    windowHandle,
                    appId,
                    new WEBAUTHN_CLIENT_DATA(version, clientData.Length, clientDataPtr),
                    new WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS(1, credentialPtr),
                    out assertionPtr);

                if (result == WebAuthnResult.Canceled)
                    throw new CanceledException();

                if (result != WebAuthnResult.Ok)
                    throw new ErrorException($"Error code: ${result}");

                var assertion = Marshal.PtrToStructure<WEBAUTHN_ASSERTION>(assertionPtr);

                var signature = new byte[assertion.cbSignature];
                Marshal.Copy(assertion.pbSignature, signature, 0, assertion.cbSignature);

                var authData = new byte[assertion.cbAuthenticatorData];
                Marshal.Copy(assertion.pbAuthenticatorData, authData, 0, assertion.cbAuthenticatorData);

                return (signature, authData);
            }
            finally
            {
                if (assertionPtr != IntPtr.Zero)
                    WebAuthNFreeAssertion(assertionPtr);

                FreeUnmanaged(ref credentialPtr);
                FreeUnmanaged(ref keyHandlePtr);
                FreeUnmanaged(ref clientDataPtr);
            }
        }

        //
        // Internal
        //

        internal static IntPtr CopyToUnmanaged(byte[] src)
        {
            var ptr = Marshal.AllocHGlobal(src.Length);
            Marshal.Copy(src, 0, ptr, src.Length);
            return ptr;
        }

        internal static IntPtr CopyToUnmanaged<T>(T src)
        {
            var ptr = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
            Marshal.StructureToPtr(src, ptr, false);
            return ptr;
        }

        internal static void FreeUnmanaged(ref IntPtr ptr)
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(ptr);
                ptr = IntPtr.Zero;
            }
        }

        //
        // Windows API P/Invoke
        //

        [DllImport("user32.dll")]
        internal static extern IntPtr GetForegroundWindow();

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNGetApiVersionNumber")]
        internal static extern uint WebAuthNGetApiVersionNumber();

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNAuthenticatorGetAssertion", CharSet = CharSet.Unicode)]
        internal static extern WebAuthnResult WebAuthNAuthenticatorGetAssertion(
            [In] IntPtr hWnd,
            [In, Optional] string rpId,
            [In] WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
            [In, Optional] WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS pWebAuthNGetAssertionOptions,
            [Out] out IntPtr ppWebAuthNAssertion);

        [DllImport("webauthn.dll", EntryPoint = "WebAuthNFreeAssertion", CharSet = CharSet.Unicode)]
        internal static extern void WebAuthNFreeAssertion([In] IntPtr pWebAuthNAssertion);

        internal enum WebAuthnResult : uint
        {
            Ok = 0,
            Canceled = 0x800704C7
        }

        internal const int VersionU2F = 1;
        internal const int VersionFido2 = 2;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal sealed class WEBAUTHN_CLIENT_DATA
        {
            // Version of this structure, to allow for modifications in the future.
            // This field is required and should be set to CURRENT_VERSION above.
            private /* DWORD */ int dwVersion;

            // Size of the pbClientDataJSON field.
            private /* DWORD */ int cbClientDataJSON;

            // UTF-8 encoded JSON serialization of the client data.
            private /* PBYTE */ IntPtr pbClientDataJSON;

            // Hash algorithm ID used to hash the pbClientDataJSON field.
            private /* LPCWSTR */ string pwszHashAlgId = "SHA-256";

            public WEBAUTHN_CLIENT_DATA(int version, int length, IntPtr ptr)
            {
                dwVersion = version;
                cbClientDataJSON = length;
                pbClientDataJSON = ptr;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal sealed class WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
        {
            // Version of this structure, to allow for modifications in the future.
            private /* DWORD */ int dwVersion = 4; // WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2

            // Time that the operation is expected to complete within.
            // This is used as guidance, and can be overridden by the platform.
            private /* DWORD */ int dwTimeoutMilliseconds = 30_000; // 30 seconds

            // Allowed Credentials List.
            private /* WEBAUTHN_CREDENTIALS */ WEBAUTHN_CREDENTIALS CredentialList;

            // Optional extensions to parse when performing the operation.
            private /* WEBAUTHN_EXTENSIONS */ WEBAUTHN_EXTENSIONS Extensions = new WEBAUTHN_EXTENSIONS();

            // Optional. Platform vs Cross-Platform Authenticators.
            private /* DWORD */ int dwAuthenticatorAttachment = 3; // WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2

            // User Verification Requirement.
            private /* DWORD */ int dwUserVerificationRequirement = 3; // WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED

            // Reserved for future Use
            private /* DWORD */ int dwFlags = 0;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_2
            //

            // Optional identifier for the U2F AppId. Converted to UTF8 before being hashed. Not lower cased.
            private /* PCWSTR */ string pwszU2fAppId = null; // Not used in U2F

            // If the following is non-NULL, then, set to TRUE if the above pwszU2fAppid was used instead of
            // PCWSTR pwszRpId;
            private /* BOOL* */ IntPtr pbU2fAppId = IntPtr.Zero; // Not used in U2F

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3
            //

            // Cancellation Id - Optional - See WebAuthNGetCancellationId
            private /* GUID* */ IntPtr pCancellationId = IntPtr.Zero; // Not used in U2F

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4
            //

            // Allow Credential List. If present, "CredentialList" will be ignored.
            private /* PWEBAUTHN_CREDENTIAL_LIST */ IntPtr pAllowCredentialList = IntPtr.Zero; // Not used in U2F

            public WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS(int numCredentials, IntPtr unmanagedCredentialsBlob)
            {
                CredentialList = new WEBAUTHN_CREDENTIALS(numCredentials, unmanagedCredentialsBlob);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal class WEBAUTHN_CREDENTIALS
        {
            private /* DWORD */ int cCredentials;
            private /* PWEBAUTHN_CREDENTIAL */ IntPtr pCredentials;

            public WEBAUTHN_CREDENTIALS(int numCredentials, IntPtr unmanagedCredentialsBlob)
            {
                cCredentials = numCredentials;
                pCredentials = unmanagedCredentialsBlob;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal class WEBAUTHN_CREDENTIAL
        {
            // Version of this structure, to allow for modifications in the future.
            private /* DWORD */ int dwVersion = 1;

            // Size of pbID.
            private /* DWORD */ int cbId;

            // Unique ID for this particular credential.
            private /* PBYTE */ IntPtr pbId;

            // Well-known credential type specifying what this particular credential is.
            private /* LPCWSTR */ string pwszCredentialType = "public-key";

            public WEBAUTHN_CREDENTIAL(int numBytes, IntPtr unmangedBytes)
            {
                cbId = numBytes;
                pbId = unmangedBytes;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal class WEBAUTHN_EXTENSIONS
        {
            private /* DWORD */ int cExtensions = 0;
            private /* PWEBAUTHN_EXTENSION */ IntPtr pExtensions = IntPtr.Zero;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal class WEBAUTHN_ASSERTION
        {
            // Version of this structure, to allow for modifications in the future.
            public /* DWORD */ int dwVersion;

            // Size of cbAuthenticatorData.
            public /* DWORD */ int cbAuthenticatorData;

            // Authenticator data that was created for this assertion.
            public /* PBYTE */ IntPtr pbAuthenticatorData;

            // Size of pbSignature.
            public /* DWORD */ int cbSignature;

            // Signature that was generated for this assertion.
            public /* PBYTE */ IntPtr pbSignature;

            // Credential that was used for this assertion.
            public /* WEBAUTHN_CREDENTIAL */ WEBAUTHN_CREDENTIAL Credential;

            // Size of User Id
            public /* DWORD */ int cbUserId;

            // UserId
            public /* PBYTE */ IntPtr pbUserId;
        }
    }
}
