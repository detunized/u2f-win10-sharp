using System;
using System.Linq;

namespace U2fWin10
{
    public static class WebAuthN
    {
        public class Assertion
        {
            public string ClientData { get; }
            public string KeyHandle { get; }
            public string Signature { get; }
            public string AuthData { get; }

            public Assertion(string clientData, string keyHandle, string signature, string authData)
            {
                ClientData = clientData;
                KeyHandle = keyHandle;
                Signature = signature;
                AuthData = authData;
            }
        }

        public static Assertion GetAssertion(string appId,
                                             string challenge,
                                             string origin,
                                             bool crossOrigin,
                                             string keyHandle)
        {
            return GetAssertion(appId, challenge, origin, crossOrigin, new[] { keyHandle });
        }

        public static Assertion GetAssertion(string appId,
                                             string challenge,
                                             string origin,
                                             bool crossOrigin,
                                             string[] keyHandles)
        {
            return GetAssertion(appId, challenge, origin, crossOrigin, keyHandles, WinApi.GetForegroundWindow());
        }

        public static Assertion GetAssertion(string appId,
                                             string challenge,
                                             string origin,
                                             bool crossOrigin,
                                             string keyHandle,
                                             IntPtr windowHandle)
        {
            return GetAssertion(appId, challenge, origin, crossOrigin, new[] { keyHandle }, windowHandle);
        }

        public static Assertion GetAssertion(string appId,
                                             string challenge,
                                             string origin,
                                             bool crossOrigin,
                                             string[] keyHandles,
                                             IntPtr windowHandle)
        {
            Utils.ThrowIfNotOnWindows();

            var crossOriginLowerCase = crossOrigin ? "true" : "false";
            var clientDataJson = $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":{crossOriginLowerCase}}}";
            var clientDataBytes = clientDataJson.ToBytes();

            var result = WinApi.Sign(version: WinApi.VersionFido2,
                                     appId: appId,
                                     clientData: clientDataBytes,
                                     keyHandles: keyHandles.Select(x => x.DecodeBase64UrlSafe()).ToArray(),
                                     windowHandle: windowHandle);

            return new Assertion(clientData: clientDataBytes.ToBaseBase64UrlSafe(),
                                 keyHandle: result.keyHandle.ToBaseBase64UrlSafe(),
                                 signature: result.Signature.ToBaseBase64UrlSafe(),
                                 authData: result.AuthData.ToBaseBase64UrlSafe());
        }
    }
}
