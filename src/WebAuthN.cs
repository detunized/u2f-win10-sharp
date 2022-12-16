using System;

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
            return GetAssertion(appId, challenge, origin, crossOrigin, keyHandle, WinApi.GetForegroundWindow());
        }

        public static Assertion GetAssertion(string appId,
                                             string challenge,
                                             string origin,
                                             bool crossOrigin,
                                             string keyHandle,
                                             IntPtr windowHandle)
        {
            var crossOriginLowerCase = crossOrigin ? "true" : "false";
            var clientDataJson = $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":{crossOriginLowerCase}}}";
            var clientDataBytes = clientDataJson.ToBytes();

            var result = WinApi.Sign(version: WinApi.VersionFido2,
                                     appId: appId,
                                     clientData: clientDataBytes,
                                     keyHandle: keyHandle.DecodeBase64UrlSafe(),
                                     windowHandle: windowHandle);

            return new Assertion(clientData: clientDataBytes.ToBaseBase64UrlSafe(),
                                 keyHandle: keyHandle, 
                                 signature: result.Signature.ToBaseBase64UrlSafe(), 
                                 authData: result.AuthData.ToBaseBase64UrlSafe());
        }
    }
}
