// Copyright (C) 2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("U2fWin10.Test")]

namespace U2fWin10
{
    public static class U2f
    {
        public static int GetApiVersion()
        {
            return (int)WinApi.WebAuthNGetApiVersionNumber();
        }

        public class Assertion
        {
            public string ClientData { get; }
            public string KeyHandle { get; }
            public string Signature { get; }

            public Assertion(string clientData, string keyHandle, string signature)
            {
                ClientData = clientData;
                KeyHandle = keyHandle;
                Signature = signature;
            }
        }

        public static Assertion GetAssertion(string appId,
                                             string challenge,
                                             string origin,
                                             string keyHandle)
        {
            return GetAssertion(appId, challenge, origin, keyHandle, WinApi.GetForegroundWindow());
        }

        public static Assertion GetAssertion(string appId,
                                             string challenge,
                                             string origin,
                                             string keyHandle,
                                             IntPtr windowHandle)
        {
            var clientDataJson = $"{{\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"typ\":\"navigator.id.getAssertion\"}}";
            var clientDataBytes = clientDataJson.ToBytes();

            var result = WinApi.Sign(version: WinApi.VersionFido2,
                                     appId: appId,
                                     clientData: clientDataBytes,
                                     keyHandle: keyHandle.DecodeBase64UrlSafe(),
                                     windowHandle: windowHandle);

            // Combine the last 5 bytes of the auth data and the signature.
            var signature = new byte[result.Signature.Length + 5];
            Array.Copy(result.AuthData, result.AuthData.Length - 5, signature, 0, 5);
            Array.Copy(result.Signature, 0, signature, 5, result.Signature.Length);

            return new Assertion(clientData: clientDataBytes.ToBaseBase64UrlSafe(),
                                 keyHandle: keyHandle,
                                 signature: result.Signature.ToBaseBase64UrlSafe());
        }
    }
}
