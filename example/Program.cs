// Copyright (C) 2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using U2fWin10;

namespace Example
{
    internal static class Program
    {
        public static void Main(string[] args)
        {
            var apiVersion = U2f.GetApiVersion();
            Console.WriteLine($"API version: {apiVersion}");

            try
            {
                var r1 = U2f.GetAssertion(appId: "https://snappy.local/app-id.json",
                                          challenge: "zImw3II_G5JKACzFB4I1FLFTmo2lmEs4Jg2gOP2dYNk",
                                          origin: "https://snappy.local",
                                          keyHandles: new[]
                                          {
                                              // Invalid key
                                              "lizejqv8eHXSToeUEbxLzT65XIvIKY5YJdzSKGhvtP7SHDo_o4IXuEuGdajO172g1pXE2DZ-veI5_mmVCiZp4Q",
                                              // Correct key
                                              "mizejqv8eHXSToeUEbxLzT65XIvIKY5YJdzSKGhvtP7SHDo_o4IXuEuGdajO172g1pXE2DZ-veI5_mmVCiZp4Q",
                                              // Invalid key
                                              "nizejqv8eHXSToeUEbxLzT65XIvIKY5YJdzSKGhvtP7SHDo_o4IXuEuGdajO172g1pXE2DZ-veI5_mmVCiZp4Q",
                                          });

                Console.WriteLine("U2F");
                Console.WriteLine($"ClientData: {r1.ClientData}");
                Console.WriteLine($"KeyHandle: {r1.KeyHandle}");
                Console.WriteLine($"Signature: {r1.Signature}");
            }
            catch (CanceledException e)
            {
                Console.WriteLine($"Canceled: '{e.Message}'");
            }
            catch (ErrorException e)
            {
                Console.WriteLine($"Error: '{e.Message}'");
            }

            try
            {
                var r2 = WebAuthN.GetAssertion(appId: "1password.com",
                                               challenge: "z6TQzWKemfqfkG0-uOeqAGu07-2DM1Pr68MdYbRp6oA",
                                               origin: "https://my.1password.com",
                                               crossOrigin: false,
                                               keyHandles: new[]
                                               {
                                                   // Invalid key
                                                   "5dVObe0KpHxfqCGs-8_-xGQ6aovw8AJ4ZIofcVPLWPJtbpRPu7Uew9kVosWNfU2j-we25axbAktN9N7OJhYODg",
                                                   // Correct key
                                                   "4dVObe0KpHxfqCGs-8_-xGQ6aovw8AJ4ZIofcVPLWPJtbpRPu7Uew9kVosWNfU2j-we25axbAktN9N7OJhYODg",
                                                   // Invalid key
                                                   "6dVObe0KpHxfqCGs-8_-xGQ6aovw8AJ4ZIofcVPLWPJtbpRPu7Uew9kVosWNfU2j-we25axbAktN9N7OJhYODg",
                                               });

                Console.WriteLine("WebAuthn");
                Console.WriteLine($"ClientData: {r2.ClientData}");
                Console.WriteLine($"KeyHandle: {r2.KeyHandle}");
                Console.WriteLine($"Signature: {r2.Signature}");
                Console.WriteLine($"AuthData: {r2.AuthData}");
            }
            catch (CanceledException e)
            {
                Console.WriteLine($"Canceled: '{e.Message}'");
            }
            catch (ErrorException e)
            {
                Console.WriteLine($"Error: '{e.Message}'");
            }
        }
    }
}
