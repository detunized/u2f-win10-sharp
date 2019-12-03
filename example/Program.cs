using System;
using System.Text;
using U2fWin10;

namespace U2fWin10Example
{
    class Program
    {
        static void Main(string[] args)
        {
            var appId = "https://snappy.local/app-id.json";
            var challenge = Encoding.UTF8.GetBytes("{\"challenge\":\"zImw3II_G5JKACzFB4I1FLFTmo2lmEs4Jg2gOP2dYNk\",\"origin\":\"https://snappy.local\",\"typ\":\"navigator.id.getAssertion\"}");
            var keyHandle = Convert.FromBase64String("mizejqv8eHXSToeUEbxLzT65XIvIKY5YJdzSKGhvtP7SHDo/o4IXuEuGdajO172g1pXE2DZ+veI5/mmVCiZp4Q==");

            var signature = U2f.Sign(appId, challenge, keyHandle);
            Console.WriteLine(Convert.ToBase64String(signature));
        }
    }
}
