# U2F host library for Windows 10

![](https://github.com/detunized/u2f-win10-sharp/workflows/CI/badge.svg)

This library wraps the native WebAuthn host API released in Windows 10 build
1903. There are a few pure .NET and wrapped native libraries that aim to
provide similar functionality available on GitHub. The problem with those
libraries is that they usually interact with the USB U2F devices via a HID
layer. Starting with build 1903 Windows requires elevated privileges (run as
administrator) to interact with a U2F device in such a way. The only way to do
it in the user mode is to use the [Windows native API][api] for this. This is
what this library does.

## Changes

See [CHANGELOG.md](CHANGELOG.md).

## License

The library is released under [the MIT license][mit]. See [LICENSE][license]
for details.

[api]: https://github.com/microsoft/webauthn
[mit]: http://www.opensource.org/licenses/mit-license.php
[license]: LICENSE
