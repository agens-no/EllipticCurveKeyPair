EllipticCurveKeyPair 🔑🔑
========================

Sign, verify, encrypt and decrypt using the Secure Enclave.

## Features

- create a private public keypair
- store the private key on the secure enclave
- store the public key in keychain
- each time you use the private key the user will be prompted with touch id or device id in order to use it
- export the public key as X.509 DER with proper ASN.1 header / structure
- verify the signature with openssl in command line easily

## Nitty-gritty 

Using the Security Framework can be a little bit confusing. That’s why I created this. You may use it as example code and guidance or you may use it as a micro framework.

I found it tricky to figure out how to use the `SecKeyRawVerify`, `SecKeyGeneratePair` and `SecItemCopyMatching` C APIs in Swift 3, but the implementation is quite straight forward thanks to awesome Swift 3 features.

## Installation

Just drag the `Sources/EllipticCurveKeyPair.swift` file into your XCode project. 

To keep the source code here at a minimum you need to pass a sha256 function in to this library yourself because [CommonCrypto is missing a module map for swift](http://www.openradar.me/26276263). In the demo app you'll see how you can do that very easily.

## Usage

See demo app for example.

## Verifying a signature

In the demo app you’ll see that each time you create a signature some useful information is logged to console.

Example output

```sh
#! /bin/sh
echo 414243 | xxd -r -p > dataToSign.dat
echo 3046022100842512baa16a3ec9b977d4456923319442342e3fdae54f2456af0b7b8a09786b022100a1b8d762b6cb3d85b16f6b07d06d2815cb0663e067e0b2f9a9c9293bde8953bb | xxd -r -p > signature.dat
cat > key.pem <<EOF
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdDONNkwaP8OhqFTmjLxVcByyPa19
ifY2IVDinFei3SvCBv8fgY8AU+Fm5oODksseV0sd4Zy/biSf6AMr0HqHcw==
-----END PUBLIC KEY-----
EOF
/usr/local/opt/openssl/bin/openssl dgst -sha256 -verify key.pem -signature signature.dat dataToSign.dat
```

In order to run this script you can

1. Paste it in to a file: `verify.sh`
1. Make the file executable: `chmod u+x verify.sh`
1. Run it: `./verify.sh`

Then you should see
```sh
Verified OK
```

PS: This script will create 4 files in your current directory.

## Examples

There are lots of great possibilities with Secure Enclave. Here are some examples

### Encrypting

1. Encrypt a message using the public key
1. Decrypt the message using the private key – only accessible with touch id / device pin

Only available on iOS 10

### Signing

1. Sign some data received by server using the private key – only accessible with touch id / device pin
1. Verify that the signature is valid using the public key

A use case could be

1. User is requesting a new agreement / purchase
1. Server sends a push with a session token that should be signed
1. On device we sign the session token using the private key - prompting the user to confirm with touch id
1. The signed token is then sent to server
1. Server already is in posession of the public key and verifies the signature using the public key
1. Server is now confident that user signed this agreement with touch id


## Keywords
Security framework, Swift 3, Swift, SecKeyRawVerify, SecKeyGeneratePair, SecItemCopyMatching, secp256r1, Elliptic Curve Cryptography, ECDSA, ECDH, ASN.1, Apple, iOS, Mac OS, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyTypeEC, kSecAttrTokenIDSecureEnclave

## Credits

### TrailOfBits

[TrailOfBits](https://github.com/trailofbits/) published some objective-c code a while back which was to great help! Thanks for [sharing](https://blog.trailofbits.com/2016/06/28/start-using-the-secure-enclave-crypto-api/) Tidas and [SecureEnclaveCrypto](https://github.com/trailofbits/SecureEnclaveCrypto). They also got some other most interesting and capable projects. Check out the new VPN solution [Algo](https://github.com/trailofbits/algo).

### Quinn “the Eskimo!”, Apple

He shared som [very valuable insights](https://forums.developer.apple.com/message/84684#84684) with regards to exporting the public key in the proper DER X.509 format.

## FAQ

**Q: Why am I not being prompted with touch id / device pin on simulator?**  
A: The simulator doesn’t posess any secure enclave and therefore trying to access it would just lead to errors. For your leisure we store the private key in keychain instead of the secure enclave on simulator. This makes development faster and easier. The only diff [is a single line of code](https://github.com/agens-no/EllipticCurveKeyPair/blob/70c248e83e8c0aaf73a9c27a1bce4becfe257bba/Sources/EllipticCurveKeyPair.swift#L124-L137).

**Q: Where can I learn more?**  
A: Check out this video on [WWDC 2015](https://developer.apple.com/videos/play/wwdc2015/706/) about Security in general or [click here](https://developer.apple.com/videos/play/wwdc2015/706/?time=2069) to skip right to the section about the Secure Enclave.

## Feedback

We would 😍 to hear your opinion about this library. Wether you like or don’t. Please file an issue if there’s something you would like to see improved. Reach me on twitter as [@hfossli](https://twitter.com/hfossli) if you have any questions at all 😀.

[<img src="http://static.agens.no/images/agens_logo_w_slogan_avenir_medium.png" width="340" />](http://agens.no/)
