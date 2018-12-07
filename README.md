SCD-PKCS#11
===========

The scd-pkcs#11 module is a prototype / proof of concept PKCS#11 provider interfacing to GnuPG's smart card daemon (scdaemon).

It allows PKCS#11 aware applications such as Firefox or OpenSSH to use smart cards via GnuPG's builtin smart card support. scd-pkcs#11 is an alternative to the OpenSC PKCS#11 module.

## Component Overview

### Scenario A - with SCD-PKCS#11

This Scenario is the focus of this project.

    USB SmartCard
      |-- scdaemon -- gpg-agent -- GnuPG / SSH (via gpg-agent's builtin ssh-agent)
                        |-- SCD-PKCS#11 provider
                              |-- client app (Firefox, SSH, ...)

### Scenario B - with and without SCD-PKCS#11

Problem: scdaemon needs exclusive access to the smart card

    USB SmartCard
      |-- pcscd
      |     |-- CCID driver
      |           |-- PKCS#11 provider (e.g. opensc-pkcs11.so)
      |                 |-- client app (Firefox, SSH, ...)
      |
      |-- scdaemon ---- gpg-agent -- GnuPG (or SSH via gpg-agent builtin ssh-agent)
                              |-- SCD-PKCS#11 provider
                                    |-- client app

### Scenario C - without SCD-PKCS#11, but with gnupg-pkcs11-scd:

    USB token
      |-- pcscd
            |-- CCID driver
                  |-- PKCS#11 provider (e.g. opensc-pkcs11.so)
                        |-- client app (Firefox, SSH, ...)
                        |-- gnupg-pkcs11-scd (alternative scdaemon)
                              |-- gpg-agent -- GnuPG

### Scenario D - OSX component overview

    USB token -- PCSCD -- CCID driver bundle -- PKCS#11 provider -- client app
      |-- .. .. .. .. .. .. |-- tokend -- tokend.bundle -- Keychain -- OSX App (Safari, Chrome, ...)
      |
      |-- scdaemon -- gpg-agent -- GnuPG
                        |-- SCD-PKCS#11 provider -- client app

Problems:

  * scdaemon and CCID do not work simultaneously.
  * scdaemon does not quit after use.
  * CCID is not up to date. New hardware may need custom drivers.
  * tokend is not well documented. The relevant open source OpenSC.tokend seems to lack maintenance since OSX 10.6, but appears to work (even if somewhat by coincidence).

## Compiling / Installation

Please read the [wiki installation page](https://github.com/sektioneins/scd-pkcs11/wiki/Installation).

Quick-Install from source:

```
./configure
make
make install
```

That's it. See the [wiki](https://github.com/sektioneins/scd-pkcs11/wiki) for further documentation. 

### Quick Installation on OSX / macOS

```
brew install sektioneins/tap/scd-pkcs11
```

## Related Projects

  * [Scute](http://www.scute.org/) - "Scute is a PKCS #11 module that adds support for the OpenPGP smartcard card to the Mozilla Network Security Services (NSS)."
  * [YKCS11](https://developers.yubico.com/yubico-piv-tool/YKCS11_release_notes.html) - "This is a PKCS#11 module that allows to communicate with the PIV application running on a YubiKey."

## Feedback

Please use the [issue tracker](https://github.com/sektioneins/scd-pkcs11/issues).

When reporting a bug, please provide

  * Operating System and version
  * library version, e.g. commit id or package version
  * PKCS#11 client, e.g. Firefox
  * Short description of what to do to reproduce the bug
  * If needed, log files, screen shots, additional information.

## License

Copyright (C) 2015-2018 SektionEins GmbH / Ben Fuhrmannek

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
