# Overview [![License](https://img.shields.io/badge/License-GPL%20v3%2B-blue.svg?style=flat-square)](https://github.com/wiire/pixiewps/blob/master/LICENSE.md)

**Pixiewps** is a tool written in C used to **bruteforce offline** the WPS PIN exploiting the low or non-existing entropy of some Access Points, the so-called "pixie-dust attack" discovered by Dominique Bongard in summer 2014. It is meant for educational purposes only.

As opposed to the traditional online brute-force attack, implemented in tools like Reaver or Bully which aim to recover the pin in a few hours, this method can get the PIN in only a matter of **milliseconds** to **minutes**, depending on the target, **if vulnerable**.

![pixiewps_screenshot_1](https://i.imgur.com/nvS69me.png)

Since version 1.4, it can also recover the **WPA-PSK** from a complete passive capture (M1 through M7) for some devices (currently **only some devices** which work with `--mode 3`).

![pixiewps_screenshot_2](https://i.imgur.com/qVQ8Rng.png)

It all started as a project from the community, more details can be found here:
- [https://forums.kali.org/showthread.php?25018-Pixiewps-wps-pixie-dust-attack-tool](https://forums.kali.org/showthread.php?25018-Pixiewps-wps-pixie-dust-attack-tool)
- [https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-(Offline-WPS-Attack)](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-(Offline-WPS-Attack))

A non-exhaustive list of vulnerable devices (currently unmaintained?):
- [https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit?pref=2&pli=1#gid=2048815923](https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit?pref=2&pli=1#gid=2048815923)

# Requirements

```
apt-get -y install build-essential
```

- Prior versions of **1.2** require [libssl-dev](https://www.openssl.org/)
- Version **1.4** and later make use of multi-threading and require **libpthread**

# Setup

**Download**

`git clone https://github.com/wiire/pixiewps`

or

`wget https://github.com/wiire/pixiewps/archive/master.zip && unzip master.zip`

**Build**

```bash
cd pixiewps*/
cd src/
make
```
Optionally, you can run make OPENSSL=1 to use faster OpenSSL SHA256 functions.

**Install**

```
sudo make install
```

# Usage

```
Usage: pixiewps <arguments>

Required arguments:

  -e, --pke         : Enrollee public key
  -r, --pkr         : Registrar public key
  -s, --e-hash1     : Enrollee hash 1
  -z, --e-hash2     : Enrollee hash 2
  -a, --authkey     : Authentication session key
  -n, --e-nonce     : Enrollee nonce

Optional arguments:

  -m, --r-nonce     : Registrar nonce
  -b, --e-bssid     : Enrollee BSSID
  -l, --length      : Bruteforce entire pin length (experimental)
  -v, --verbosity   : Verbosity level 1-3, 1 is quietest           [3]
  -o, --output      : Write output to file
  -j, --jobs        : Number of parallel threads to use         [Auto]

  -h                : Display this usage screen
  --help            : Verbose help and more usage examples
  -V, --version     : Display version

  --mode N[,... N]  : Mode selection, comma separated           [Auto]
  --start [mm/]yyyy : Starting date             (only mode 3) [+1 day]
  --end   [mm/]yyyy : Ending date               (only mode 3) [-1 day]
  -f, --force       : Bruteforce full range     (only mode 3)

Miscellaneous arguments:

  -7, --m7-enc      : Recover encrypted settings from M7 (only mode 3)
  -5, --m5-enc      : Recover secret nonce from M5       (only mode 3)
```

## Usage example

The most common usage example is:

```
pixiewps --pke ... --pkr ... --e-hash1 ... --e-hash2 ... --authkey ... --e-nonce ...
```

which requires a modified version of Reaver or Bully which prints the *Authentication Session key* (`--authkey`, `-a`). The recommended version is [reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x).

The program has also a man page and a verbose help screen (`--help`) with more examples.

## -S, --dh-small
This feature was introduced back in Reaver 1.3. It works by choosing the private key = 1, thus resulting in having the public key `--pkr` = 2. This speeds up the cracking process since the AP must do less computations to calculate the Diffie-Hellman shared secret, which is later used to derive the session keys that encrypt the current transaction. Pixiewps can exploit this feature so that the user doesn't have to input `--pkr` (it's always 2) and optionally compute the session keys, like `--authkey`, if additional arguments, `--r-nonce` and `--bssid`, are specified.

It turns out some routers are buggy and do not function correctly with this feature. Some won't even be able to validate the correct PIN and the transaction will fail after M4. For this reason this feature is **deprecated** and should **never be used** in Reaver.

## -7, --m7-enc
This option requires the attribute *encrypted settings* found in M7 when the Registrar proved knowledge of the PIN, and the Access Points, the Enrollee, sends its current network configuration.

This feature can be used to crack the WPA-PSK (and WPS PIN) from a passive packet capture (e.g. sniffing a PBC session).

## -f, --force
This option is used only for mode 3. When used pixiewps will start bruteforcing from the current time and go back all the way to 0. It is conceptually identical to using `--end 01/1970` only (or `--start 01/1970` since they're interchangeable).

## Empty PIN
The empty PIN, denoted with `<empty>` can be tested with `-p ""` in Reaver [1.6.1](https://github.com/t6x/reaver-wps-fork-t6x/releases/tag/v1.6.1) and later. It comes from a misconfiguration of the WPS pin method on some Access Points which have the pin variable set to `NULL` (or empty string).

![pixiewps_screenshot_3](https://i.imgur.com/t3JYGHV.png)

# Supported platforms

Pixiewps can be compiled and installed on a wide variety of platforms including [OpenWrt](https://openwrt.org/) / [LEDE](https://lede-project.org/) and Android.

On Windows it can be compiled with [MinGW](http://www.mingw.org/). Be sure to have installed phtread support.

## Notes for wrappers and scripts
- The data in input can be formatted with one of the following byte separators: '`:`', '`-`', '` `', or without
- The most useful tags like `WPS pin` and `WPA-PSK` are denoted with `[+]` or `[-]` in case of failure
- Pixiewps returns `0` on a successful attempt

# Acknowledgements

- Part of the code was inspired by Bully by Brian Purcell
- Some files were taken from [wpa_supplicant](https://w1.fi/wpa_supplicant/) written by Jouni Malinen
- The hashing crypto libraries were taken (and modified) from [mbed TLS](https://tls.mbed.org/)
- Endianness detection and conversion is from [rofl0r/endianness.h](https://github.com/rofl0r/endianness.h)
- See [contributors](https://github.com/wiire-a/pixiewps/graphs/contributors) for a list of everyone that has contributed
- Huge thanks to `kcdtv`, `rofl0r` and `binarymaster` for helping and testing
- Special thanks to `soxrok2212`, `datahead`, `t6_x`, `aanarchyy` and the [Kali Linux](https://www.kali.org/) community

# References

Pixiewps is based on the work of Dominique Bongard ([@Reversity](https://twitter.com/reversity)):
- [Offline bruteforce attack on WiFi Protected Setup](http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf) (slides)
- [WPS Insecurity](http://video.adm.ntnu.no/pres/549931214e18d) (video presentation at NTNU)
