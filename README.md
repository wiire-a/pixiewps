# Overview [![License](https://img.shields.io/badge/License-GPL%20v3%2B-blue.svg?style=flat-square)](https://github.com/wiire/pixiewps/blob/master/LICENSE.md)

**Pixiewps** is a tool written in C used to **bruteforce offline** the WPS pin exploiting the low or non-existing entropy of some Access Points, the so-called "pixie dust attack" discovered by Dominique Bongard in summer 2014. It is meant for educational purposes only.

As opposed to the traditional online bruteforce attack, implemented in tools like Reaver or Bully which aim to recover the pin in a few hours, this method can get the pin in only a matter of **milliseconds** to **minutes**, depending on the target, **if vulnerable**.

![pixiewps_screenshot](http://i.imgur.com/JOa5uTp.png)

More details can be found here:
- [https://forums.kali.org/showthread.php?25018-Pixiewps-wps-pixie-dust-attack-tool](https://forums.kali.org/showthread.php?25018-Pixiewps-wps-pixie-dust-attack-tool)
- [https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-(Offline-WPS-Attack)](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-(Offline-WPS-Attack))

A non-exhaustive list of vulnerable devices (not maintained by me):
- [https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit?pref=2&pli=1#gid=2048815923](https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit?pref=2&pli=1#gid=2048815923)

# Requirements

```
apt-get -y install build-essential
```

Prior versions of 1.2 require [libssl-dev](https://www.openssl.org/).

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

**Install**

```
sudo make install
```

# Usage

```
Usage: pixiewps <arguments>

Required Arguments:

  -e, --pke         : Enrollee public key
  -r, --pkr         : Registrar public key
  -s, --e-hash1     : Enrollee hash 1
  -z, --e-hash2     : Enrollee hash 2
  -a, --authkey     : Authentication session key
  -n, --e-nonce     : Enrollee nonce

Optional Arguments:

  -m, --r-nonce     : Registrar nonce
  -b, --e-bssid     : Enrollee BSSID
  -S, --dh-small    : Small Diffie-Hellman keys (PKr not needed)  [No]
  -v, --verbosity   : Verbosity level 1-3, 1 is quietest           [3]

  -h                : Display this usage screen
  --help            : Verbose help and more usage examples
  -V, --version     : Display version

  --mode N[,... N]  : Mode selection, comma separated           [Auto]
  --start [mm/]yyyy : Starting date (only mode 3)       [Current time]
  --end   [mm/]yyyy : Ending date   (only mode 3)            [-3 days]
```

# Usage example

A common usage example is:

```
pixiewps --pke <pke> --pkr <pkr> --e-hash1 <e-hash1> --e-hash2 <e-hash2> --authkey <authkey> --e-nonce <e-nonce>
```

which requires a modified version of Reaver or Bully which prints the *Authentication Session key* (`--authkey`, `-a`). The recommended version is [reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x).

# Supported OS

Pixiewps can be compiled and installed on a wide variety of platforms including [OpenWrt](https://openwrt.org/) and Android.

# Acknowledgements

- Part of the code was inspired by Bully and its WPS functionality written by Jouni Malinen
- The crypto libraries were taken from [mbed TLS](https://tls.mbed.org/)
- Special thanks to: `soxrok2212`, `datahead`, `t6_x`, `aanarchyy`, `kcdtv` and the [Kali Linux](https://www.kali.org/) community

# References

Pixiewps is based on the work of Dominique Bongard:
1. [Video presentation](http://video.adm.ntnu.no/pres/549931214e18d)
2. [Slide presentation](http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf)
