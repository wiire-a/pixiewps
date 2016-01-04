# Overview [![License](https://img.shields.io/badge/License-GPL%20v3%2B-blue.svg?style=flat-square)] (https://github.com/wiire/pixiewps/blob/master/LICENSE.md)

**Pixiewps** is a tool written in C used to **bruteforce offline** the WPS pin exploiting the low or non-existing entropy of some APs (pixie dust attack). It is meant for educational purposes only.

- - -

# Requirements

Prior versions of 1.2 require [libssl-dev](https://www.openssl.org/).

- - -

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

`sudo make install`

- - -

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

which requires a modified version of Reaver or Bully which prints *AuthKey*. The recommended version is [reaver-wps-fork-t6x](https://github.com/t6x/reaver-wps-fork-t6x).