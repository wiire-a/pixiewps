# OVERVIEW [![License](https://img.shields.io/badge/License-GPL%20v3%2B-blue.svg)] (https://github.com/wiire/pixiewps/blob/master/LICENSE.md)

Pixiewps is a tool written in C used to bruteforce offline the WPS pin exploiting the low or non-existing entropy of some APs (pixie dust attack). It is meant for educational purposes only. All credits for the research go to Dominique Bongard.

# DEPENDENCIES

Pixiewps requires libssl. To install it:

```
    sudo apt-get install libssl-dev
```

# INSTALLATION

Pixiewps can be built and installed by running:

```
    ~/pixiewps$ cd src
    ~/pixiewps/src$ make
    ~/pixiewps/src$ sudo make install
```

# USAGE

```
 Usage: pixiewps <arguments>

 Required Arguments:

    -e, --pke           : Enrollee public key
    -r, --pkr           : Registrar public key
    -s, --e-hash1       : Enrollee Hash1
    -z, --e-hash2       : Enrollee Hash2
    -a, --authkey       : Authentication session key

 Optional Arguments:

    -n, --e-nonce       : Enrollee nonce (mode 2,3,4)
    -m, --r-nonce       : Registrar nonce
    -b, --e-bssid       : Enrollee BSSID
    -S, --dh-small      : Small Diffie-Hellman keys (PKr not needed)   [No]
    -f, --force         : Bruteforce the whole keyspace (mode 4)       [No]
    -v, --verbosity     : Verbosity level 1-3, 1 is quietest            [2]

    -h, --help          : Display this usage screen
```

# DESCRIPTION OF ARGUMENTS

```
    -e, --pke

        Enrollee's DH public key, found in M1.

    -r, --pkr

        Registrar's DH public key, found in M2 or can be avoided by specifying
        small Diffie-Hellman keys in both Reaver and Pixiewps.

    -s, --e-hash1

        Enrollee Hash-1, found in M3.

    -z, --e-hash2

        Enrollee Hash-2, found in M3.

    -a, --authkey

        Registration Protocol authentication session key. Although for this parameter a
        modified version of Reaver or Bully is needed, it can be avoided by specifying
        small Diffie-Hellman keys in both Reaver and Pixiewps and supplying --e-nonce,
        --r-nonce and --e-bssid.

    -n, --e-nonce

        Enrollee's nonce, found in M1.

    -m, --r-nonce

        Registrar's nonce, found in M2.

    -b, --e-bssid

        Enrollee's BSSID.

    -S, --dh-small

        Small Diffie-Hellman keys. The same option MUST be specified on Reaver
        (1.3 or later versions) too.

    -f, --force

        Force Pixiewps to bruteforce the whole keyspace for mode 4.
        It could take up to several minutes to complete.

    -v, --verbosity

        Verbosity level (1-3). Level 3 displays the most information.

    -h, --help

        Display usage screen.
```
