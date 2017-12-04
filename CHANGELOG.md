# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.4.1] - 2017-12-04
### Fixed
- Segmentation fault when trying to recover the PIN with `-m7-enc` and other options @rofl0r @binarymaster.

## [1.4.0] - 2017-12-04
### Added
- Multi-threading support @rofl0r.
- Huge performance optimizations (`--mode 3`).
- Future and past timespan windows when seed is found to compensate sudden NTP updates (`--mode 3`).
- Optional WPA-PSK and E-S2 recovery from M7 and E-S1 from M5 (majority of `--mode 3`, with `--m7-enc` and `--m5-enc`).
- Print of number of cores when `--version` is used.
- Re-introduced possibility to compile with OpenSSL (`make OPENSSL=1`) for better performance @rofl0r.
- Message for contributing, see README for more details.

### Fixed
- Fixed compilation with `-O0` @rofl0r.

### Changed
- Increased default timespan for `--mode 3` to +-1 day.
- Increased maximum limit for `--start`/`--end` to `0x7FFFFFFF` (`02/2038`) @binarymaster.
- Formatted output differently to fit terminal (removed `:` as byte separator).
- Print program version with `--version` on `stdout` (other info on `stderr`).
- Makefile to a more conventional way @rofl0r.

### Deprecated
- Option `-S`, `--dh-small`.
- Option `-l`, `--length`.

## [1.3.0] - 2017-10-07
### Added
- Empty PIN cracking (denoted with `<empty>`) @binarymaster.
- Option `-o`, `--output` to write output to file @binarymaster.
- Option `-l`, `--length` to brute-force arbitrary PIN length (unverified) @binarymaster.
- Man page @samueloph.

### Fixed
- Several Makefile fixes.

## [1.2.2] - 2016-01-04
### Added
- FreeBSD support @fbettag.

### Fixed
- Division by zero on BSD variants.

## [1.2.1] - 2016-01-04
### Changed
- Use UTC time to display seed.

## [1.2.0] - 2015-12-06
### Added
- Option `--mode` for mode selection.
- Options `--start` and `--end` (`--mode 3`).
- Mac OS support @marchrius.

### Changed
- Removed OpenSSL dependency.

## [1.1.0] - 2015-05-01
### Added
- Fully implemented new mode (`--mode 3`).
- Authentication session key (`--authkey`) computation with small Diffie-Hellman keys (`--dh-small`).
- OpenWrt Makefile @d8tahead.

## [1.0.5] - 2015-04-10
### Added
- Initial implementation of new mode (`--mode 3`).

## [1.0.0] - 2015-04-02
