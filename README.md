[![Mozilla Public License](https://img.shields.io/badge/license-MPL-blue.svg)](https://www.mozilla.org/MPL/)
# mkpasswd

## Summary

Simple mkpasswd utility written in golang for platform portability.

## Installing

With a proper Go environment simply run:

```bash
go get -u github.com/myENA/mkpasswd
```

## Usage

### Summary

```
ahurt$ ./mkpasswd -h
Usage of mkpasswd:
  -hash string
        Optional hash argument: sha512, sha256, md5 or apr1 (default "sha512")
  -password string
        Optional password argument
  -rounds int
        Optional number of rounds
  -salt string
        Optional salt argument without prefix
```

### Example

```
ahurt$ ./mkpasswd
Password: ****
Confirm:  ****
$6$amUMrbDAEvqAdrtz$Jg0xMnIVeRR2IrZExX3AJj/IIMkfqDGGebIiUFRM2A376d8rbIJYBMOQGjoLeHu3mPlq//0Awc55zEtBNH43m.
```
