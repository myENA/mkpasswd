[![Mozilla Public License](https://img.shields.io/badge/license-MPL-blue.svg)](https://www.mozilla.org/MPL/)
# mkpasswd

## Summary

Simple mkpasswd utility written in golang for platform portability.

## Installing

With a proper Go environment simply run:

```bash
go get -u github.com/myENA/mkpasswd
```

Optionally, if you have [glide](https://glide.sh) installed you may do a reproducible build:

```bash
cd $GOPATH/src
git clone https://github.com/myENA/mkpasswd github.com/myENA/mkpasswd
cd github.com/myENA/mkpasswd
glide install
go build
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
