package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/tredoe/osutil/user/crypt"
	"github.com/tredoe/osutil/user/crypt/apr1_crypt"
	"github.com/tredoe/osutil/user/crypt/md5_crypt"
	"github.com/tredoe/osutil/user/crypt/sha256_crypt"
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
)

// read password from stdin
func passwordPrompt() (string, error) {
	var p1, p2 []byte // passwords
	var err error     // error holder

	// loop until match
	for {
		// prompt user and read password
		fmt.Print("Password: ")
		if p1, err = gopass.GetPasswdMasked(); err != nil {
			return "", err
		}

		// prompt user and read confirmation
		fmt.Print("Confirm:  ")
		if p2, err = gopass.GetPasswdMasked(); err != nil {
			return "", err
		}

		// compare passwords and ensure non-nil
		if bytes.Equal(p1, p2) && p1 != nil {
			// return password string - no error
			return string(p1), nil
		}

		// not equal - try again
		fmt.Print("Password confirmation failed.  Please try again.\n")
	}
}

// it all happens here
func main() {
	var passwordString string // user supplied password
	var hashString string     // user supplied hash (optional)
	var saltString string     // user supplied salt (optional)
	var c crypt.Crypter       // hashing object
	var saltPrefix string     // salt prefix set based on hash
	var saltMaxLen int        // maximum salt length set based on hash
	var shadowHash string     // generated shadow hash
	var err error             // generic error holder

	// initialize flagset
	fs := flag.NewFlagSet("mkpasswd", flag.ContinueOnError)

	// set command line options
	fs.StringVar(&passwordString, "password", "",
		"Optional password argument")
	fs.StringVar(&saltString, "salt", "",
		"Optional salt argument without prefix")
	fs.StringVar(&hashString, "hash", "sha512",
		"Optional hash argument: sha512, sha256, md5 or apr1")

	// parse arguments and check return
	if err = fs.Parse(os.Args[1:]); err != nil {
		// oops ... exit out
		os.Exit(1)
	}

	// build crypter based on options
	switch strings.ToLower(hashString) {
	case "apr1":
		c = crypt.New(crypt.APR1)
		saltPrefix = apr1_crypt.MagicPrefix
		saltMaxLen = apr1_crypt.SaltLenMax
	case "md5":
		c = crypt.New(crypt.MD5)
		saltPrefix = md5_crypt.MagicPrefix
		saltMaxLen = md5_crypt.SaltLenMax
	case "sha256":
		c = crypt.New(crypt.SHA256)
		saltPrefix = sha256_crypt.MagicPrefix
		saltMaxLen = sha256_crypt.SaltLenMax
	case "sha512":
		c = crypt.New(crypt.SHA512)
		saltPrefix = sha512_crypt.MagicPrefix
		saltMaxLen = sha512_crypt.SaltLenMax
	default:
		fmt.Printf("Unknown hash (%s) specified.  "+
			"Valid options: sha512 (default), sha256, md5 or apr1\n", hashString)
		os.Exit(1)
	}

	// check salt string
	if saltString != "" {
		// check length
		if len(saltString) > saltMaxLen {
			// warn user
			fmt.Printf("Warning specified salt greater than max length (%d).  "+
				"Salt will be truncated.\n", saltMaxLen)
		}
		// prepend appropriate magic prefix and salt
		saltString = fmt.Sprintf("%s%s", saltPrefix, saltString)
	}

	// check password
	if passwordString == "" {
		// prompt for password and check error
		if passwordString, err = passwordPrompt(); err != nil {
			fmt.Printf("Error reading passsword: %s", err.Error())
			os.Exit(1)
		}
	}

	// build hash and check error
	if shadowHash, err = c.Generate([]byte(passwordString), []byte(saltString)); err != nil {
		fmt.Printf("Failed to generate shadow hash: %s\n", err.Error())
		os.Exit(1)
	}

	// print hash and exit
	fmt.Printf("%s\n", shadowHash)
	os.Exit(0)
}
