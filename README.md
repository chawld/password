# password
A password generator implemented in Go

This library implements a random password generator with characters from character sets specified by the caller. Callers can also specify the
minimum number of characters from each set.
The library uses crypto/rand to select characters at random from the character sets. Callers override this by providing their own implementation of
the `Random` interface. The passwords generate will always have the minimum number of characters from each character set.

## Installation
`go get -u github.com/chawld/password`

## Usage
```
package main

import (
	"fmt"

	"github.com/chawld/password"
	"github.com/golang/glog"
)

func main() {
	g, err := password.NewGenerator(
		password.WithCharacters(password.LowerCaseAlphabet, 1),
		password.WithCharacters(password.UpperCaseAlphabet, 2),
		password.WithCharacters(password.Digits, 3),
		password.WithCharacters([]rune(`~!@#$%^&{}[]|\;:'",./?*()-_=+`), 4),
	)
	if err != nil {
		glog.Fatalf("Failed to build password generator: %v", err)
	}

	passwd, err := g.Generate(15, 20)
	if err != nil {
		glog.Fatalf("Failed to build password generator: %v", err)
	}
	fmt.Printf("%v\n", string(passwd))
}
```

## License
This code is licensed under the Apache 2.0 license.
