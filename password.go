package password

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var (
	// Errors returned by API, apart from the ones returned by crypto/rand and math/big.
	InvalidLengthErr = fmt.Errorf("Invalid password length")
	NoCharactersErr  = fmt.Errorf("No characters specified")

	// Character sets declared for easy of use. These are not auto-included in the password.
	LowerCaseAlphabet = []rune("abcdefghijklmnopqrstuvwxyz")
	UpperCaseAlphabet = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	Digits            = []rune("0123456789")
)

// Generator represents a password generator.
type Generator interface {
	// Generate returns a password of a random length between min and max, or an error.
	Generate(min, max uint) ([]rune, error)
}

// Options represents the type of options accepted by the password generator. See below for
// supported options.
type Options func(*generator)

// Random is an interface that custom random number generator need to implement.
type Random interface {
	Get(max uint) (uint, error)
}

// WithRandom lets caller specify a custom random number generator.
func WithRandom(random Random) Options {
	return func(g *generator) {
		g.random = random
	}
}

// WithCharacters lets caller specify the character set to use and the minimum number of characters
// to include in a password.
func WithCharacters(set []rune, min uint) Options {
	return func(g *generator) {
		g.charsets = append(g.charsets, charSet{
			set: set,
			min: min,
		})
		g.min += min
		g.num += uint(len(set))
	}
}

// NewGenerator returns a new password generator with the given options.
func NewGenerator(opts ...Options) (Generator, error) {
	g := &generator{random: random{}}
	for _, o := range opts {
		o(g)
	}
	if g.num == 0 {
		return nil, NoCharactersErr

	}
	return g, nil
}

type charSet struct {
	set []rune // a set of characters.
	min uint   // the minimum number of characters from this set that must be in a password.
}

// generator is a password generator that implements the Generator internface.
type generator struct {
	charsets []charSet
	min      uint   // minimum length of a password.
	num      uint   // max length of a password.
	random   Random // optional random number generator.
}

// Generate returns a password of a random length between min and max, or an error.
func (g *generator) Generate(min, max uint) ([]rune, error) {

	// Generate a password of random length.
	length, err := g.getRandomLength(min, max)
	if err != nil {
		return nil, err
	}

	// Select the characters at random.
	chars, err := g.getRandomChars(length)
	if err != nil {
		return nil, err
	}

	// Shuffle the characters.
	err = shuffle(g.random, chars)
	if err != nil {
		return nil, err
	}

	return chars, nil
}

// getRandomLength returns a random number between min and max (uniform distribution).
func (g *generator) getRandomLength(min, max uint) (uint, error) {
	if max < min || max < g.min {
		return 0, InvalidLengthErr
	}
	if min < g.min {
		min = g.min
	}
	length, err := g.random.Get(max - min + 1)
	if err != nil {
		return 0, err
	}
	return length + min, nil
}

// getRandomChars returns characters selected at random from the character sets in the password
// generator. There is an order in which the characters are selected, so the returned slice will
// have a pattern and shouldn't be used as is as a password.
func (g *generator) getRandomChars(n uint) ([]rune, error) {
	chars := make([]rune, 0, n)

	// First get minimum number of characters from each set, so the requirements are met.
	for _, c := range g.charsets {
		newChars, err := getRandomChars(g.random, c.set, c.min)
		if err != nil {
			return nil, err
		}
		chars = append(chars, newChars...)
	}

	// pick the rest of characters from all the character sets.
	for i := uint(0); i < n-g.min; i++ {
		k, err := g.random.Get(g.num)
		if err != nil {
			return nil, err
		}
		for _, c := range g.charsets {
			if k < uint(len(c.set)) {
				chars = append(chars, c.set[k])
				break
			}
			k -= uint(len(c.set))
		}
	}

	return chars, nil
}

// getRandomChars returns characters selected at random, uniform distribution, with repeats, from
// the given slice.
func getRandomChars(r Random, from []rune, n uint) ([]rune, error) {
	chars := make([]rune, n)
	l := uint(len(from))
	for i := uint(0); i < n; i++ {
		k, err := r.Get(l)
		if err != nil {
			return nil, err
		}
		chars[i] = from[k]
	}
	return chars, nil
}

// shuffle rearranges (in-place) the characters in a random order.
func shuffle(r Random, chars []rune) error {
	n := uint(len(chars))
	for i := uint(0); i < n-1; i++ {
		k, err := r.Get(n - i)
		if err != nil {
			return err
		}
		chars[i], chars[i+k] = chars[i+k], chars[i]
	}
	return nil
}

// random implements the Random interface using crypto/rand package.
type random struct{}

// Get returns a random number (uniform distribution) in the range [0, max), or an error.
func (r random) Get(max uint) (uint, error) {
	b := big.NewInt(int64(max))
	nInt, err := rand.Int(rand.Reader, b)
	if err != nil {
		return 0, err
	}
	n := uint(nInt.Int64())
	return n, nil
}
