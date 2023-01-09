package password

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenPassword(t *testing.T) {
	g, err := NewGenerator()
	require.Equal(t, err, NoCharactersErr)

	g, err = NewGenerator(
		WithCharacters(LowerCaseAlphabet, 1),
		WithCharacters(UpperCaseAlphabet, 2),
		WithCharacters(Digits, 3),
		WithCharacters([]rune(`~!@#$%^&{}[]|\;:'",./?*()-_=+`), 4),
	)
	require.Nil(t, err)

	_, err = g.Generate(8, 9)
	require.Equal(t, err, InvalidLengthErr)

	_, err = g.Generate(20, 19)
	require.Equal(t, err, InvalidLengthErr)

	for i := 0; i < 10000; i++ {
		p, err := g.Generate(8, 20)
		require.Nil(t, err)
		require.GreaterOrEqual(t, len(p), 10)
		require.LessOrEqual(t, len(p), 20)

		numLower, numUpper, numDigits, numSpecial := 0, 0, 0, 0
		for i := 0; i < len(p); i++ {
			switch {
			case p[i] >= 'a' && p[i] <= 'z':
				numLower++
			case p[i] >= 'A' && p[i] <= 'Z':
				numUpper++
			case p[i] >= '0' && p[i] <= '9':
				numDigits++
			default:
				numSpecial++
			}
		}
		require.GreaterOrEqual(t, numLower, 1)
		require.GreaterOrEqual(t, numUpper, 2)
		require.GreaterOrEqual(t, numDigits, 3)
		require.GreaterOrEqual(t, numSpecial, 4)
	}
}
