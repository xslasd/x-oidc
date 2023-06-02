package util

import "math/rand"

var letters = []rune("abcdefhijkmnprstwxyz2345678")

func RandomString(length int) string {
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
func DefString(val string, defVal string) string {
	if val != "" {
		return val
	}
	return defVal
}
