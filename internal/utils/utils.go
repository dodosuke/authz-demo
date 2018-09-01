package utils

import (
	"math/rand"
	"net/url"
)

// Contains is a function to check the slice of string contains a string and returns in Int
func Contains(t []string, s string) int {
	for i, v := range t {
		if v == s {
			return i
		}
	}
	return -1
}

// RandomString returns randomized string with the given length
func RandomString(l int) string {
	b := make([]byte, l)
	for i := 0; i < l; i++ {
		b[i] = byte(65 + rand.Intn(25))
	}
	return string(b)
}

// Diff returns the elements in a that are not in b
func Diff(a, b []string) []string {
	mb := map[string]bool{}
	for _, x := range b {
		mb[x] = true
	}
	d := []string{}
	for _, x := range a {
		if _, ok := mb[x]; !ok {
			d = append(d, x)
		}
	}
	return d
}

// BuildURL is a function to build a url based on given parameters
func BuildURL(b string, qs url.Values, f string) *url.URL {
	u, err := url.Parse(b)
	if err != nil {
		return nil
	}
	q := u.Query()
	for k, v := range qs {
		q.Set(k, v[0])
	}
	u.RawQuery = q.Encode()

	if f != "" {
		u.Fragment = f
	}

	return u
}
