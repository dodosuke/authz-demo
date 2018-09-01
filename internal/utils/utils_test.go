package utils

import "testing"

func TestDiff(t *testing.T) {
	a := []string{"hoge", "fugo"}
	b := []string{"hoge", "fugo", "hego"}
	c := []string{}

	if len(Diff(a, b)) != 0 {
		t.Fatalf("failed")
	}

	if len(Diff(b, a)) != 1 {
		t.Fatalf("faled")
	}

	if len(Diff(c, a)) != 0 {
		t.Fatalf("Failed")
	}
}
