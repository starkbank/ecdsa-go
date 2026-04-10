package tests

import "testing"

func assertPanics(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s: expected panic but did not get one", name)
		}
	}()
	f()
}
