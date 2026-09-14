//go:build !darwin && !linux && !windows

package main

import "errors"

func openBrowserURL(string) error {
	return errors.New("opening a browser is unsupported on this platform; use 'veil web --print'")
}
