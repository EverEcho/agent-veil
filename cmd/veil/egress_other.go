//go:build !linux

package main

import "context"

func startProtectedEgressWatch(context.Context, context.CancelFunc, int, string, protectedEgressBinding) (<-chan error, error) {
	result := make(chan error, 1)
	result <- nil
	return result, nil
}
