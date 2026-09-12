//go:build linux

package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/agentveil/agentveil/internal/core"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/egress"
)

const protectedEgressWatchInterval = 250 * time.Millisecond

func startProtectedEgressWatch(ctx context.Context, cancel context.CancelFunc, processID int, endpoint string) (<-chan error, error) {
	identity, err := egress.LinuxProcessIdentity("", processID)
	if err != nil {
		return nil, fmt.Errorf("bind protected process identity: %w", err)
	}
	localEndpoint, err := protectedCoreLocalEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	observer, err := egress.NewObserver(identity, egress.DefaultMaxProcessSnapshot, egress.LinuxProcCollector{}, egress.LinuxConnectionCollector{})
	if err != nil {
		return nil, err
	}
	watcher, err := egress.NewWatcher(observer, protectedEgressWatchInterval, nil, []egress.LocalEndpoint{localEndpoint}, func(_ context.Context, assessments []egress.Assessment) error {
		return validateProtectedEgress(assessments)
	})
	if err != nil {
		return nil, err
	}
	result := make(chan error, 1)
	go func() {
		err := watcher.Run(ctx)
		if err != nil {
			cancel()
		}
		result <- err
	}()
	return result, nil
}

func protectedCoreLocalEndpoint(endpoint string) (egress.LocalEndpoint, error) {
	address, err := core.ListenAddress(endpoint)
	if err != nil {
		return egress.LocalEndpoint{}, err
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return egress.LocalEndpoint{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return egress.LocalEndpoint{}, fmt.Errorf("core endpoint port is invalid: %s", portText)
	}
	return egress.LocalEndpoint{Transport: egress.TransportTCP, Host: host, Port: uint16(port)}, nil
}

func validateProtectedEgress(assessments []egress.Assessment) error {
	for _, assessment := range assessments {
		switch assessment.Status {
		case egress.StatusLocal, egress.StatusContentProtected, egress.StatusBlocked:
			continue
		case egress.StatusObserved:
			return domain.NewError(domain.ErrUnexpectedEgress, "protect process egress", "unexpected process egress was observed; the protected process group was stopped")
		default:
			return domain.NewError(domain.ErrUnexpectedEgress, "protect process egress", "an unknown process egress assessment was returned; the protected process group was stopped")
		}
	}
	return nil
}
