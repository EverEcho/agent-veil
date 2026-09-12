package network

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/agentveil/agentveil/internal/domain"
)

func negotiateSOCKS5(connection net.Conn, target string) error {
	if err := writeFull(connection, []byte{5, 1, 0}); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	if response[0] != 5 || response[1] != 0 {
		return domain.NewError(domain.ErrUpstreamDenied, "dial SOCKS5", "proxy rejected no-authentication negotiation")
	}
	host, rawPort, err := net.SplitHostPort(target)
	if err != nil {
		return domain.NewError(domain.ErrInvalidContract, "dial SOCKS5", "target address is invalid")
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return domain.NewError(domain.ErrInvalidContract, "dial SOCKS5", "target port is invalid")
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 1)
			request = append(request, ipv4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return domain.NewError(domain.ErrInvalidContract, "dial SOCKS5", "target hostname is invalid")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if err := writeFull(connection, request); err != nil {
		return err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return err
	}
	if header[0] != 5 || header[2] != 0 {
		return domain.NewError(domain.ErrUpstreamDenied, "dial SOCKS5", "proxy returned a malformed response")
	}
	if header[1] != 0 {
		return domain.NewError(domain.ErrUpstreamDenied, "dial SOCKS5", fmt.Sprintf("proxy rejected target with status %d", header[1]))
	}
	addressBytes := 0
	switch header[3] {
	case 1:
		addressBytes = net.IPv4len
	case 4:
		addressBytes = net.IPv6len
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(connection, length); err != nil {
			return err
		}
		addressBytes = int(length[0])
	default:
		return domain.NewError(domain.ErrUpstreamDenied, "dial SOCKS5", "proxy returned an unknown address type")
	}
	_, err = io.CopyN(io.Discard, connection, int64(addressBytes+2))
	return err
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
