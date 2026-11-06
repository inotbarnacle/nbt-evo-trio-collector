//go:build !windows

package main

import "golang.org/x/sys/unix"

func enableBroadcast(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
}
