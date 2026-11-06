package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type endpoint struct {
	Gateway string
	Head    string
	Local   string
}

func usableIP(text string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(text)
	if err != nil || !ip.Is4() || !ip.IsLinkLocalUnicast() {
		return netip.Addr{}, errors.New("use an ENET IPv4 address in 169.254.x.x")
	}
	b := ip.As4()
	if b[2] == 0 || b[2] == 255 {
		return netip.Addr{}, errors.New("use a usable ENET link-local address")
	}
	return ip, nil
}

func discover() ([]endpoint, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	locals := map[string]bool{}
	for _, addr := range addrs {
		if prefix, e := netip.ParsePrefix(addr.String()); e == nil {
			if ip, e := usableIP(prefix.Addr().String()); e == nil {
				locals[ip.String()] = true
			}
		}
	}
	if len(locals) == 0 {
		return nil, errors.New("no 169.254.x.x network adapter found; check the ENET cable")
	}
	var wg sync.WaitGroup
	var lock sync.Mutex
	var results []endpoint
	for local := range locals {
		wg.Go(func() {
			gateways, heads := broadcast(local)
			for _, gateway := range gateways {
				head := headIP(local, gateway)
				if head == "" && len(gateways) == 1 && len(heads) == 1 {
					head = heads[0]
				}
				lock.Lock()
				results = append(results, endpoint{gateway, head, local})
				lock.Unlock()
			}
		})
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		if results[i].Gateway == results[j].Gateway {
			return results[i].Local < results[j].Local
		}
		return results[i].Gateway < results[j].Gateway
	})
	if len(results) == 0 {
		return nil, errors.New("no ENET gateway replied; use manual IPs or check your cable, ignition and firewall")
	}
	return results, nil
}

var addressTag = regexp.MustCompile(`DIAGADR(10|62|63)`)

func broadcast(local string) (gateways, heads []string) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var err error
		if e := c.Control(func(fd uintptr) { err = enableBroadcast(fd) }); e != nil {
			return e
		}
		return err
	}}
	conn, err := lc.ListenPacket(context.Background(), "udp4", local+":0")
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1800 * time.Millisecond))
	dest := &net.UDPAddr{IP: net.IPv4(169, 254, 255, 255), Port: 6811}
	if _, err := conn.WriteTo([]byte{0, 0, 0, 0, 0, 0x11}, dest); err != nil {
		return
	}
	seen := map[string]bool{}
	buf := make([]byte, 4096)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		if n < 6 || buf[4] != 0 || buf[5] != 0x11 {
			continue
		}
		ip, err := usableIP(remote.(*net.UDPAddr).IP.String())
		if err != nil || ip.String() == local {
			continue
		}
		tag := addressTag.FindSubmatch(buf[6:n])
		if len(tag) != 2 || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		if string(tag[1]) == "10" {
			gateways = append(gateways, ip.String())
		} else {
			heads = append(heads, ip.String())
		}
	}
	return
}

func enetDial(local, host, port string, limit time.Duration) (net.Conn, error) {
	if _, err := usableIP(host); err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: limit}
	if local != "" {
		if _, err := usableIP(local); err != nil {
			return nil, err
		}
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(local)}
	}
	c, err := d.Dial("tcp4", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	// Limit legacy SSH and diagnostic operations to a directly attached ENET link.
	if _, err := usableIP(c.LocalAddr().(*net.TCPAddr).IP.String()); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func readDID(local, gateway string, did uint16) ([]byte, error) {
	conn, err := enetDial(local, gateway, "6801", 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2500 * time.Millisecond))
	hi, lo := byte(did>>8), byte(did)
	if _, err = conn.Write([]byte{0, 0, 0, 5, 0, 1, 0xf4, 0x63, 0x22, hi, lo}); err != nil {
		return nil, err
	}
	var header [6]byte
	for i := 0; i < 32; i++ {
		if _, err = io.ReadFull(conn, header[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(header[:4])
		if n > 4096 {
			return nil, errors.New("oversized ENET identification response")
		}
		body := make([]byte, n)
		if _, err = io.ReadFull(conn, body); err != nil {
			return nil, err
		}
		switch binary.BigEndian.Uint16(header[4:]) {
		case 0x12:
			if _, err = conn.Write([]byte{0, 0, 0, 2, 0, 0x13, 0, 0xf4}); err != nil {
				return nil, err
			}
		case 1:
			if bytes.HasPrefix(body, []byte{0x63, 0xf4, 0x62, hi, lo}) {
				return body[5:], nil
			}
			if len(body) == 5 && bytes.HasPrefix(body, []byte{0x63, 0xf4, 0x7f, 0x22}) && body[4] != 0x78 {
				return nil, fmt.Errorf("DME gateway did not return head unit identification (NRC %02X)", body[4])
			}
		}
	}
	return nil, errors.New("no matching head unit identification response")
}

func headIP(local, gateway string) string {
	value, err := readDID(local, gateway, 0x172a)
	if err != nil {
		return ""
	}
	result := strings.Trim(string(value), "\x00 \r\n")
	if len(value) == 4 {
		result = net.IP(value).String()
	}
	if ip, e := usableIP(result); e == nil && ip.String() != gateway && ip.String() != local {
		return ip.String()
	}
	return ""
}
