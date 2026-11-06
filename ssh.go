package main

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"regexp"
	"strings"
	"time"
)

type vehicleInput struct {
	Head, Local, Version, Fingerprint string
}

type inspection struct {
	Version, Result, Fingerprint string
	Ready                        bool
}

var firmwarePattern = regexp.MustCompile(`(?i)\bNBTevo_([a-z][0-9]{5}[a-z])\b`)

func firmwareName(text string) string {
	m := firmwarePattern.FindStringSubmatch(text)
	if len(m) == 2 {
		return "NBTevo_" + strings.ToUpper(m[1])
	}
	return ""
}

func sshConnect(in vehicleInput) (*ssh.Client, net.Conn, string, error) {
	config := &ssh.ClientConfig{
		User: "root",
		Config: ssh.Config{
			KeyExchanges: append(append([]string{}, ssh.SupportedAlgorithms().KeyExchanges...),
				"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"),
			Ciphers: append(append([]string{}, ssh.SupportedAlgorithms().Ciphers...), "aes128-cbc", "aes256-cbc", "3des-cbc"),
			MACs:    append(append([]string{}, ssh.SupportedAlgorithms().MACs...), "hmac-sha1", "hmac-sha1-96"),
		},
		HostKeyAlgorithms: append(append([]string{}, ssh.SupportedAlgorithms().HostKeys...), "ssh-rsa", "ssh-dss"),
	}
	if in.Fingerprint != "" {
		config.Auth = []ssh.AuthMethod{ssh.Password("ts&SK412")}
	}
	var observed string
	config.HostKeyCallback = func(_ string, _ net.Addr, key ssh.PublicKey) error {
		observed = ssh.FingerprintSHA256(key)
		if observed != in.Fingerprint {
			return errors.New("SSH fingerprint has not been confirmed")
		}
		return nil
	}
	c, err := enetDial(in.Local, in.Head, "22", 4*time.Second)
	if err != nil {
		return nil, nil, "", fmt.Errorf("could not reach head unit SSH: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	conn, channels, requests, err := ssh.NewClientConn(c, net.JoinHostPort(in.Head, "22"), config)
	if err != nil {
		c.Close()
		return nil, nil, observed, err
	}
	return ssh.NewClient(conn, channels, requests), c, observed, nil
}

type remote struct {
	client *ssh.Client
	socket net.Conn
}

type bounded struct {
	data  bytes.Buffer
	limit int
}

func (b *bounded) Write(p []byte) (int, error) {
	if b.data.Len()+len(p) > b.limit {
		return 0, errors.New("SSH response exceeded expected size")
	}
	return b.data.Write(p)
}

func (r remote) run(cmd string, input []byte, limit int) ([]byte, error) {
	_ = r.socket.SetDeadline(time.Now().Add(8 * time.Second))
	s, err := r.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	out, stderr := bounded{limit: limit}, bounded{limit: 2048}
	s.Stdin = bytes.NewReader(input)
	s.Stdout, s.Stderr = &out, &stderr
	if err = s.Run(cmd); err != nil {
		return nil, err
	}
	return out.data.Bytes(), nil
}

type remoteRunner interface {
	run(cmd string, input []byte, limit int) ([]byte, error)
}
