package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

//go:embed index.html
var page embed.FS

func main() {
	noBrowser := flag.Bool("no-browser", false, "print the local app URL for development")
	findCar := flag.Bool("find-car", false, "find ENET gateway and head unit addresses, then exit")
	output := flag.String("output", "", "save the --find-car result to a text file")
	flag.Parse()
	if *findCar {
		os.Exit(printDiscovery(*output))
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var entropy [24]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		listener.Close()
		os.Exit(1)
	}
	prefix := "/" + hex.EncodeToString(entropy[:]) + "/"
	host := listener.Addr().String()
	origin := "http://" + host
	url := origin + prefix
	var operations sync.Mutex
	var collected bundle
	mux := http.NewServeMux()
	html, _ := page.ReadFile("index.html")
	mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host {
			http.Error(w, "Invalid host", 403)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		if r.URL.Path == prefix && r.Method == "GET" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(html)
			return
		}
		if r.Method != "POST" || r.Header.Get("Origin") != origin ||
			!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "Invalid local app request", 403)
			return
		}
		reply := func(value any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(value)
		}
		if !operations.TryLock() {
			reply(inspection{Result: "Another operation is running."})
			return
		}
		defer operations.Unlock()
		switch strings.TrimPrefix(r.URL.Path, prefix) {
		case "discover":
			items, err := discover()
			if err != nil {
				reply(inspection{Result: err.Error()})
				return
			}
			reply(items)
		case "collect":
			collected = bundle{}
			var in struct {
				vehicleInput
				IncludeLibraries bool
			}
			if !readRequest(w, r, &in) {
				reply(inspection{Result: "Invalid connection settings."})
				return
			}
			client, socket, fingerprint, err := sshConnect(in.vehicleInput)
			if err != nil {
				result := inspection{Result: err.Error()}
				if in.Fingerprint != "" && fingerprint == in.Fingerprint {
					result.Result = "SSH login failed. Enable temporary SSH and check that the head unit uses the default root password."
				}
				if fingerprint != "" && fingerprint != in.Fingerprint {
					if in.Fingerprint == "" {
						result.Fingerprint = fingerprint
						result.Result = "Verify this fingerprint against your known SSH connection."
					} else {
						result.Result = "The SSH fingerprint changed. Recheck the head unit address."
					}
				}
				reply(result)
				return
			}
			defer client.Close()
			report, err := collect(remote{client, socket}, in.Version, in.IncludeLibraries)
			if err != nil {
				reply(inspection{Result: err.Error()})
				return
			}
			collected = report
			reply(struct {
				Result, Name string
				Files        []string
			}{"Bundle collected. Review the contents below.", report.Name, report.Files})
		case "download":
			if len(collected.Data) == 0 {
				http.Error(w, "Collect a bundle first", 404)
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", "attachment; filename="+collected.Name)
			_, _ = w.Write(collected.Data)
		case "quit":
			reply(inspection{Result: "Collector closed."})
			time.AfterFunc(300*time.Millisecond, func() { os.Exit(0) })
		default:
			http.NotFound(w, r)
		}
	})
	server := http.Server{Handler: mux, ReadHeaderTimeout: 4 * time.Second, ReadTimeout: 6 * time.Second, WriteTimeout: 4 * time.Minute, IdleTimeout: 35 * time.Second, MaxHeaderBytes: 8192}
	fmt.Println(url)
	if !*noBrowser {
		switch runtime.GOOS {
		case "darwin":
			_ = exec.Command("/usr/bin/open", url).Start()
		case "windows":
			_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start()
		default:
			_ = exec.Command("xdg-open", url).Start()
		}
	}
	_ = server.Serve(listener)
}

func readRequest(w http.ResponseWriter, r *http.Request, dest any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return d.Decode(dest) == nil && d.Decode(new(any)) == io.EOF
}

// On Windows the packaged GUI executable may not have a console, so the
// discovery result can also be written directly to a user-selected file.
func printDiscovery(path string) int {
	items, err := discover()
	var result strings.Builder
	code := 0
	if err != nil {
		fmt.Fprintln(&result, "ENET discovery:", err)
		code = 1
	}
	for _, item := range items {
		head := item.Head
		if head == "" {
			head = "unavailable; check the SSH unlock tool"
		}
		fmt.Fprintf(&result, "Gateway IP: %s\nHead unit SSH IP: %s\nComputer ENET IP: %s\n\n",
			item.Gateway, head, item.Local)
	}
	if path != "" {
		if err := os.WriteFile(path, []byte(result.String()), 0600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	} else {
		fmt.Print(result.String())
	}
	return code
}
