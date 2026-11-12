// An intentionally narrow Xray distribution: JSON-only, local config-only,
// RAW/REALITY, SOCKS ingress, VLESS, fixed freedom egress and blackhole/router.
// The Xray implementation remains an independent process and MPL-2.0 module.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/json"
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
)

const companionVersion = "opentunnel-xray 26.11.9-otu.1"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(companionVersion, runtime.Version())
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "use version or run -c LOCAL_CONFIG [-test]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("c", "", "local JSON configuration")
	test := fs.Bool("test", false, "validate only, no listeners")
	if fs.Parse(os.Args[2:]) != nil || fs.NArg() != 0 || *config == "" {
		fmt.Fprintln(os.Stderr, "invalid companion arguments")
		os.Exit(2)
	}
	// Never dump key-bearing config or parser errors: they can contain the
	// offending secret value. The host reports stage and exit code instead.
	log.SetOutput(io.Discard)
	f, err := os.Open(*config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration unavailable")
		os.Exit(23)
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		_ = f.Close()
		fmt.Fprintln(os.Stderr, "invalid configuration file")
		os.Exit(23)
	}
	cfg, err := core.LoadConfig("json", io.LimitReader(f, 64<<10))
	_ = f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration rejected")
		os.Exit(23)
	}
	instance, err := core.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration rejected")
		os.Exit(23)
	}
	if *test {
		_ = instance.Close()
		fmt.Println("Configuration OK.")
		return
	}
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		fmt.Fprintln(os.Stderr, "companion startup failed")
		os.Exit(1)
	}
	defer instance.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	debug.SetMemoryLimit(192 << 20)
	<-ctx.Done()
}
