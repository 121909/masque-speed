package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"fofa-masque/internal/runner"
	"fofa-masque/internal/tunnel"
	"fofa-masque/internal/web"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	port := flag.Int("port", 0, "WebUI loopback port (0 chooses an available port)")
	noBrowser := flag.Bool("no-browser", false, "do not open the default browser")
	flag.Parse()
	if *port < 0 || *port > 65535 {
		return errors.New("port must be between 0 and 65535")
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("find user config directory: %w", err)
	}
	credentialsPath := filepath.Join(configDir, "masque-speed", "credentials.json")
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		return fmt.Errorf("listen on loopback: %w", err)
	}
	defer listener.Close()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generate session token: %w", err)
	}
	token := hex.EncodeToString(secret)
	scan := runner.New(tunnel.New())
	server := &http.Server{
		Handler:           web.New(scan, token, credentialsPath),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       45 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	address := "http://" + listener.Addr().String() + "/#token=" + token
	fmt.Println("MASQUE Speed · TCP/HTTP2 + UDP/QUIC")
	fmt.Println("WebUI: " + address)
	fmt.Println("仅监听本机；关闭程序或按 Ctrl+C 停止。凭据仅在点击保存时写入：")
	fmt.Println(credentialsPath)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	if !*noBrowser {
		if err := openBrowser(address); err != nil {
			log.Printf("无法自动打开浏览器，请使用上述 WebUI 地址：%v", err)
		}
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case err := <-done:
		scan.Stop()
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-signals:
		scan.Stop()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			status := scan.Snapshot().Status
			if status != "running" && status != "stopping" {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return nil
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
