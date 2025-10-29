# 🔐 passwd-crasher

SSH password cracking tool with multi-threading support and fail2ban protection.

## ✨ Features

- 🔄 Multi-threaded SSH password cracking
- ⏱️ Configurable connection timeout
- 🛡️ Delay between attempts to avoid detection
- 📝 Verbose mode for detailed logging
- 🛑 Graceful shutdown with signal handling
- 🚦 Connection limiting to prevent overwhelming the server
- 🚨 fail2ban detection and automatic delay adjustment

## 📦 Installation

```bash
go build -o passwd-crasher main.go
```

## 🚀 Usage

```bash
./passwd-crasher -p password.txt -u root -t 192.168.1.1
```

### ⚙️ Options

- `-p` : Password file path (one password per line) **[required]**
- `-u` : SSH username **[required]**
- `-t` : Target server address (host:port or host) **[required]**
- `-n` : Number of concurrent threads (default: 1, recommended for SSH)
- `-timeout` : SSH connection timeout (default: 5s)
- `-d` : Delay between connection attempts (default: 5ms, use 5s for fail2ban protection)
- `-v` : Verbose mode (show all attempts)

### 📋 Examples

**Basic usage:**
```bash
./passwd-crasher -p passwords.txt -u root -t 192.168.1.1
```

**With fail2ban protection (5s delay):**
```bash
./passwd-crasher -p passwords.txt -u root -t 192.168.1.1 -d 5s
```

**Custom delay and timeout:**
```bash
./passwd-crasher -p passwords.txt -u root -t 192.168.1.1 -d 2s -timeout 10s
```

**Verbose mode with multiple threads:**
```bash
./passwd-crasher -p passwords.txt -u root -t 192.168.1.1 -n 2 -v
```

**With custom port:**
```bash
./passwd-crasher -p passwords.txt -u root -t 192.168.1.1:2222
```

## 📄 Password File Format

Create a text file with one password per line:

```
password1
password2
password3
admin123
```

## ⚠️ Warning

**FOR TESTING PURPOSES ONLY**

This tool is designed for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Ensure you have proper authorization before using this tool.

## 📜 License

MIT
