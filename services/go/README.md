# Monarch Go Power-Up Service

High-performance network scanner written in Go, optional enhancement for Monarch Security Engine.

## Features

- **Ultra-fast TCP connect scanner** (1000+ ports/sec with goroutines)
- **Banner grabbing** with service fingerprinting
- **CIDR expansion** and IP range support
- **HTTP microservice mode** for Node.js integration

## Usage

### Standalone

```bash
go run main.go -target 192.168.1.1 -ports 21,22,80,443
go run main.go -target 192.168.1.0/24 -ports 1-1000 -concurrency 200
go run main.go -target 10.0.0.1-50 -ports 22,80,443,3000,8080
```

### Microservice mode

```bash
go run main.go -server -port 5002
# POST http://localhost:5002/scan
# {
#   "host": "192.168.1.1",
#   "ports": [21,22,80,443],
#   "timeoutMs": 1000,
#   "concurrency": 100
# }
```

### Build binary

```bash
go build -o monarch-go main.go
./monarch-go -target 192.168.1.0/24 -ports 1-65535 -concurrency 500
```

## Integration with Node.js

```js
// Future bridge in src/modules/go-bridge.js
const result = await fetch('http://localhost:5002/scan', {
  method: 'POST',
  body: JSON.stringify({ host: '192.168.1.1', portsStr: '21,22,80,443' })
}).then(r => r.json());
```

## Performance

- Scans 1000 ports in ~2-5 seconds (100 concurrency, 1s timeout)
- Memory efficient - goroutine pool with semaphore
- Zero external dependencies

This service is **optional** - Monarch core works without it.
