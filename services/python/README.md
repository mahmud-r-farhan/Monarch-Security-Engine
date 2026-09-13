# Monarch Python Power-Up Service

Optional Python microservice that enhances Monarch Security Engine with advanced checks that benefit from Python's security ecosystem.

## Features

- **High-entropy secret detection** using Shannon entropy analysis
- **Secret pattern matching** for AWS, GitHub, OpenAI, Stripe, private keys
- **Vulnerable library detection** (jQuery, Lodash, Angular, React CVEs)
- **Supply chain checks**

## Usage

### Standalone scan

```bash
python3 advanced_scanner.py --target https://example.com
python3 advanced_scanner.py --html-file ./page.html --format text
```

### Microservice mode (for Node.js integration)

```bash
python3 advanced_scanner.py --server --port 5001
# Then POST to http://localhost:5001/analyze
# { "target": "https://example.com", "html": "<html>..." }
```

### Install optional deps

```bash
pip install -r requirements.txt
```

## Integration with Node.js

Monarch Node.js server can call this service via:

```js
// In src/modules/python-bridge.js (future)
const result = await fetch('http://localhost:5001/analyze', {
  method: 'POST',
  body: JSON.stringify({ target, html })
}).then(r => r.json());
```

This service is **optional** - Monarch core works 100% without it.
