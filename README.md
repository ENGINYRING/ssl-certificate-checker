[![ENGINYRING](https://cdn.enginyring.com/img/logo_dark.png)](https://www.enginyring.com)

# SSL Certificate Checker

**Standalone BASH SSL Certificate Validator** - An automated bash script to check, validate, and analyze SSL/TLS certificates for any domain with comprehensive security analysis.

## 🚀 Features

- **Comprehensive SSL Analysis**: Validates certificates, expiration dates, and security configurations
- **OS Detection**: Automatically detects Linux distributions and macOS
- **Automatic Dependency Management**: Checks and optionally installs required packages
- **SSRF Protection**: Blocks access to private and reserved IP ranges
- **Rate Limiting**: Prevents abuse with configurable rate limits (10 checks per 5 minutes)
- **Smart Caching**: 1-hour cache to reduce repeated queries
- **Security Checks**: 
  - Weak signature algorithm detection (MD5, SHA1)
  - Key strength validation (RSA < 2048 bits)
  - Self-signed certificate detection
  - Hostname mismatch detection
  - Certificate Transparency verification
  - Wildcard certificate identification
- **Export Options**: JSON, CSV, and text format support
- **Color-Coded Output**: Beautiful terminal output with status indicators
- **Interactive Mode**: User-friendly prompts and confirmations

## 📋 Prerequisites

- Linux or macOS operating system
- Bash 4.0 or higher
- Root/sudo access for installing dependencies (if needed)
- Internet connection for checking certificates
- The script will prompt to install required packages if missing:
  - `openssl`
  - `bc`
  - `dig` or `host` (dnsutils/bind-utils)
  - `jq` (optional but recommended)

## 🔧 Installation

```
# Download the script
wget -O ssl_checker.sh https://raw.githubusercontent.com/ENGINYRING/ssl-certificate-checker/main/ssl_checker.sh

# Make the script executable
chmod +x ssl_checker.sh
```

## 📖 Usage

### Interactive Mode

Run the script without any arguments to enter interactive mode:

```
./ssl_checker.sh
```

You'll be prompted to enter:
- **Domain Name**: The domain to check (e.g., example.com)

### Command-Line Mode

```
./ssl_checker.sh <domain>
```

**Parameters:**
1. `domain` - (Required) Domain name to check (without https:// or www)

## 💡 Examples

### Check Google's SSL Certificate

```
./ssl_checker.sh google.com
```

### Check GitHub's SSL Certificate

```
./ssl_checker.sh github.com
```

### Check Your Own Domain

```
./ssl_checker.sh yourdomain.com
```

### Check with Subdomain

```
./ssl_checker.sh api.example.com
```

## 🔄 What the Script Does

1. **Validates Dependencies**: Checks for required packages and offers to install them
2. **Validates Domain Input**: Sanitizes and validates domain name format
3. **SSRF Protection**: Resolves domain and blocks private IP ranges
4. **Retrieves Certificate**: 
   - Connects to domain:443 via OpenSSL
   - Extracts certificate chain
   - Supports SNI (Server Name Indication)
5. **Parses Certificate Data**:
   - Validity dates and expiration
   - Issuer and organization details
   - Subject Alternative Names (SANs)
   - Key size and algorithm
   - Signature algorithm
   - Serial number
6. **Security Analysis**:
   - Detects weak cryptographic standards
   - Validates hostname matching
   - Checks Certificate Transparency logs
   - Identifies self-signed certificates
7. **Displays Results**: Color-coded terminal output with recommendations
8. **Optional Export**: Save results to JSON, CSV, or text file

## 📊 Certificate Information Displayed

### Validity Period
- Issue date
- Expiration date
- Days remaining until expiration
- Certificate age

### Certificate Details
- Common Name (CN)
- Issuer information
- Organization
- Certificate type (DV/OV/EV)

### Subject Alternative Names
- All domains covered by the certificate
- Displays up to 15 SANs (with count of additional)

### Security Analysis
- Key strength (RSA bits, EC curve)
- Signature algorithm
- CA-signed vs Self-signed
- Wildcard certificate detection
- Hostname match verification
- Certificate Transparency status

## 📤 Export Options

After checking a certificate, you can export data in three formats:

### JSON Export
```
Export certificate data? [y/N] y
Export format (json/csv/txt) [json]: json
```
Output: `~/.ssl-checker/ssl-cert-example.com-1234567890.json`

### CSV Export
```
Export certificate data? [y/N] y
Export format (json/csv/txt) [json]: csv
```
Output: `~/.ssl-checker/ssl-cert-example.com-1234567890.csv`

### Text Export
```
Export certificate data? [y/N] y
Export format (json/csv/txt) [json]: txt
```
Output: `~/.ssl-checker/ssl-cert-example.com-1234567890.txt`

## 🗂️ Data Storage

All script data is stored in `~/.ssl-checker/`:

```
~/.ssl-checker/
├── cache/                          # Cached certificate data
│   ├── example.com.pem            # Raw certificate
│   ├── example.com.txt            # Parsed certificate text
│   └── example.com.cache          # Cached results
├── rate_limits.txt                 # Rate limiting tracking
└── ssl-cert-*.{json,csv,txt}      # Exported certificate data
```

## 🔐 Security Features

### SSRF Protection
The script blocks connections to private and reserved IP ranges:
- **10.0.0.0/8** - Private Class A
- **172.16.0.0/12** - Private Class B
- **192.168.0.0/16** - Private Class C
- **127.0.0.0/8** - Loopback
- **169.254.0.0/16** - Link-local

### Rate Limiting
- **Default**: 10 checks per 5 minutes per user
- Tracks by username and domain
- Automatic cleanup of old entries

### Caching
- **Duration**: 1 hour per domain
- Reduces server load
- Speeds up repeated checks

## 🐛 Troubleshooting

### Certificate Download Fails

```
✗ Failed to retrieve SSL certificate
  Possible reasons:
  -  Server may be unreachable
  -  Firewall blocking port 443
  -  No SSL/TLS service on port 443
  -  SSL handshake failed
```

**Solutions:**
- Verify domain is correct and accessible
- Check firewall rules
- Ensure port 443 is open
- Try manually: `openssl s_client -connect domain.com:443 -servername domain.com`

### Domain Resolution Fails

```
✗ Could not resolve domain name: example.com
```

**Solutions:**
- Check DNS settings
- Verify domain exists
- Try with different DNS server: `dig @8.8.8.8 example.com`

### Private IP Range Blocked

```
✗ Access to private or reserved IP ranges is not allowed: 192.168.1.1
```

**Solutions:**
- This is intentional SSRF protection
- The domain resolves to a private IP
- Cannot check internal/private domains

### Missing Dependencies

```
⚠ Missing dependencies detected
The following packages need to be installed:
  -  jq
  -  dnsutils
```

**Solutions:**
- Accept the installation prompt
- Or install manually based on your OS

### Rate Limit Exceeded

```
✗ Rate limit exceeded. Please wait a few minutes and try again.
```

**Solutions:**
- Wait 5 minutes before trying again
- Or clear rate limits: `rm ~/.ssl-checker/rate_limits.txt`

## 🎨 Output Color Codes

- 🟢 **Green**: Valid certificate, strong security
- 🟡 **Yellow**: Warnings, expiring soon, self-signed
- 🔴 **Red**: Expired, invalid, weak security
- 🔵 **Blue**: Informational messages
- 🔷 **Cyan**: Section headers

## 🔧 Advanced Usage

### Batch Checking Multiple Domains

```
#!/bin/bash
domains=("google.com" "github.com" "stackoverflow.com")
for domain in "${domains[@]}"; do
    ./ssl_checker.sh "$domain"
    echo "---"
done
```

### Automated Export to JSON

```
#!/bin/bash
echo "y" | ./ssl_checker.sh example.com | grep -A 100 "SSL Certificate Information"
```

### Check and Alert on Expiring Certificates

```
#!/bin/bash
./ssl_checker.sh example.com | grep "Days Remaining" | awk '{if ($3 < 30) print "WARNING: Certificate expires in " $3 " days"}'
```

### Clear Cache for Fresh Check

```
rm -f ~/.ssl-checker/cache/example.com.*
./ssl_checker.sh example.com
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 🔗 Useful Links

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Certificate Transparency](https://certificate.transparency.dev/)
- [SSL Labs Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
- [Let's Encrypt](https://letsencrypt.org/)

## 👤 Author

**ENGINYRING**

- GitHub: [@ENGINYRING](https://github.com/ENGINYRING)
- [**ENGINYRING**: Hosting • VPS • Domains • CAD/BIM](https://www.enginyring.com)

---

⭐ If you find this project helpful, please give it a star!

* * * 
© 2025 ENGINYRING. All rights reserved.  
* * *

[Web hosting](https://www.enginyring.com/en/webhosting) | [VPS hosting](https://www.enginyring.com/en/virtual-servers) | [Free DevOps tools](https://www.enginyring.com/tools)


