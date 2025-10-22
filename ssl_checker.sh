#!/usr/bin/env bash

#############################################################################
# SSL Certificate Checker - Standalone BASH Version
#############################################################################
# 
# Repository: https://github.com/ENGINYRING/ssl-certificate-checker
# Author: ENGINYRING (https://www.enginyring.com)
# License: MIT
# Version: 1.0.0
#
# Description:
#   Professional SSL/TLS certificate validator with comprehensive security
#   analysis, automatic dependency management, and export capabilities.
#
# Features:
#   - Multi-OS support (Debian/Ubuntu, RHEL/Fedora, Arch, Alpine, macOS)
#   - Automatic dependency detection and installation
#   - SSRF protection and rate limiting
#   - Certificate security analysis
#   - Export to JSON/CSV/TXT formats
#   - Smart caching system
#
# Usage:
#   ./ssl_checker.sh [domain]
#   ./ssl_checker.sh --help
#   ./ssl_checker.sh --version
#
#############################################################################

set -euo pipefail

# Script information
readonly SCRIPT_NAME="SSL Certificate Checker"
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_AUTHOR="ENGINYRING"
readonly SCRIPT_URL="https://github.com/ENGINYRING/ssl-certificate-checker"
readonly AUTHOR_URL="https://www.enginyring.com"

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Script configuration
readonly RATE_LIMIT_CHECKS=10
readonly RATE_LIMIT_WINDOW=300  # 5 minutes
readonly CACHE_TTL=3600         # 1 hour
readonly MAX_CACHE_ENTRIES=50

# Directories
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DATA_DIR="${HOME}/.ssl-checker"
readonly CACHE_DIR="${DATA_DIR}/cache"
readonly RATE_LIMIT_FILE="${DATA_DIR}/rate_limits.txt"

# Create data directories
mkdir -p "${DATA_DIR}" "${CACHE_DIR}"

#############################################################################
# Help and Version Functions
#############################################################################

show_help() {
    cat << EOF
${CYAN}${BOLD}${SCRIPT_NAME} v${SCRIPT_VERSION}${NC}
Professional SSL/TLS certificate validator

${BOLD}USAGE:${NC}
    $(basename "$0") [OPTIONS] [DOMAIN]

${BOLD}OPTIONS:${NC}
    -h, --help              Show this help message
    -v, --version           Show version information
    -e, --export FORMAT     Auto-export results (json|csv|txt)
    -o, --output FILE       Specify output file for export
    -n, --no-cache          Bypass cache and fetch fresh data
    -q, --quiet             Minimal output (errors only)
    --no-color              Disable colored output

${BOLD}ARGUMENTS:${NC}
    DOMAIN                  Domain name to check (e.g., example.com)
                           Omit to enter interactive mode

${BOLD}EXAMPLES:${NC}
    $(basename "$0") google.com
    $(basename "$0") github.com --export json
    $(basename "$0") example.com -e json -o /tmp/cert.json
    $(basename "$0") --no-cache cloudflare.com

${BOLD}DATA STORAGE:${NC}
    Configuration:  ${DATA_DIR}
    Cache:          ${CACHE_DIR}
    Exports:        ${DATA_DIR}/ssl-cert-*.{json,csv,txt}

${BOLD}AUTHOR:${NC}
    ${SCRIPT_AUTHOR}
    ${AUTHOR_URL}

${BOLD}REPOSITORY:${NC}
    ${SCRIPT_URL}

${BOLD}LICENSE:${NC}
    MIT License - See LICENSE file for details

${BOLD}NEED HOSTING WITH FREE SSL?${NC}
    Web Hosting: ${AUTHOR_URL}/en/webhosting
    VPS Servers: ${AUTHOR_URL}/en/virtual-servers
    Free Tools:  ${AUTHOR_URL}/tools

EOF
}

show_version() {
    cat << EOF
${SCRIPT_NAME} version ${SCRIPT_VERSION}

Copyright (c) 2025 ${SCRIPT_AUTHOR}
License: MIT License
Repository: ${SCRIPT_URL}

This is free software; you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
EOF
}

#############################################################################
# Utility Functions
#############################################################################

print_header() {
    echo -e "${CYAN}${BOLD}" >&2
    echo "╔════════════════════════════════════════════════════════════════════╗" >&2
    echo "║       SSL Certificate Checker v${SCRIPT_VERSION} - by ENGINYRING         ║" >&2
    echo "╚════════════════════════════════════════════════════════════════════╝" >&2
    echo -e "${NC}" >&2
}

print_footer() {
    echo "" >&2
    echo -e "${CYAN}─────────────────────────────────────────────────────────────────${NC}" >&2
    echo -e "${BOLD}Need professional hosting with automatic SSL certificates?${NC}" >&2
    echo -e "  Web Hosting: ${BLUE}${AUTHOR_URL}/en/webhosting${NC}" >&2
    echo -e "  VPS Servers: ${BLUE}${AUTHOR_URL}/en/virtual-servers${NC}" >&2
    echo -e "  Free Tools:  ${BLUE}${AUTHOR_URL}/tools${NC}" >&2
    echo -e "${CYAN}─────────────────────────────────────────────────────────────────${NC}" >&2
    echo "" >&2
}

print_success() {
    echo -e "${GREEN}✓${NC} $1" >&2
}

print_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1" >&2
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1" >&2
}

print_section() {
    echo "" >&2
    echo -e "${CYAN}${BOLD}═══ $1 ═══${NC}" >&2
}

#############################################################################
# OS Detection and Package Management
#############################################################################

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME="${ID}"
        OS_VERSION="${VERSION_ID:-unknown}"
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        OS_NAME="macos"
        OS_VERSION="$(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
    else
        OS_NAME="unknown"
        OS_VERSION="unknown"
    fi
}

get_package_manager() {
    case "${OS_NAME}" in
        ubuntu|debian|linuxmint|pop)
            echo "apt"
            ;;
        rhel|centos|fedora|rocky|almalinux)
            if command -v dnf &>/dev/null; then
                echo "dnf"
            else
                echo "yum"
            fi
            ;;
        arch|manjaro|endeavouros)
            echo "pacman"
            ;;
        alpine)
            echo "apk"
            ;;
        opensuse*|sles)
            echo "zypper"
            ;;
        macos)
            echo "brew"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

check_dependencies() {
    local missing_deps=()
    local deps=("openssl" "bc")
    
    # Check for DNS resolution tool
    if ! command -v dig &>/dev/null && ! command -v host &>/dev/null; then
        case "${OS_NAME}" in
            ubuntu|debian|linuxmint|pop)
                missing_deps+=("dnsutils")
                ;;
            rhel|centos|fedora|rocky|almalinux)
                missing_deps+=("bind-utils")
                ;;
            arch|manjaro|endeavouros)
                missing_deps+=("bind-tools")
                ;;
            alpine)
                missing_deps+=("bind-tools")
                ;;
            opensuse*|sles)
                missing_deps+=("bind-utils")
                ;;
            macos)
                # dig is built-in on macOS
                ;;
        esac
    fi
    
    # Check for jq (optional but recommended)
    if ! command -v jq &>/dev/null; then
        deps+=("jq")
    fi
    
    # Check core dependencies
    for dep in "${deps[@]}"; do
        if ! command -v "${dep}" &>/dev/null; then
            missing_deps+=("${dep}")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo "${missing_deps[@]}"
        return 1
    fi
    return 0
}

install_dependencies() {
    local pkg_manager
    pkg_manager="$(get_package_manager)"
    
    if [[ "${pkg_manager}" == "unknown" ]]; then
        print_error "Could not detect package manager for your OS: ${OS_NAME}"
        print_info "Please install these packages manually: $*"
        return 1
    fi
    
    print_section "Missing Dependencies Detected"
    echo -e "${YELLOW}The following packages need to be installed:${NC}" >&2
    for pkg in "$@"; do
        echo "  • ${pkg}" >&2
    done
    echo "" >&2
    
    echo -n "Install missing dependencies? [Y/n] " >&2
    read -r response
    response="${response:-Y}"
    
    if [[ ! "${response}" =~ ^[Yy]$ ]]; then
        print_error "Cannot proceed without required dependencies."
        exit 1
    fi
    
    print_info "Installing dependencies using ${pkg_manager}..."
    
    case "${pkg_manager}" in
        apt)
            sudo apt-get update || true
            sudo apt-get install -y "$@"
            ;;
        dnf)
            sudo dnf install -y "$@"
            ;;
        yum)
            sudo yum install -y "$@"
            ;;
        pacman)
            sudo pacman -Sy --noconfirm "$@"
            ;;
        apk)
            sudo apk add --no-cache "$@"
            ;;
        zypper)
            sudo zypper install -y "$@"
            ;;
        brew)
            brew install "$@"
            ;;
    esac
    
    if [[ $? -eq 0 ]]; then
        print_success "Dependencies installed successfully!"
    else
        print_error "Failed to install dependencies. Please install manually."
        exit 1
    fi
}

#############################################################################
# Rate Limiting
#############################################################################

check_rate_limit() {
    local client_key="$1"
    local current_time
    current_time=$(date +%s)
    local cutoff_time=$((current_time - RATE_LIMIT_WINDOW))
    
    # Clean old entries and count recent checks
    if [[ -f "${RATE_LIMIT_FILE}" ]]; then
        local temp_file="${RATE_LIMIT_FILE}.tmp"
        awk -v cutoff="${cutoff_time}" -v key="${client_key}" '
            $2 >= cutoff { print }
        ' "${RATE_LIMIT_FILE}" > "${temp_file}"
        mv "${temp_file}" "${RATE_LIMIT_FILE}"
        
        local check_count
        check_count=$(awk -v key="${client_key}" '$1 == key' "${RATE_LIMIT_FILE}" | wc -l)
        
        if [[ ${check_count} -ge ${RATE_LIMIT_CHECKS} ]]; then
            return 1
        fi
    fi
    
    # Add new entry
    echo "${client_key} ${current_time}" >> "${RATE_LIMIT_FILE}"
    return 0
}

#############################################################################
# Domain Validation and SSRF Protection
#############################################################################

validate_domain() {
    local domain="$1"
    
    # Remove protocol prefix
    domain="${domain#http://}"
    domain="${domain#https://}"
    
    # Remove www prefix
    domain="${domain#www.}"
    
    # Remove trailing slash
    domain="${domain%/}"
    
    # Remove port specification
    domain="${domain%:*}"
    
    # Basic domain format validation
    if [[ ! "${domain}" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        print_error "Invalid domain format: ${domain}"
        print_info "Example: example.com"
        return 1
    fi
    
    echo "${domain}"
    return 0
}

check_ssrf() {
    local domain="$1"
    local ip
    
    # Resolve domain to IP
    if command -v dig &>/dev/null; then
        ip=$(dig +short "${domain}" A | head -n1)
    elif command -v host &>/dev/null; then
        ip=$(host "${domain}" | awk '/has address/ { print $4 ; exit }')
    else
        print_error "No DNS resolution tool available (dig or host)"
        return 1
    fi
    
    if [[ -z "${ip}" ]] || [[ ! "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_error "Could not resolve domain name: ${domain}"
        return 1
    fi
    
    # Check for private/reserved IP ranges
    local octets
    IFS='.' read -ra octets <<< "${ip}"
    local first="${octets[0]}"
    local second="${octets[1]}"
    
    # Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    # Loopback: 127.0.0.0/8
    # Link-local: 169.254.0.0/16
    if [[ ${first} -eq 10 ]] || \
       [[ ${first} -eq 127 ]] || \
       [[ ${first} -eq 169 && ${second} -eq 254 ]] || \
       [[ ${first} -eq 172 && ${second} -ge 16 && ${second} -le 31 ]] || \
       [[ ${first} -eq 192 && ${second} -eq 168 ]]; then
        print_error "Access to private or reserved IP ranges is not allowed: ${ip}"
        return 1
    fi
    
    print_success "Domain resolved to: ${ip}"
    return 0
}

#############################################################################
# SSL Certificate Retrieval and Parsing
#############################################################################

get_ssl_certificate() {
    local domain="$1"
    local cert_file="${CACHE_DIR}/${domain}.pem"
    local cert_text_file="${CACHE_DIR}/${domain}.txt"
    
    print_info "Connecting to ${domain}:443..."
    
    # Retrieve certificate
    if ! timeout 30 openssl s_client -connect "${domain}:443" \
        -servername "${domain}" -showcerts </dev/null 2>/dev/null | \
        openssl x509 -outform PEM > "${cert_file}" 2>/dev/null; then
        print_error "Failed to retrieve SSL certificate"
        print_info "Possible reasons:"
        echo "  • Server may be unreachable" >&2
        echo "  • Firewall blocking port 443" >&2
        echo "  • No SSL/TLS service on port 443" >&2
        echo "  • SSL handshake failed" >&2
        return 1
    fi
    
    # Parse certificate to text
    if ! openssl x509 -in "${cert_file}" -text -noout > "${cert_text_file}" 2>/dev/null; then
        print_error "Failed to parse SSL certificate"
        return 1
    fi
    
    print_success "Certificate retrieved successfully"
    echo "${cert_file}"
    return 0
}

parse_certificate() {
    local cert_file="$1"
    local domain="$2"
    local cert_text_file="${cert_file%.pem}.txt"
    
    declare -A cert_info
    
    # Get dates
    cert_info[valid_from]=$(openssl x509 -in "${cert_file}" -noout -startdate | cut -d= -f2)
    cert_info[valid_to]=$(openssl x509 -in "${cert_file}" -noout -enddate | cut -d= -f2)
    
    # Convert to epoch
    cert_info[valid_from_epoch]=$(date -d "${cert_info[valid_from]}" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "${cert_info[valid_from]}" +%s 2>/dev/null)
    cert_info[valid_to_epoch]=$(date -d "${cert_info[valid_to]}" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "${cert_info[valid_to]}" +%s 2>/dev/null)
    
    local current_time
    current_time=$(date +%s)
    
    # Calculate validity
    if [[ ${current_time} -ge ${cert_info[valid_from_epoch]} && ${current_time} -le ${cert_info[valid_to_epoch]} ]]; then
        cert_info[is_valid]="true"
    else
        cert_info[is_valid]="false"
    fi
    
    # Days remaining
    cert_info[days_remaining]=$(( (cert_info[valid_to_epoch] - current_time) / 86400 ))
    
    # Certificate age in years
    cert_info[age_years]=$(echo "scale=1; (${current_time} - ${cert_info[valid_from_epoch]}) / 31557600" | bc)
    
    # Common Name
    cert_info[common_name]=$(openssl x509 -in "${cert_file}" -noout -subject | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,]*\).*/\1/p')
    
    # Issuer
    cert_info[issuer_cn]=$(openssl x509 -in "${cert_file}" -noout -issuer | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,]*\).*/\1/p')
    cert_info[issuer_o]=$(openssl x509 -in "${cert_file}" -noout -issuer | sed -n 's/.*O[[:space:]]*=[[:space:]]*\([^,]*\).*/\1/p')
    
    # Organization
    cert_info[organization]=$(openssl x509 -in "${cert_file}" -noout -subject | sed -n 's/.*O[[:space:]]*=[[:space:]]*\([^,]*\).*/\1/p')
    [[ -z "${cert_info[organization]}" ]] && cert_info[organization]="N/A"
    
    # SANs (Subject Alternative Names)
    local sans
    sans=$(openssl x509 -in "${cert_file}" -noout -text | grep -A1 "Subject Alternative Name" | tail -n1 | tr ',' '\n' | sed 's/DNS://g' | sed 's/^[[:space:]]*//' | tr '\n' ',' | sed 's/,$//')
    cert_info[sans]="${sans}"
    cert_info[san_count]=$(echo "${sans}" | tr ',' '\n' | grep -c . || echo 0)
    
    # Serial Number
    cert_info[serial]=$(openssl x509 -in "${cert_file}" -noout -serial | cut -d= -f2 | sed 's/\(..\)/\1:/g' | sed 's/:$//')
    
    # Signature Algorithm
    cert_info[signature_algorithm]=$(openssl x509 -in "${cert_file}" -noout -text | grep "Signature Algorithm" | head -n1 | awk '{print $3}')
    
    # Check for weak signature
    if [[ "${cert_info[signature_algorithm]}" =~ (md5|sha1) ]]; then
        cert_info[weak_signature]="true"
    else
        cert_info[weak_signature]="false"
    fi
    
    # Public Key Info
    local pubkey_info
    pubkey_info=$(openssl x509 -in "${cert_file}" -noout -text | grep -A1 "Public Key Algorithm")
    
    # Key size and type
    if echo "${pubkey_info}" | grep -q "rsaEncryption"; then
        local key_bits
        key_bits=$(openssl x509 -in "${cert_file}" -noout -text | grep "Public-Key:" | sed 's/[^0-9]//g')
        cert_info[key_size]="${key_bits} bit RSA"
        if [[ ${key_bits} -lt 2048 ]]; then
            cert_info[weak_key]="true"
        else
            cert_info[weak_key]="false"
        fi
    elif echo "${pubkey_info}" | grep -q "id-ecPublicKey"; then
        local key_bits
        key_bits=$(openssl x509 -in "${cert_file}" -noout -text | grep "ASN1 OID" | awk '{print $3}')
        cert_info[key_size]="EC ${key_bits}"
        cert_info[weak_key]="false"
    else
        cert_info[key_size]="Unknown"
        cert_info[weak_key]="unknown"
    fi
    
    # Self-signed detection
    local subject_cn="${cert_info[common_name]}"
    local issuer_cn="${cert_info[issuer_cn]}"
    if [[ "${subject_cn}" == "${issuer_cn}" ]]; then
        cert_info[is_self_signed]="true"
    else
        cert_info[is_self_signed]="false"
    fi
    
    # Wildcard detection
    if [[ "${cert_info[common_name]}" =~ ^\*\. ]] || [[ "${sans}" =~ \*\. ]]; then
        cert_info[is_wildcard]="true"
    else
        cert_info[is_wildcard]="false"
    fi
    
    # Hostname mismatch detection
    cert_info[hostname_mismatch]="true"
    if [[ "${cert_info[common_name]}" == "${domain}" ]]; then
        cert_info[hostname_mismatch]="false"
    else
        # Check SANs
        IFS=',' read -ra san_array <<< "${sans}"
        for san in "${san_array[@]}"; do
            san=$(echo "${san}" | xargs) # trim whitespace
            if [[ "${san}" == "${domain}" ]]; then
                cert_info[hostname_mismatch]="false"
                break
            fi
            # Wildcard matching
            if [[ "${san}" =~ ^\*\. ]]; then
                local wildcard_domain="${san#\*.}"
                if [[ "${domain}" == *".${wildcard_domain}" ]]; then
                    cert_info[hostname_mismatch]="false"
                    break
                fi
            fi
        done
    fi
    
    # Certificate Transparency
    if grep -q "CT Precertificate SCTs" "${cert_text_file}" 2>/dev/null; then
        cert_info[has_sct]="true"
    else
        cert_info[has_sct]="false"
    fi
    
    # Certificate type detection (basic)
    if grep -q "2.23.140.1.1" "${cert_text_file}" 2>/dev/null; then
        cert_info[cert_type]="EV (Extended Validation)"
    elif grep -q "2.23.140.1.2.2" "${cert_text_file}" 2>/dev/null; then
        cert_info[cert_type]="OV (Organization Validated)"
    elif [[ "${cert_info[organization]}" != "N/A" ]]; then
        cert_info[cert_type]="OV (Organization Validated) - inferred"
    else
        cert_info[cert_type]="DV (Domain Validated)"
    fi
    
    # Export to global associative array
    for key in "${!cert_info[@]}"; do
        CERT_INFO["${key}"]="${cert_info[${key}]}"
    done
}

#############################################################################
# Display Functions
#############################################################################

display_certificate_info() {
    local domain="$1"
    
    print_section "SSL Certificate Information"
    
    # Status determination
    local status_icon status_message status_color
    local current_time
    current_time=$(date +%s)
    
    if [[ "${CERT_INFO[is_valid]}" == "true" ]]; then
        if [[ ${CERT_INFO[days_remaining]} -le 30 ]]; then
            status_icon="⚠"
            status_message="Certificate Expiring Soon"
            status_color="${YELLOW}"
        else
            status_icon="✓"
            status_message="Certificate Valid"
            status_color="${GREEN}"
        fi
    elif [[ ${current_time} -gt ${CERT_INFO[valid_to_epoch]} ]]; then
        status_icon="✗"
        status_message="Certificate Expired"
        status_color="${RED}"
    elif [[ ${current_time} -lt ${CERT_INFO[valid_from_epoch]} ]]; then
        status_icon="⚠"
        status_message="Certificate Not Yet Valid"
        status_color="${YELLOW}"
    else
        status_icon="✗"
        status_message="Certificate Invalid"
        status_color="${RED}"
    fi
    
    echo -e "${status_color}${BOLD}${status_icon} ${status_message} - ${domain}${NC}" >&2
    echo "" >&2
    
    # Validity Period
    echo -e "${CYAN}${BOLD}📅 Validity Period${NC}" >&2
    echo -e "  Issue Date:      $(date -d "@${CERT_INFO[valid_from_epoch]}" "+%b %d, %Y" 2>/dev/null || date -r "${CERT_INFO[valid_from_epoch]}" "+%b %d, %Y" 2>/dev/null)" >&2
    echo -e "  Expiration:      $(date -d "@${CERT_INFO[valid_to_epoch]}" "+%b %d, %Y" 2>/dev/null || date -r "${CERT_INFO[valid_to_epoch]}" "+%b %d, %Y" 2>/dev/null)" >&2
    
    local days_color="${GREEN}"
    [[ ${CERT_INFO[days_remaining]} -le 30 ]] && days_color="${RED}"
    echo -e "  Days Remaining:  ${days_color}${CERT_INFO[days_remaining]}${NC}" >&2
    echo -e "  Certificate Age: ${CERT_INFO[age_years]} years" >&2
    echo "" >&2
    
    # Certificate Details
    echo -e "${CYAN}${BOLD}📄 Certificate Details${NC}" >&2
    echo -e "  Common Name:     ${CERT_INFO[common_name]}" >&2
    echo -e "  Issuer:          ${CERT_INFO[issuer_cn]}" >&2
    [[ "${CERT_INFO[issuer_o]}" != "" ]] && echo -e "  Issuer Org:      ${CERT_INFO[issuer_o]}" >&2
    echo -e "  Organization:    ${CERT_INFO[organization]}" >&2
    echo -e "  Type:            ${CERT_INFO[cert_type]}" >&2
    echo "" >&2
    
    # Subject Alternative Names
    if [[ ${CERT_INFO[san_count]} -gt 0 ]]; then
        echo -e "${CYAN}${BOLD}🌐 Subject Alternative Names (${CERT_INFO[san_count]})${NC}" >&2
        IFS=',' read -ra san_array <<< "${CERT_INFO[sans]}"
        local count=0
        for san in "${san_array[@]}"; do
            if [[ ${count} -lt 15 ]]; then
                echo -e "  • ${san}" >&2
                ((count++))
            fi
        done
        if [[ ${CERT_INFO[san_count]} -gt 15 ]]; then
            echo -e "  ${YELLOW}... and $((CERT_INFO[san_count] - 15)) more${NC}" >&2
        fi
        echo "" >&2
    fi
    
    # Security Analysis
    echo -e "${CYAN}${BOLD}🔒 Security Analysis${NC}" >&2
    
    # Key strength
    local key_color="${GREEN}"
    [[ "${CERT_INFO[weak_key]}" == "true" ]] && key_color="${RED}"
    echo -e "  Key Strength:    ${key_color}${CERT_INFO[key_size]}${NC}" >&2
    
    # Signature algorithm
    local sig_color="${GREEN}"
    [[ "${CERT_INFO[weak_signature]}" == "true" ]] && sig_color="${RED}"
    echo -e "  Signature:       ${sig_color}${CERT_INFO[signature_algorithm]}${NC}" >&2
    
    # Self-signed
    local selfsign_color="${GREEN}"
    local selfsign_text="CA-Signed"
    if [[ "${CERT_INFO[is_self_signed]}" == "true" ]]; then
        selfsign_color="${YELLOW}"
        selfsign_text="Self-Signed"
    fi
    echo -e "  Authority:       ${selfsign_color}${selfsign_text}${NC}" >&2
    
    # Wildcard
    local wildcard_text="Standard Certificate"
    [[ "${CERT_INFO[is_wildcard]}" == "true" ]] && wildcard_text="Wildcard Certificate"
    echo -e "  Type:            ${wildcard_text}" >&2
    
    # Hostname match
    local hostname_color="${GREEN}"
    local hostname_text="Hostname Match"
    if [[ "${CERT_INFO[hostname_mismatch]}" == "true" ]]; then
        hostname_color="${RED}"
        hostname_text="Hostname Mismatch"
    fi
    echo -e "  Hostname Check:  ${hostname_color}${hostname_text}${NC}" >&2
    
    # Certificate Transparency
    local ct_color="${GREEN}"
    local ct_text="CT Logged"
    if [[ "${CERT_INFO[has_sct]}" == "false" ]]; then
        ct_color="${YELLOW}"
        ct_text="No CT Logging"
    fi
    echo -e "  Transparency:    ${ct_color}${ct_text}${NC}" >&2
    echo "" >&2
    
    # Additional Info
    echo -e "${CYAN}${BOLD}ℹ️  Additional Information${NC}" >&2
    echo -e "  Serial Number:   ${CERT_INFO[serial]:0:60}..." >&2
    echo "" >&2
    
    # Warnings and recommendations
    if [[ ${CERT_INFO[days_remaining]} -le 60 ]] && [[ "${CERT_INFO[is_valid]}" == "true" ]]; then
        print_warning "Certificate renewal recommended"
    elif [[ ${current_time} -gt ${CERT_INFO[valid_to_epoch]} ]]; then
        print_error "Certificate has expired - immediate renewal required"
    elif [[ "${CERT_INFO[is_self_signed]}" == "true" ]]; then
        print_warning "Self-signed certificate detected - consider using a trusted CA"
    elif [[ "${CERT_INFO[weak_signature]}" == "true" ]] || [[ "${CERT_INFO[weak_key]}" == "true" ]]; then
        print_error "Outdated cryptographic standards detected"
    fi
}

#############################################################################
# Export Functions
#############################################################################

export_certificate_data() {
    local domain="$1"
    local format="$2"
    local output_file="${3:-}"
    
    if [[ -z "${output_file}" ]]; then
        output_file="${DATA_DIR}/ssl-cert-${domain}-$(date +%s).${format}"
    fi
    
    case "${format}" in
        json)
            export_json "${output_file}"
            ;;
        csv)
            export_csv "${output_file}"
            ;;
        txt|text)
            export_text "${output_file}"
            ;;
        *)
            print_error "Unknown export format: ${format}"
            return 1
            ;;
    esac
    
    print_success "Certificate data exported to: ${output_file}"
}

export_json() {
    local output_file="$1"
    
    if command -v jq &>/dev/null; then
        # Use jq for pretty JSON
        {
            echo "{"
            local first=true
            for key in "${!CERT_INFO[@]}"; do
                if [[ "${first}" == "true" ]]; then
                    first=false
                else
                    echo ","
                fi
                printf '  "%s": "%s"' "${key}" "${CERT_INFO[${key}]}"
            done
            echo ""
            echo "}"
        } | jq '.' > "${output_file}"
    else
        # Fallback without jq
        {
            echo "{"
            local first=true
            for key in "${!CERT_INFO[@]}"; do
                if [[ "${first}" == "true" ]]; then
                    first=false
                else
                    echo ","
                fi
                printf '  "%s": "%s"' "${key}" "${CERT_INFO[${key}]}"
            done
            echo ""
            echo "}"
        } > "${output_file}"
    fi
}

export_csv() {
    local output_file="$1"
    
    {
        echo "Property,Value"
        for key in "${!CERT_INFO[@]}"; do
            # Escape commas in values
            local value="${CERT_INFO[${key}]}"
            value="${value//,/ }"
            echo "${key},${value}"
        done
    } > "${output_file}"
}

export_text() {
    local output_file="$1"
    
    {
        echo "SSL Certificate Information"
        echo "=================================================="
        echo ""
        for key in "${!CERT_INFO[@]}"; do
            printf "%-25s: %s\n" "${key}" "${CERT_INFO[${key}]}"
        done
    } > "${output_file}"
}

#############################################################################
# Main Logic
#############################################################################

main() {
    declare -gA CERT_INFO
    local auto_export=""
    local output_file=""
    local use_cache=true
    local DOMAIN_ARG=""
    
    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            -e|--export)
                auto_export="$2"
                shift 2
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -n|--no-cache)
                use_cache=false
                shift
                ;;
            -q|--quiet)
                exec 2>/dev/null
                shift
                ;;
            --no-color)
                RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' WHITE='' BOLD='' NC=''
                shift
                ;;
            -*)
                print_error "Unknown option: $1"
                echo "Use --help for usage information" >&2
                exit 1
                ;;
            *)
                DOMAIN_ARG="$1"
                shift
                ;;
        esac
    done
    
    print_header
    
    # Detect OS
    detect_os
    print_info "Detected OS: ${OS_NAME} ${OS_VERSION}"
    
    # Check dependencies
    local missing_deps
    if ! missing_deps=$(check_dependencies); then
        print_warning "Missing dependencies detected"
        install_dependencies ${missing_deps}
    else
        print_success "All dependencies are installed"
    fi
    
    echo "" >&2
    
    # Get domain input
    local domain
    if [[ -n "${DOMAIN_ARG:-}" ]]; then
        domain="${DOMAIN_ARG}"
    else
        echo -n "Enter domain name (e.g., example.com): " >&2
        read -r domain
    fi
    
    # Validate domain
    if ! domain=$(validate_domain "${domain}"); then
        exit 1
    fi
    
    print_info "Checking SSL certificate for: ${domain}"
    echo "" >&2
    
    # Rate limiting check
    local client_key="ssl_checker_$(whoami)_${domain}"
    if ! check_rate_limit "${client_key}"; then
        print_error "Rate limit exceeded. Please wait a few minutes and try again."
        exit 1
    fi
    
    # SSRF protection
    if ! check_ssrf "${domain}"; then
        exit 1
    fi
    
    # Check cache
    local cache_file="${CACHE_DIR}/${domain}.cache"
    local current_time
    current_time=$(date +%s)
    
    if [[ "${use_cache}" == true ]] && [[ -f "${cache_file}" ]]; then
        local cache_time
        cache_time=$(stat -c %Y "${cache_file}" 2>/dev/null || stat -f %m "${cache_file}" 2>/dev/null)
        if [[ $((current_time - cache_time)) -lt ${CACHE_TTL} ]]; then
            print_info "Using cached certificate data"
            # shellcheck disable=SC1090
            source "${cache_file}"
            display_certificate_info "${domain}"
            
            # Auto-export or ask
            if [[ -n "${auto_export}" ]]; then
                export_certificate_data "${domain}" "${auto_export}" "${output_file}"
            else
                echo "" >&2
                echo -e "${CYAN}╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌${NC}" >&2
                echo -e "${BOLD}📤 Export Options${NC}" >&2
                echo "" >&2
                echo -n "Export certificate data? [y/N]: " >&2
                read -r export_response
                if [[ "${export_response}" =~ ^[Yy]$ ]]; then
                    echo -n "Export format (json/csv/txt) [json]: " >&2
                    read -r export_format
                    export_format="${export_format:-json}"
                    export_certificate_data "${domain}" "${export_format}"
                else
                    echo "" >&2
                    print_info "Export skipped"
                fi
            fi
            
            print_footer
            return 0
        fi
    fi
    
    # Retrieve certificate
    local cert_file
    if ! cert_file=$(get_ssl_certificate "${domain}"); then
        exit 1
    fi
    
    # Parse certificate
    parse_certificate "${cert_file}" "${domain}"
    
    # Cache results
    {
        echo "# Certificate cache for ${domain}"
        echo "# Generated: $(date)"
        for key in "${!CERT_INFO[@]}"; do
            echo "CERT_INFO[${key}]='${CERT_INFO[${key}]}'"
        done
    } > "${cache_file}"
    
    # Display results
    display_certificate_info "${domain}"
    
    # Auto-export or ask
    if [[ -n "${auto_export}" ]]; then
        export_certificate_data "${domain}" "${auto_export}" "${output_file}"
    else
        echo "" >&2
        echo -e "${CYAN}╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌${NC}" >&2
        echo -e "${BOLD}📤 Export Options${NC}" >&2
        echo "" >&2
        echo -n "Export certificate data? [y/N]: " >&2
        read -r export_response
        if [[ "${export_response}" =~ ^[Yy]$ ]]; then
            echo -n "Export format (json/csv/txt) [json]: " >&2
            read -r export_format
            export_format="${export_format:-json}"
            export_certificate_data "${domain}" "${export_format}"
        else
            echo "" >&2
            print_info "Export skipped"
        fi
    fi
    
    print_footer
}

# Run main function
main "$@"
