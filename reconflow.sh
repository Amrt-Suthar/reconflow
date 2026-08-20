#!/usr/bin/env bash
#
# bug_bounty_recon.sh
# Authorized bug-bounty reconnaissance automation.
#
# Core tools:
#   subfinder, dnsx, httpx
#
# Optional tools:
#   assetfinder, amass, katana, nuclei
#
# Example:
#   ./bug_bounty_recon.sh \
#     --domain example.com \
#     --authorized \
#     --active \
#     --rate-limit 10 \
#     --threads 20
#

## Example (Commands to use):
# # Basic passive reconnaissance
# ./bug_bounty_recon.sh --domain example.com --authorized

# # Save results under a custom directory
# ./bug_bounty_recon.sh -d example.com --authorized -o ./results

# # Active crawling with conservative limits
# ./bug_bounty_recon.sh -d example.com --authorized \
#   --active --rate-limit 5 --threads 10 --timeout 15

# # Active scan with restricted nuclei checks
# ./bug_bounty_recon.sh -d example.com --authorized \
#   --active --nuclei --rate-limit 5 --threads 10

# # Resume the target’s latest run
# ./bug_bounty_recon.sh -d example.com --authorized --resume

# # Display usage information
# ./bug_bounty_recon.sh --help

# # Display version
# ./bug_bounty_recon.sh --version

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

VERSION="2.0.0"

DOMAIN=""
OUTPUT_ROOT="./runs"
THREADS=20
RATE_LIMIT=10
TIMEOUT=10
ACTIVE=false
RUN_NUCLEI=false
RESUME=false
AUTHORIZED=false

RUN_DIR=""
LOG_FILE=""

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
BLUE=$'\033[0;34m'
RESET=$'\033[0m'

usage() {
    cat <<EOF
Bug Bounty Recon Automation v${VERSION}

Usage:
  $0 --domain DOMAIN --authorized [options]

Required:
  -d, --domain DOMAIN       Authorized root domain
      --authorized          Confirm you have permission to test the target

Options:
  -o, --output DIRECTORY    Output directory (default: ./runs)
  -t, --threads NUMBER      Worker count (default: 20)
  -r, --rate-limit NUMBER   Requests per second (default: 10)
      --timeout SECONDS     HTTP timeout (default: 10)
      --active              Enable crawling and active HTTP checks
      --nuclei              Run non-destructive nuclei templates
      --resume              Reuse today's most recent run
  -h, --help                Show help
  -v, --version             Show version

Examples:
  $0 -d example.com --authorized
  $0 -d example.com --authorized --active -r 5 -t 10
  $0 -d example.com --authorized --active --nuclei

This tool must only be used on targets you are explicitly authorized to test.
EOF
}

log() {
    local level="$1"
    shift

    local color="$BLUE"
    case "$level" in
        INFO) color="$BLUE" ;;
        OK) color="$GREEN" ;;
        WARN) color="$YELLOW" ;;
        ERROR) color="$RED" ;;
    esac

    local message="[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] [$level] $*"
    printf '%s%s%s\n' "$color" "$message" "$RESET" >&2

    if [[ -n "${LOG_FILE:-}" ]]; then
        printf '%s\n' "$message" >> "$LOG_FILE"
    fi
}

die() {
    log ERROR "$*"
    exit 1
}

on_error() {
    local exit_code=$?
    local line_number="${1:-unknown}"
    log ERROR "Failure near line ${line_number}; exit code ${exit_code}"
    exit "$exit_code"
}

trap 'on_error $LINENO' ERR
trap 'log WARN "Interrupted"; exit 130' INT TERM

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

require_command() {
    command_exists "$1" || die "Required command not found: $1"
}

validate_integer() {
    local name="$1"
    local value="$2"
    local minimum="$3"
    local maximum="$4"

    [[ "$value" =~ ^[0-9]+$ ]] ||
        die "$name must be an integer"

    (( value >= minimum && value <= maximum )) ||
        die "$name must be between $minimum and $maximum"
}

normalize_domain() {
    local value="$1"

    value="${value,,}"
    value="${value#http://}"
    value="${value#https://}"
    value="${value%%/*}"
    value="${value%.}"

    printf '%s' "$value"
}

validate_domain() {
    local domain="$1"

    [[ ${#domain} -le 253 ]] ||
        die "Domain is too long"

    [[ "$domain" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] ||
        die "Invalid domain: $domain"
}

safe_name() {
    LC_ALL=C printf '%s' "$1" | tr -c '[:alnum:]._-' '_'
}

stage_done() {
    [[ -f "$RUN_DIR/.done-$1" ]]
}

mark_done() {
    touch "$RUN_DIR/.done-$1"
}

run_stage() {
    local stage="$1"
    shift

    if "$RESUME" && stage_done "$stage"; then
        log INFO "Skipping completed stage: $stage"
        return
    fi

    log INFO "Starting stage: $stage"
    "$@"
    mark_done "$stage"
    log OK "Completed stage: $stage"
}

filter_scope() {
    local input="$1"
    local output="$2"

    awk -v root="$DOMAIN" '
        {
            value=tolower($0)
            sub(/^https?:\/\//, "", value)
            sub(/\/.*/, "", value)
            sub(/:[0-9]+$/, "", value)
            sub(/\.$/, "", value)

            if (value == root || value ~ ("\\." root "$")) {
                print value
            }
        }
    ' "$input" |
        grep -E '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' |
        sort -u > "$output"
}

discover_subdomains() {
    local raw="$RUN_DIR/raw-subdomains.txt"
    : > "$raw"

    log INFO "Running passive subfinder discovery"
    subfinder \
        -silent \
        -all \
        -recursive \
        -d "$DOMAIN" \
        -o "$RUN_DIR/subfinder.txt" || true

    cat "$RUN_DIR/subfinder.txt" >> "$raw"

    if command_exists assetfinder; then
        log INFO "Running assetfinder"
        assetfinder --subs-only "$DOMAIN" \
            > "$RUN_DIR/assetfinder.txt" 2>> "$LOG_FILE" || true
        cat "$RUN_DIR/assetfinder.txt" >> "$raw"
    else
        log WARN "assetfinder not installed; skipping"
    fi

    if command_exists amass; then
    log INFO "Running passive amass enumeration (maximum 10 minutes)"

    if timeout --signal=TERM --kill-after=15s 10m \
        amass enum -passive -d "$DOMAIN" \
        -o "$RUN_DIR/amass.txt" >> "$LOG_FILE" 2>&1
    then
        log OK "Amass completed"
    else
        exit_code=$?

        if [[ "$exit_code" -eq 124 ]]; then
            log WARN "Amass timed out after 10 minutes; continuing"
        else
            log WARN "Amass failed with exit code $exit_code; continuing"
        fi
    fi

    [[ -f "$RUN_DIR/amass.txt" ]] &&
        cat "$RUN_DIR/amass.txt" >> "$raw"
else
    log WARN "amass not installed; skipping"
fi

    printf '%s\n' "$DOMAIN" >> "$raw"
    filter_scope "$raw" "$RUN_DIR/subdomains.txt"

    log OK "Discovered $(wc -l < "$RUN_DIR/subdomains.txt") in-scope names"
}

resolve_subdomains() {
    dnsx \
        -silent \
        -l "$RUN_DIR/subdomains.txt" \
        -threads "$THREADS" \
        -rate-limit "$RATE_LIMIT" \
        -o "$RUN_DIR/resolved.txt"

    filter_scope "$RUN_DIR/resolved.txt" "$RUN_DIR/resolved-scoped.txt"
    mv "$RUN_DIR/resolved-scoped.txt" "$RUN_DIR/resolved.txt"

    dnsx \
        -silent \
        -l "$RUN_DIR/resolved.txt" \
        -a \
        -aaaa \
        -cname \
        -resp \
        -threads "$THREADS" \
        -rate-limit "$RATE_LIMIT" \
        -o "$RUN_DIR/dns-records.txt" || true

    log OK "Resolved $(wc -l < "$RUN_DIR/resolved.txt") hosts"
}

probe_http() {
    httpx \
        -silent \
        -l "$RUN_DIR/resolved.txt" \
        -threads "$THREADS" \
        -rate-limit "$RATE_LIMIT" \
        -timeout "$TIMEOUT" \
        -retries 1 \
        -follow-redirects \
        -status-code \
        -title \
        -tech-detect \
        -server \
        -ip \
        -cname \
        -content-length \
        -json \
        -o "$RUN_DIR/httpx.jsonl"

    # Produce clean URL and readable summary files.
    jq -r 'select(.url != null) | .url' \
        "$RUN_DIR/httpx.jsonl" |
        sort -u > "$RUN_DIR/alive.txt"

    jq -r '
        [
            (.url // "-"),
            ((.status_code // 0) | tostring),
            (.title // "-"),
            ((.tech // []) | join(",")),
            (.webserver // "-"),
            (.host_ip // "-")
        ] | @tsv
    ' "$RUN_DIR/httpx.jsonl" > "$RUN_DIR/http-summary.tsv"

    log OK "Found $(wc -l < "$RUN_DIR/alive.txt") responding URLs"
}

crawl_targets() {
    if ! command_exists katana; then
        log WARN "katana not installed; skipping crawl"
        return
    fi

    [[ -s "$RUN_DIR/alive.txt" ]] || {
        log WARN "No live URLs available for crawling"
        return
    }

    katana \
        -silent \
        -list "$RUN_DIR/alive.txt" \
        -depth 2 \
        -concurrency "$THREADS" \
        -parallelism 5 \
        -rate-limit "$RATE_LIMIT" \
        -timeout "$TIMEOUT" \
        -known-files robotstxt,sitemapxml \
        -extension-filter \
            png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3,pdf \
        -o "$RUN_DIR/crawled-urls-raw.txt" || true

    grep -E "^https?://([^/]+\.)?${DOMAIN//./\\.}([/:]|$)" \
        "$RUN_DIR/crawled-urls-raw.txt" |
        sort -u > "$RUN_DIR/crawled-urls.txt" || true

    grep -Ei '\.js([?#].*)?$' "$RUN_DIR/crawled-urls.txt" |
        sort -u > "$RUN_DIR/javascript-files.txt" || true

    grep -Ei \
        '/(api|graphql|swagger|openapi|v[0-9]+)(/|[?#]|$)' \
        "$RUN_DIR/crawled-urls.txt" |
        sort -u > "$RUN_DIR/api-candidates.txt" || true

    log OK "Collected $(wc -l < "$RUN_DIR/crawled-urls.txt") scoped URLs"
}

run_safe_nuclei() {
    if ! command_exists nuclei; then
        log WARN "nuclei not installed; skipping"
        return
    fi

    [[ -s "$RUN_DIR/alive.txt" ]] || {
        log WARN "No live URLs available for nuclei"
        return
    }

    log WARN "Running explicitly limited, non-destructive nuclei checks"

    nuclei \
        -silent \
        -list "$RUN_DIR/alive.txt" \
        -severity info,low,medium,high,critical \
        -exclude-tags \
            dos,fuzz,intrusive,bruteforce,exposure-token,default-login \
        -rate-limit "$RATE_LIMIT" \
        -bulk-size "$THREADS" \
        -concurrency "$THREADS" \
        -timeout "$TIMEOUT" \
        -retries 1 \
        -jsonl-export "$RUN_DIR/nuclei.jsonl" || true
}

create_report() {
    local discovered resolved alive crawled js_count findings

    discovered=$(wc -l < "$RUN_DIR/subdomains.txt")
    resolved=$(wc -l < "$RUN_DIR/resolved.txt")
    alive=$(wc -l < "$RUN_DIR/alive.txt")

    crawled=0
    js_count=0
    findings=0

    [[ -f "$RUN_DIR/crawled-urls.txt" ]] &&
        crawled=$(wc -l < "$RUN_DIR/crawled-urls.txt")

    [[ -f "$RUN_DIR/javascript-files.txt" ]] &&
        js_count=$(wc -l < "$RUN_DIR/javascript-files.txt")

    [[ -f "$RUN_DIR/nuclei.jsonl" ]] &&
        findings=$(wc -l < "$RUN_DIR/nuclei.jsonl")

    cat > "$RUN_DIR/report.txt" <<EOF
BUG BOUNTY RECON REPORT
=======================

Target:          $DOMAIN
Generated:       $(date -u '+%Y-%m-%dT%H:%M:%SZ')
Active mode:     $ACTIVE
Nuclei enabled:  $RUN_NUCLEI
Rate limit:      $RATE_LIMIT requests/second
Threads:         $THREADS

RESULTS
-------
Subdomains:      $discovered
Resolved hosts:  $resolved
Live URLs:       $alive
Crawled URLs:    $crawled
JavaScript URLs: $js_count
Nuclei results:  $findings

FILES
-----
subdomains.txt       Normalized in-scope names
resolved.txt         DNS-resolving names
dns-records.txt      DNS metadata
alive.txt            Responding HTTP URLs
httpx.jsonl          Structured HTTP metadata
http-summary.tsv     Human-readable HTTP summary
crawled-urls.txt     In-scope crawl results
javascript-files.txt JavaScript asset URLs
api-candidates.txt   Potential API routes
nuclei.jsonl         Limited template results
recon.log            Execution log

All automated results require manual verification.
EOF

    log OK "Report written to $RUN_DIR/report.txt"
}

parse_arguments() {
    while (($#)); do
        case "$1" in
            -d|--domain)
                [[ $# -ge 2 ]] || die "Missing value for $1"
                DOMAIN="$2"
                shift 2
                ;;
            -o|--output)
                [[ $# -ge 2 ]] || die "Missing value for $1"
                OUTPUT_ROOT="$2"
                shift 2
                ;;
            -t|--threads)
                [[ $# -ge 2 ]] || die "Missing value for $1"
                THREADS="$2"
                shift 2
                ;;
            -r|--rate-limit)
                [[ $# -ge 2 ]] || die "Missing value for $1"
                RATE_LIMIT="$2"
                shift 2
                ;;
            --timeout)
                [[ $# -ge 2 ]] || die "Missing value for $1"
                TIMEOUT="$2"
                shift 2
                ;;
            --active)
                ACTIVE=true
                shift
                ;;
            --nuclei)
                RUN_NUCLEI=true
                ACTIVE=true
                shift
                ;;
            --resume)
                RESUME=true
                shift
                ;;
            --authorized)
                AUTHORIZED=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                printf '%s\n' "$VERSION"
                exit 0
                ;;
            *)
                die "Unknown argument: $1"
                ;;
        esac
    done
}

main() {
    parse_arguments "$@"

    [[ -n "$DOMAIN" ]] || {
        usage
        exit 1
    }

    "$AUTHORIZED" ||
        die "Authorization not confirmed. Add --authorized only with permission."

    DOMAIN=$(normalize_domain "$DOMAIN")
    validate_domain "$DOMAIN"

    validate_integer "threads" "$THREADS" 1 100
    validate_integer "rate limit" "$RATE_LIMIT" 1 150
    validate_integer "timeout" "$TIMEOUT" 1 120

    require_command awk
    require_command grep
    require_command sort
    require_command jq
    require_command subfinder
    require_command dnsx
    require_command httpx

    local domain_dir
    local timestamp

    domain_dir="$(safe_name "$DOMAIN")"
    timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"

    if "$RESUME"; then
        RUN_DIR=$(
            find "$OUTPUT_ROOT/$domain_dir" \
                -mindepth 1 \
                -maxdepth 1 \
                -type d \
                -print 2>/dev/null |
                sort -r |
                head -n 1
        )

        [[ -n "$RUN_DIR" ]] ||
            die "No previous run found to resume"
    else
        RUN_DIR="$OUTPUT_ROOT/$domain_dir/$timestamp"
    fi

    mkdir -p "$RUN_DIR"
    RUN_DIR="$(cd "$RUN_DIR" && pwd -P)"
    LOG_FILE="$RUN_DIR/recon.log"

    log INFO "Target: $DOMAIN"
    log INFO "Results: $RUN_DIR"
    log INFO "Mode: $([[ "$ACTIVE" == true ]] && echo active || echo passive)"

    run_stage discovery discover_subdomains
    run_stage resolution resolve_subdomains
    run_stage http-probing probe_http

    if "$ACTIVE"; then
        run_stage crawling crawl_targets
    else
        log INFO "Passive mode: crawling disabled"
    fi

    if "$RUN_NUCLEI"; then
        run_stage nuclei run_safe_nuclei
    fi

    create_report

    log OK "Recon completed"
    printf '\nResults: %s\n' "$RUN_DIR"
}

main "$@"