# ReconFlow
ReconFlow — Map the unseen. Hunt the surface. A stealthy, scope-aware recon pipeline built for authorized security operations.

## Features

- Passive subdomain discovery
- DNS resolution
- HTTP service probing
- Optional active crawling
- Restricted, non-destructive Nuclei checks
- Rate and concurrency controls
- Resumable runs
- Structured reports

## Requirements

- Bash
- jq
- subfinder
- dnsx
- httpx
- assetfinder
- amass
- katana
- nuclei

## Usage
```bash
chmod +x reconflow.sh
./reconflow.sh --domain example.com --authorized

**Active crawling** :
./reconflow.sh --domain example.com --authorized --active \
  --rate-limit 5 --threads 10

**Restricted Nuclei checks** :
./reconflow.sh --domain example.com --authorized --active --nuclei \
  --rate-limit 5 --threads 10

**Resume latest run**:
./reconflow.sh --domain example.com --authorized --resume

```

## Legal notice 

Use ReconFlow only on systems you own or have explicit authorization to test. Users are responsible for complying with applicable laws and program rules. Automated findings require manual validation

