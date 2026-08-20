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
## Basic passive reconnaissance:
./reconflow.sh --domain example.com --authorized

## Save results under a custom directory: 
./reconflow.sh -d example.com --authorized -o ./results

## Active crawling with conservative limits: 
./reconflow.sh -d example.com --authorized \
--active --rate-limit 5 --threads 10 --timeout 15

## Active scan with restricted nuclei checks:
./reconflow.sh -d example.com --authorized \
--active --nuclei --rate-limit 5 --threads 10

## Resume the target’s latest run:
./reconflow.sh -d example.com --authorized --resume

## Display usage information: 
./reconflow.sh --help

## Display version:
./reconflow.sh --version

```

## Legal notice 

Use ReconFlow only on systems you own or have explicit authorization to test. Users are responsible for complying with applicable laws and program rules. Automated findings require manual validation

