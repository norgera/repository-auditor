# Repository Auditor (CS4471A Group 4)

A VS Code extension that discovers five scanner microservices through a pair of registries.

| Folder | Purpose |
|---|---|
| `contracts/` | JSON schemas for service metadata and scan responses |
| `registry_service/` | Registry: registration, leases, search, health |
| `scanner_kit/` | Shared scanner code: registration agent, input guard, sandbox, redaction |
| `scanners/` | S1 dyff, S2 Gitleaks, S3 Trivy, S4 zizmor, S5 OSV-Scanner, S6 test service |
| `extension/` | TypeScript VS Code extension (the service consumer) |
| `demo/` | Automated demo and VS Code host test |

The backend uses only the Python standard library (3.10 or later).

## Run

Install the scanners you want to use. Without one, its service still registers and returns status `error`.

    brew install dyff gitleaks trivy zizmor osv-scanner

    python3 -m unittest discover -s tests     # backend tests
    python3 demo/run_demo.py                  # scenarios D1 to D6, about 40 s
    (cd extension && npm install && npm test) # extension logic against real registries
    python3 demo/host_test.py                 # extension inside VS Code
    python3 demo/real_scan_test.py            # real tools on synthetic files (S5 contacts osv.dev)

Manual run, each in its own terminal from this folder, with the same `REGISTRY_TOKEN` exported in all of them:

    REGISTRY_NAME=A PORT=8701 python3 -m registry_service.app
    REGISTRY_NAME=B PORT=8702 python3 -m registry_service.app
    python3 -m scanners.run s1                # repeat for s2 to s5, and s6

Then open `extension/` in VS Code and press F5.

## Settings

`LEASE_TTL` (15), `SWEEP_INTERVAL` (2), `RENEW_INTERVAL` (5), `RETRY_INTERVAL` (3), `SCAN_TIME_LIMIT` (20), `HOST`, `PORT`, `PUBLIC_URL`, `REGISTRY_URLS`.

## Not done yet

Local runs use HTTP on localhost. HTTPS, container images and IBM Cloud deployment are still to do.
