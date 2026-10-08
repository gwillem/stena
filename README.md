# stena

A Go CLI for the Nowhere Networks captive portal used on Stena ferries.
The module is `github.com/gwillem/stena`; all Go code is in the root `main` package.
Supported platforms: macOS and Linux.

## Usage

```sh
go run . login VOUCHER
go run . login --logout-oldest VOUCHER
go run . scan
go run . -v scan
```

`login` discovers the portal through the default gateway, authenticates with the
voucher, completes access-controller authentication, and prints the session.
`--logout-oldest` permits logging out the client already using the voucher.

`scan` queries unique MAC addresses already in the active interface's ARP cache.
It prints the MAC, voucher or open-access keyword, decimal gigabytes used, and
local expiry time. `OFFLINE` means fewer clients are connected than the session
allows; `<=== ME` identifies this client. The final line totals connected clients
and traffic.

Sessions are saved as `<mac>.json` in the working directory. Empty JSON files
mark missing sessions and prevent repeat lookups. Remove an empty marker to
query that MAC again. macOS requires `arp`; Linux requires `ip` from iproute2.
Use `-v` or `--verbose` for diagnostics on stderr.

## Privacy and Git

Session output and JSON may contain voucher codes and device identifiers.
Do not publish them. Fixtures use synthetic MACs, documentation IP addresses,
and a dummy voucher.

`.gitignore` allows only the reviewed source, tests, module files, this README,
and `AGENTS.md`. Local session JSON, the `mac` inventory, legacy Python scripts,
and compiled binaries remain ignored. Review each new file before adding an
allowlist exception. Do not force-add local artifacts.

## Checks

```sh
go mod tidy
gofumpt -w *.go
go fix ./...
golangci-lint run ./...
go test ./...
```
