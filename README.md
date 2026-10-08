# Stenaline Wifi Scanner

Scan for wifi vouchers and register using an unused voucher.

## Usage

Connect to the `Internet@Sea` network and wait a few minutes. Then run:

```sh
go install github.com/gwillem/stena@latest
stena scan
stena login <voucher>
```

To query specific MAC addresses directly, pass one or more addresses using
12 hexadecimal digits each:

```sh
stena scan 020000000002 020000000003
cat mac | xargs stena scan
```

This skips ARP discovery and checks the API even if an empty cache file exists.
Stdout contains one session line per registered address.
Unregistered addresses produce no output. There is no totals line.
Portal discovery progress still goes to stderr. With no MAC arguments,
`stena scan` scans the ARP cache as above.

Both scan modes fetch statuses with up to 20 concurrent workers. Sessions are
printed as fetches finish; output order is unspecified.
The voucher column is left-aligned and padded to at least eight characters;
longer voucher codes are not truncated.

```
❯ stena scan
Finding default gateway...
Finding own MAC via gateway 192.0.2.1 on en0...
Checking ARP cache on en0 (own MAC 020000000001)...
Checking portal sessions (ARP entries: 38)...
020000000001 TEST-01  0.10GB 2030-01-02 12:00 <=== ME
020000000002 TEST-02  0.10GB 2030-01-02 12:00
020000000003 TEST-03  0.10GB 2030-01-02 12:00
020000000004 TEST-04  0.10GB 2030-01-02 12:00
020000000005 TEST-05  0.10GB 2030-01-02 12:00
020000000006 TEST-06  0.10GB 2030-01-02 12:00
020000000007 TEST-07  0.10GB 2030-01-02 12:00
020000000008 TEST-08  0.10GB 2030-01-02 12:00
020000000009 TEST-09  0.10GB 2030-01-02 12:00
02000000000a TEST-10  0.10GB 2030-01-02 12:00
02000000000b TEST-11  0.10GB 2030-01-02 12:00
02000000000c TEST-12  0.10GB 2030-01-02 12:00
02000000000d TEST-13  0.10GB 2030-01-02 12:00
02000000000e TEST-14  0.10GB 2030-01-02 12:00
02000000000f TEST-15  0.10GB 2030-01-02 12:00
020000000010 TEST-16  0.10GB 2030-01-02 12:00
020000000011 TEST-17  0.10GB 2030-01-02 12:00
020000000012 TEST-18  0.10GB 2030-01-02 12:00
020000000013 TEST-19  0.10GB 2030-01-02 12:00
020000000014 TEST-20  0.10GB 2030-01-02 12:00
20 active clients, 2.00GB traffic
```
