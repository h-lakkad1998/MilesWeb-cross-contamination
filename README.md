# MilesWeb-cross-contamination
This repo. is the evidance that shows that MilesWeb a hosting service provider in India does not care about protecting server. Event when I approached the support team they said our servers are safe. I am posting evidence that they not safe I foud legit files are loaded in the Linux kernel RAM of server.


# 1) Is the Infection Still Existing in Other Setups on This Server?
YES — Critically. Look at your latest ipcs -m output:

67 active SC Implant payloads (0x7321xxxx) are currently sitting in the Linux kernel RAM of server sapphire across 19 other cPanel customer accounts:

tclmkhxp (29 active infected sites in RAM)

fblnigkr (18 active infected sites in RAM)

tbpxfkys (8 active infected sites in RAM)

cromxmfq (3 active infected sites in RAM)

uhhmxyrz, miphzrap (2 each)

uxxmfrkr, gdldnbti, porflmxg, qunmbtmj, twmdjsci, hjcezjsl, sqqcughy, yycztwii, mrahmial, ibugrpjv, fneeqvtd, lasrnalk, seoclerk, vfgvnqjm, jlkcvycq, tczimusu (1 each)

Active Mutation Between Your Two Snapshots: Look at user hjcezjsl (0x732120b5):

In your first ipcs -m run: shmid 786508 | 468741 bytes

In your second ipcs -m run: shmid 852029 | 584143 bytes
This proves the malware is actively executing and mutating in real time on neighboring accounts on this server right now.

Why This Endangers Your Account: Every one of those 67 segments has permissions 644 (world-readable by every user on the server). Even though CageFS hides other users' files in /home/, SysV Shared Memory (ipcs -m) is NOT virtualized/isolated on this server. Any compromised script or user on the server can attach to and read any 0x7321xxxx segment in RAM via shmat().

# 2) Incident & Forensic Report: Kernel Shared Memory (`SysV SHM`) Persistence of `SCV:5.1.2` (SC403) WordPress Implant and Server-Wide IPC Exposure on `sapphire`

**Date:** October 27, 2026  
**Affected Server Hostname:** `sapphire`  
**Reporting cPanel Account:** `ztqudefh`  
**Malware Family Identified:** SC Implant / SC403 (`/* SCV:5.1.2 */`, `SCSHM1` Shared Memory Resident Dropper, EtherHiding Blockchain C2)  
**Severity:** Critical (Server-Wide Multi-Tenant Infection & Lack of CloudLinux CageFS IPC Namespace Isolation)

---

## 1. Executive Summary

Following repeated recontamination of a WordPress environment under account `ztqudefh`—which persisted even after full filesystem cleanups, database purges, and resetting to a blank WordPress installation—a deep forensic investigation was conducted via cPanel SSH/Terminal.

The investigation revealed that the reinfection was driven by **SC Implant (`SCV:5.1.2`)**, a multi-layered, self-healing WordPress malware strain that stores its entire 453 KB compressed PHP payload directly inside **Linux Kernel System V Shared Memory (`SysV SHM`)** keyed via `ftok('wp-config.php', 's')` (`0x7321xxxx`). Because `SysV SHM` persists in the OS kernel independently of disk files, deleting or reinstalling files on disk did not clear the payload from RAM.

More critically, querying the kernel IPC table (`ipcs -m`) revealed a **server-wide security and isolation issue on host `sapphire`**:
1. **SysV IPC namespaces are not isolated per user in CageFS**—any unprivileged user can view and attach to shared memory segments across the entire physical server.
2. **67 other active `0x7321xxxx` malware segments across 19 other cPanel customer accounts** are currently resident in kernel RAM on `sapphire` with world-readable (`0644`) permissions.

---

## 2. Symptoms & Initial Indicators of Compromise (IoCs)

Prior to kernel memory analysis, standard filesystem and database cleanups repeatedly encountered the following regenerating artifacts:
* **Obfuscated Hourly WP-Cron Hooks:** `q9ejopk47ya0nvbtk`, `sg2fx1q5yk1h23ecea`, `jk0cntt3w6ahd0nlp3`
* **Uploads Directory Droppers:** 8-character hex ZIP archives (`315a733f.zip`) and `sc_*` temporary `.part` fragments in `wp-content/uploads/`
* **Core Configuration Injection:** `/* SC_WC */` marker injected into `wp-config.php` alongside malicious `wp-content/maintenance.php` and `wp-content/.htaccess` LiteSpeed directives
* **Rogue Administrator Accounts:** Auto-generated administrator accounts matching `admin_<hex>` (e.g., `admin_04a2edd344`, UID 84) hidden from the WP-Admin UI
* **Database State & EtherHiding C2 Options:** `wp_options` keys including `sc_canary`, `sc_lb_mode`, `sc_c2_cache`, `sc_last_c2`, `sc_last_rpc`, and `sc_initialized` communicating with Binance Smart Chain / Ethereum RPC endpoints (EtherHiding)

Despite removing all of the above and deploying a blank WordPress setup, the infection remained resident.

---

## 3. Step-by-Step Forensic Investigation & Commands Executed

### Step 3.1: Inspecting the Linux Kernel Shared Memory Table (`ipcs -m`)
To determine whether the malware was surviving disk wipes via kernel RAM, the System V Shared Memory table was queried from the unprivileged user shell (`ztqudefh`):

```bash
ipcs -m
echo "My user: $(whoami)" && ipcs -m | grep $(whoami)
```

Finding:
My user: ztqudefh
key        shmid   owner     perms  bytes   nattch  status
0x73211f45 753798  ztqudefh  644    453370  0

Even with nattch = 0 (no active process currently attached), segment 753798 (453,370 bytes) remained persistently allocated in the OS kernel under owner ztqudefh.

### Step 3.2: Cryptographic Mapping of the 0x7321xxxx ftok() Key
In Linux glibc, ftok(const char *pathname, int proj_id) constructs a 32-bit key_t integer as follows:

Bits 24–31 (0x73): ASCII hex value of 's' (0x73), the project ID used by the SC Implant.

Bits 16–23 (0x21): Minor device ID (0x21) of the server's /home filesystem block device.

Bits 0–15 (0x1f45): Lower 16 bits (inode & 0xffff) of the target wp-config.php inode.

Running an inode-to-key correlation check against the newly created wp-config.php:
find ~ -name "wp-config.php" 2>/dev/null | while read -r f; do
    ino=$(stat -c "%i" "$f")
    hex=$(printf "%04x" $((ino & 0xffff)))
    echo "File: $f | Inode: $ino | Expected SHM Key: 0x7321${hex}"
done

Output:
File: /home/ztqudefh/public_html/wp-config.php | Inode: 85329455 | Expected SHM Key: 0x7321062f

Root Cause Confirmed: The existing 0x73211f45 segment (shmid 753798) was allocated in kernel RAM from the previous wp-config.php inode (inode & 0xffff == 0x1f45) prior to the site wipe. Because filesystem deletion does not release kernel SysV SHM segments, the 453 KB payload survived across site resets.

### Step 3.3: Extracting the Live Payload from Kernel RAM via libc shmat()
Because shmop and sysvshm PHP extensions were disabled in the CLI profile (shmop: NO | sysvshm: NO), Python's ctypes interface was used to invoke the standard C library shmat() syscall directly on shmid 753798:

python3 -c '
import ctypes
libc = ctypes.CDLL("libc.so.6")
libc.shmat.restype = ctypes.c_void_p
addr = libc.shmat(753798, None, 0)
if addr and addr != 0xffffffffffffffff:
    data = ctypes.string_at(addr, 453370)
    open("/home/ztqudefh/shm_753798_evidence.bin", "wb").write(data)
    libc.shmdt(ctypes.c_void_p(addr))
'

### Extracted RAM Payload Header (shm_753798_evidence.bin):

SCSHM1:452267:f0868ac8d3d7f145a1245795769dc51150cddfa445abdb99ca15098d7b0b04f3
<?php
/**
 * Plugin Name:        Crisp Beacon
 * Plugin URI:         [https://harperallen.dev/plugins/crisp-beacon/](https://harperallen.dev/plugins/crisp-beacon/)
 * Description:        Flexible content delivery wrapper
 * Version:            1.2.4
 * Author:             Harper Allen
 * Author URI:         [https://harperallen.dev](https://harperallen.dev)
 * License:            GPL-2.0-or-later
 * Text Domain:        crisp-beacon
 */
/* SCV:5.1.2 */
function jiros($ozir,$haloy)
{
    $ozir =$haloy . '';
    return ($ozir === null) ? 67 :$ozir;
}
defined("AB" . 'SP' . "A" . 'TH') or exit;
if (!(("\x66\x75n\x63\x74\x69\x6fn" . '_e' . 'xist' . 's')('sc_de' . 'dup'))) {} else {


This conclusively proved that SC Implant v5.1.2 (/* SCV:5.1.2 */) was stored verbatim inside kernel memory segment 753798 with the SCSHM1:<length>:<sha256> header.

### Step 3.4: Eradicating the Kernel Memory Segment on ztqudefh
The segment was destroyed and active LiteSpeed PHP workers for ztqudefh were terminated:

ipcrm -m 753798
pkill -9 -u ztqudefh lsphp


Subsequent verification via ipcs -m | grep ztqudefh confirmed no SysV SHM segments remain under ztqudefh.


## 4. Server-Wide Discovery: 67 Active Infections Across 19 Neighboring Accounts

The output of ipcs -m on server sapphire revealed 67 additional shared memory segments matching the exact 0x7321xxxx SC Implant signature (388 KB – 584 KB, permissions 644) across 19 other cPanel accounts:

cPanel OwnerCount of Infected 0x7321xxxx RAM SegmentsExample shmids & Sizes (Bytes)
tclmkhxp29 segments720897 (440,113 B), 720898 (468,220 B), 327690 (557,939 B), etc.
fblnigkr18 segments65551 (520,846 B), 131091 (557,749 B), 589874 (564,960 B), etc.
tbpxfkys8 segments163885 (544,061 B), 327769 (534,348 B), 327772 (559,668 B), etc.
cromxmfq3 segments327720 (561,631 B), 327729 (561,631 B), 131131 (551,969 B)
uhhmxyrz2 segments131111 (550,661 B), 131169 (550,616 B)
miphzrap2 segments131083 (550,279 B), 589920 (542,806 B)
13 Other Accounts1 segment each (13 total)uxxmfrkr, gdldnbti, porflmxg, qunmbtmj, twmdjsci, hjcezjsl (852029), sqqcughy, yycztwii, mrahmial, ibugrpjv, fneeqvtd, lasrnalk, seoclerk, vfgvnqjm, jlkcvycq, tczimusu

Furthermore, between two consecutive ipcs -m checks minutes apart, account hjcezjsl (key 0x732120b5) rotated from shmid 786508 (468,741 bytes) to shmid 852029 (584,143 bytes), proving that the malware is actively executing and updating payloads in real time across the server.

Because all 67 segments are created with mode 0644 (world-readable) and SysV IPC is not isolated between CageFS users, any user on sapphire can read the raw memory segments of all 19 infected accounts using shmat().


## 5) Recommended Actions for the Hosting Provider (SysAdmin / Security Team)

To remediate this issue across sapphire and prevent cross-tenant exposure or kernel IPC exhaustion, we recommend the following server-level actions:

Enable CloudLinux CageFS IPC Namespace Isolation Immediately:

Currently, all cPanel accounts on sapphire share the global root SysV IPC namespace, allowing any user to run ipcs -m and attach (shmat) to world-readable 0644 memory segments owned by other tenants.

Ensure CloudLinux CageFS IPC namespace virtualization is enabled and enforced so each LVE/CageFS container has a private SysV IPC namespace and /dev/shm mount.

Purge All 0x7321xxxx (SCSHM1) Shared Memory Segments Server-Wide:

As root, inspect and remove all shared memory segments matching the 0x7321 key prefix:

Bash
ipcs -m | awk '$1 ~ /^0x7321/ {print $2}' | xargs -r -n1 ipcrm -m
Note: This must be paired with killing detached lsphp / php CLI guard processes (gr_<hex>.php) and cleaning the affected accounts; otherwise, infected sites will immediately re-allocate the segments on their next HTTP hit.

Disable shmop and sysvshm Extensions Globally in EasyApache / CloudLinux PHP Selector: Legitimate WordPress plugins almost never require raw System V shared memory (shmop_* / shm_*). Disabling shmop and sysvshm across all PHP versions (both lsphp and CLI) neutralizes the SC Implant's primary kernel-RAM persistence node.

Deploy YARA / ModSecurity / Imunify360 Rules for SCV:5.1.2 (SC403):
Scan /home/*/public_html/ across the server for the following high-confidence strings and file patterns:

File contents: SCSHM1:, /* SCV:, /* SC_WC */, /* SC_ADV */, /* SC_DB */, /* SCOCV */, /* SC_TH */, __SC_BOOT, sc_dedup
Hidden directories & replicas: wp-content/.sc_*, wp-content/.wp-object-cache-*.dat, .gr_*.php

Block incoming HTTP requests containing the /?sc_=1 Service Worker heartbeat query parameter at the LiteSpeed/WAF layer.
