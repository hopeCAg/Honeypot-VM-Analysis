# Honeypot-VM-Analysis


### MySQL Database Wipe and Extortion on corp-han0-8598a

##### VM name: corp-han0-8598a
##### Account: Name: hgmuser

<!--
**Report date:** Sep 19, 2026 &nbsp;|&nbsp; **Prepared by:** [analyst name] &nbsp;|&nbsp; **Status:** Draft for analyst review

> **Time convention.** Times below are the exported `TimeGenerated` values, presumed CDT (5 hours behind the UTC timestamps in MySQL `RawData`). Key events also give UTC in the KQL. Table names for the MySQL logs follow the brief (`MySQLAudit_CL_Auth`, `MySQLAudit_CL_Query`); adjust to your workspace. Figures/counts below were computed from the seven supplied CSVs only.

---
-->
## 1. Executive Summary

On Sep 14, 2026 at 21:36–21:37 CDT, an external attacker (`64.89.163.168`) logged in to the internet-reachable MySQL server on corp-han0-8598a as `root`, read every table in four databases, dropped all four (including `cr_corp_089`, which held `credentials`, `customers`, `orders`, `payments` tables), purged the binary logs, and left a bitcoin extortion note in a new `RECOVER_YOUR_DATA` database. The server stayed exposed afterward: 15 external IPs logged in as root between Sep 14–18, and the host also saw RDP brute-force activity with 15 successful "administrator" logons from four IPs, though no link to the database attack is established. Network telemetry confirms both services were reachable from the public internet throughout the incident window. A local administrator opened the ransom table on Sep 19 at ~11:24 CDT, roughly 4.6 days later. How the root password was obtained, how much data actually left the host, and whether recovery has occurred are **not determined from available logs**.

##### KQL:
```kql
// Destructive/extortion statements around the attack (21:30-21:40 CDT = 02:30-02:40 UTC)
MySQLAudit_CL_Query
| where TimeGenerated between (datetime(2026-09-15T02:30:00Z) .. datetime(2026-09-15T02:40:00Z))
| where Query matches regex @"(?i)^\s*(DROP|RENAME|PURGE|RESET|REVOKE|SHUTDOWN)" or Query has "RECOVER_YOUR_DATA"
| project TimeGenerated, Query | order by TimeGenerated asc
```

<img width="707" height="436" alt="image" src="https://github.com/user-attachments/assets/d8db26e0-c65e-414e-8c9f-12c6de8f0d1e" />

---

## 2. Incident Details

| Field | Detail |
|---|---|
| **Attack time** | Sep 14, 2026, 21:36:20–21:37:12 CDT (02:36–02:37 UTC on Sep 15). Source: MySQL Auth, MySQL Query. |
| **Detection time** | Sep 19, 2026, ~11:24 CDT (16:24 UTC): a local session inspects the schema of `recover_your_data`, then reads its contents at 11:27:55. `MySQLWorkbench.exe` started under `hgmuser` at 11:23:02. Source: MySQL Query, DeviceProcessEvents. |
| **Reporter** | Not determined from available logs. Activity at detection is under the local account `hgmuser`. |
| **Classification** | Type: ransomware-style database extortion (destructive, with a data-theft claim). Severity: **High**. Raise to **Critical** if `cr_corp_089` is production data with no off-host backup. |
| **Affected assets** | Host `corp-han0-8598a` (Windows; Azure guest agent present; MySQL Server 8.0.45, service MySQL80). Databases: `cr_corp_089`, `sakila`, `world` (dropped); `recover_your_data` (attacker-created). Accounts: MySQL `root@'%'`; Windows `administrator` (RDP logons). |
| **Environment note** | Binary log prefix `josh-mde-lab-bin` and the `sakila`/`world` sample databases suggest a test/lab system. Confirm classification of `cr_corp_089` with the asset owner. |

##### KQL:
```kql
MySQLAudit_CL_Query
| where TimeGenerated > datetime(2026-09-19T16:00:00Z)
| where Query has_any ("recover_your_data", "cr_corp_089")
| project TimeGenerated, Query

DeviceProcessEvents
| where DeviceName =~ "corp-han0-8598a" and TimeGenerated > datetime(2026-09-19T16:00:00Z)
| where FileName in~ ("MySQLWorkbench.exe", "mysqld.exe", "mysql.exe")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
```

<img width="707" height="409" alt="image" src="https://github.com/user-attachments/assets/f124d830-9a64-43ed-9c5e-f2991bafd7df" />

---

## 3. Impact Assessment

| Category | Assessment |
|---|---|
| **Confidentiality** | Sessions from `64.89.163.168` ran `SELECT *` on every table: `credentials`, `customers`, `orders`, `payments` (`cr_corp_089`), all `sakila` tables/views, and `world.city/country/countrylanguage`. Results return to the client, so treat as exfiltrated. `DeviceNetworkEvents` confirms this IP connected directly to `mysqld.exe` at 02:36:20 UTC, 9 seconds before its first successful login, a single direct session, not a proxied one, but per-connection byte counts are not recorded in that table, so data volume is still unknown. The note threatens disclosure after 48h (lapsed ~Sep 16, 21:36 CDT); whether a leak occurred is not determined. |
| **Integrity** | `DROP DATABASE` on `cr_corp_089`, `recover_your_data`, `sakila`, `world` at 21:37:06–07. `RESET MASTER` and `PURGE BINARY LOGS` at 21:37:09–10 remove on-host point-in-time recovery. `REVOKE ALL PRIVILEGES` from `root@'%'` at 21:37:10. No RENAME statements found. |
| **Availability** | Databases removed. `SHUTDOWN` issued at 21:37:11, but server still answered `SHOW DATABASES` at 21:37:12 and connection IDs kept incrementing (83→93 by 22:45), so no evidence the shutdown succeeded. On Sep 19 the local session queried `cr_corp_089.credentials` four times; whether restored is not determined. |
| **Scope** | One host, four databases. Unauthorised root access continued from 15 external IPs through Sep 18. No evidence of lateral movement, file encryption, persistence, or attacker process execution in the Device tables (MDE/Azure agent noise excluded). |
| **Business impact** | Not determined from available logs (data classification, backup status, and record counts are unknown). |

##### KQL:
```kql
MySQLAudit_CL_Query
| where TimeGenerated between (datetime(2026-09-15T02:30:00Z) .. datetime(2026-09-15T02:40:00Z))
| where Query matches regex @"(?i)^\s*(SELECT \* FROM|DROP DATABASE)"
| extend Op = iff(Query startswith "DROP", "DROP", "READ"), Object = extract(@"(?i)(?:FROM|DATABASE)\s+`?([\w\.]+)`?", 1, Query)
| summarize Stmts=count(), First=min(TimeGenerated) by Op, Object | order by First asc

// Confirm the ransom IP's connection to mysqld directly (byte counts not available in this table)
DeviceNetworkEvents
| where DeviceName =~ "corp-han0-8598a" and ActionType == "InboundConnectionAccepted"
| where RemoteIP == "64.89.163.168"
| project TimeGenerated, InitiatingProcessCommandLine, RemotePort

// Exfil volume: not in audit log or DeviceNetworkEvents. Needs flow data (column names vary by Traffic Analytics version)
NTANetAnalytics
| where TimeGenerated between (datetime(2026-09-15T02:30:00Z) .. datetime(2026-09-15T02:45:00Z))
| where SrcIp == "64.89.163.168" or DestIp == "64.89.163.168"
| summarize InBytes=sum(InboundBytes), OutBytes=sum(OutboundBytes) by SrcIp, DestIp, DestPort
```

<img width="639" height="427" alt="image" src="https://github.com/user-attachments/assets/3d508ce3-e4ce-4ba9-a40a-72e915690be6" />

<img width="641" height="84" alt="image" src="https://github.com/user-attachments/assets/2eb2c1cd-71e0-4913-98a2-5be0b010dc89" />

---

## 4. Indicators of Compromise

> **Discrepancy to resolve.** The BTC address, email, URL and DATAID in the analyst brief (the "28T2" set) do not appear in any supplied log. The only extortion text in the query log is a different set ("2PPLB"), inserted twice. No INSERT of the 28T2 note was audited, so its source (e.g. the table contents viewed on Sep 19 at 11:27) should be confirmed. This may indicate a second note or actor.

| Type | Value | Context | Basis |
|---|---|---|---|
| BTC | `bc1qk9kvwhzt60u3eqcjllqlj44h0tj7w7n72apz99` | Ransom wallet (28T2 note) | Brief |
| Email | `ak+28t2@onionmail.org` | Contact (28T2 note) | Brief |
| URL | `hxxps://2no[.]co/2mysql` | Reference URL (28T2 note) | Brief |
| DATAID | `28T2` | Victim ID (28T2 note) | Brief |
| BTC | `bc1q3t3rnktgv9cnd59lzk9rdhhg6qcxs7d68m2n8d` | Ransom wallet, 0.0109 BTC in 48h; note 1 | Logs |
| Email | `ak+2pplb@onionmail.org` | Contact; note 2 | Logs |
| URL | `hxxps://cuq[.]in/844` | Reference URL; note 2 | Logs |
| DATAID | `2PPLB` | Victim ID; note 2 | Logs |
| DB object | `RECOVER_YOUR_DATA` (database and table, column `text`) | Created by attacker; recreated after drops | Logs |
| IP (MySQL) | `64.89.163.168` | Ransom session: connected directly to `mysqld.exe`; exfil reads, DROPs, note inserts; root over TCP/IP (no TLS) | Logs |
| IP (MySQL) | `64.89.163.94, .140, .154, .158, .166, .170, .178, .179` | Root logins each followed by `CREATE DATABASE IF NOT EXISTS RECOVER_YOUR_DATA` (Sep 15–18). Same /24 as above. Failed only: `.89, .152, .153` | Logs |
| IP (MySQL) | `77.90.185.30` | 123 failures / 19 root successes, users root/admin/sa, TLS; each success followed by `SELECT @@max_allowed_packet`. Still active Sep 19 11:33 | Logs |
| IP (MySQL) | `77.90.185.21, 213.209.159.115` | Same pattern (21 failures / 2 successes each) | Logs |
| IP (MySQL) | `45.8.17.150, 35.241.139.80, 27.223.84.195` | Root successes. `45.8.17.150` probed for DB `mat_server` (Sep 14 22:49); `27.223.84.195` opened 5 sessions incl. DB `mysql` (Sep 16 18:23) | Logs |
| IP (MySQL) | `34.22.222.15, 34.77.78.135, 45.186.208.79, 45.186.208.84, 47.103.157.194` | Failed root logins only (the two 45.186.x hosts used a password) | Logs |
| IP (RDP) | `223.100.52.237, 80.94.95.83, 201.187.98.150, 80.66.83.80` | Successful network logons as "administrator" (15 total, Sep 14–15) | Logs |
| IP (RDP) | `113.128.79.25, 94.26.68.54, 45.156.128.156` | Failed logons only (administrator/guest); 61 failures combined | Logs |
| Exposure | `mysqld.exe`: 106 accepted inbound connections / 97 distinct public IPs (Sep 13 18:21–Sep 19 16:34 UTC). `TermService` (RDP): 146 accepted / 136 distinct public IPs (Sep 14 04:22–Sep 19 16:31 UTC) | Confirms both services were internet-reachable throughout the window | Logs |
| SQL | `JSON_SCHEMA_VALID('{"enum":[0]}', '"AAAA…')` | Oversized payload at 21:37:11 right after SHUTDOWN; purpose not determined (possible crash attempt) | Logs |

*No IP reputation, geolocation, or ownership enrichment was performed. The RDP and MySQL IP sets do not overlap.*

##### KQL:
```kql
MySQLAudit_CL_Query | where Query has_any ("bc1q", "onionmail", "DATAID", "bitcoin", "2no.co", "cuq.in")
| project TimeGenerated, Query

MySQLAudit_CL_Auth | where isnotempty(IpAddress) and IpAddress != "localhost"
| summarize Fail=countif(ActionType=="LogonFailure"), Success=countif(ActionType=="LogonSuccess"),
            First=min(TimeGenerated), Last=max(TimeGenerated), Users=make_set(Username) by IpAddress
| order by Success desc

DeviceLogonEvents | where isnotempty(RemoteIP)
| summarize Fail=countif(ActionType=="LogonFailed"), Success=countif(ActionType=="LogonSuccess"),
            First=min(TimeGenerated), Last=max(TimeGenerated) by RemoteIP, AccountName, LogonType

DeviceNetworkEvents | where DeviceName =~ "corp-han0-8598a" and ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| summarize Conns=count(), DistinctIPs=dcount(RemoteIP), First=min(TimeGenerated), Last=max(TimeGenerated) by InitiatingProcessFileName
```


<img width="708" height="117" alt="image" src="https://github.com/user-attachments/assets/72d847d6-3b30-4a99-962d-00e1b76d0735" />

<img width="564" height="266" alt="image" src="https://github.com/user-attachments/assets/fe1085a8-8abe-4e3d-b4ee-b4d825071207" />

<img width="612" height="173" alt="image" src="https://github.com/user-attachments/assets/04ed608c-39fc-4ed4-9ee6-4ce370b5b3d7" />


---

## 5. Timeline (CDT)

| Time | Event | Source |
|---|---|---|
| Sep 13 13:11–14:01 | `hgmuser` installs MySQL 8.0.45; `mysqld.exe` (service MySQL80) starts at 14:01. | DeviceProcessEvents |
| Sep 13 21:53–21:54 | `hgmuser` starts MySQL Workbench. One `root@localhost` logon fails, then sessions read `cr_corp_089.credentials` and `.orders`. Baseline: databases intact. | DeviceProcessEvents; MySQL Auth, Query |
| Sep 13 22:44–22:48 | `hgmuser` opens Remote Desktop user settings (22:44). At 22:48:42 connection ID 10 (also used by the 21:53 Workbench session) runs `CREATE USER 'root'@'%'`, `GRANT ALL PRIVILEGES ON *.* WITH GRANT OPTION`, `FLUSH PRIVILEGES`. Remote root now exists. Windows Firewall console opened at 23:01. | MySQL Query; DeviceProcessEvents |
| Sep 14 00:41 | **INITIAL ACCESS (RDP path):** 26 failed network logons from `223.100.52.237` between 00:41–00:46; success as `administrator` at 00:41:09. | DeviceLogonEvents |
| Sep 14 12:14–Sep 15 14:23 | Further RDP-type successes as administrator: `80.94.95.83` (12:40), `201.187.98.150` (11 successes, Sep 14 14:26–Sep 15 12:19), `80.66.83.80` (Sep 15 14:18, 14:23). | DeviceLogonEvents |
| Sep 14 21:36:20–29 | **INITIAL ACCESS (DB path):** `DeviceNetworkEvents` records `64.89.163.168` accepted by `mysqld.exe` at 21:36:20. Root logins denied twice with no password, then root succeeds at 21:36:29 (18 successes through 21:37:10). | DeviceNetworkEvents; MySQL Auth |
| Sep 14 21:36:27–28 | `CREATE DATABASE RECOVER_YOUR_DATA`; both ransom notes inserted (0.0109 BTC, DATAID 2PPLB). | MySQL Query |
| Sep 14 21:36:30–21:37:06 | **DB COMPROMISE:** `SELECT *` on every table in `cr_corp_089`, `recover_your_data`, `sakila`, `world` (31 tables/views, one session each). | MySQL Query |
| Sep 14 21:37:06–07 | `DROP DATABASE` `cr_corp_089`, `recover_your_data`, `sakila`, `world`. | MySQL Query |
| Sep 14 21:37:08–09 | `RECOVER_YOUR_DATA` recreated and both notes re-inserted (**RANSOM NOTE**). | MySQL Query |
| Sep 14 21:37:09–12 | `RESET MASTER`; `PURGE BINARY LOGS`; `REVOKE ALL` from `root@'%'`; `GRANT SHUTDOWN`; `SHUTDOWN`; oversized `JSON_SCHEMA_VALID` call. Server still responds at 21:37:12. | MySQL Query |
| Sep 14 22:45–22:49 | `77.90.185.30` begins root/admin/sa probes (first root success Sep 15 00:06:31). `45.8.17.150` logs in as root at 22:49:24. | MySQL Auth, Query |
| Sep 15 00:52–Sep 18 00:27 | Nine more sessions from `64.89.163.x` log in as root and run `CREATE DATABASE IF NOT EXISTS RECOVER_YOUR_DATA`; no new note inserts audited. `77.90.185.30` succeeds 19 times through Sep 18 01:26. | MySQL Auth, Query |
| Sep 15 01:13–Sep 17 20:24 | Additional root successes: `35.241.139.80, 27.223.84.195, 213.209.159.115, 77.90.185.21`. | MySQL Auth |
| Sep 13–Sep 19 (continuous) | `mysqld.exe` and `TermService` accept inbound connections from public IPs throughout the window (106 and 146 total respectively), confirming continuous internet exposure of both services, not just at the moment of attack. | DeviceNetworkEvents |
| Sep 18 02:47–Sep 19 11:23 | No MySQL audit records (gap; cause not determined). | MySQL Auth, Query |
| Sep 19 11:21–11:23 | `hgmuser` RDP session starts (11:21:30); MySQL Workbench starts (11:23:02); `root@localhost` logon fails once (11:23:27). | DeviceProcessEvents; MySQL Auth |
| Sep 19 11:24–11:28 | **DETECTION:** local session lists tables/columns of `recover_your_data` (11:24:00), queries `cr_corp_089.credentials` four times, and reads `recover_your_data` (11:27:55). | MySQL Query |
| Sep 19 11:33 | `77.90.185.30` still attempting root and sa logons. | MySQL Auth |
| Sep 19 11:35–11:37 | MsSense writes `DisableEnterpriseAuthProxyValueToRestoreAfterIsolation` (11:35:56); Azure guest agents run netstat/arp/route/ipconfig repeatedly until 11:37:01. Whether this reflects isolation or platform diagnostics is not determined. | DeviceRegistryEvents; DeviceProcessEvents |

##### KQL:
```kql
union
  (MySQLAudit_CL_Auth  | where ActionType == "LogonSuccess" | project TimeGenerated, Src="MySQL Auth",  Detail=strcat(Username, "@", IpAddress)),
  (MySQLAudit_CL_Query | where Query matches regex @"(?i)^\s*(DROP|CREATE (DATABASE|USER)|GRANT|REVOKE|PURGE|RESET|SHUTDOWN)" or Query has "RECOVER_YOUR_DATA"
                       | project TimeGenerated, Src="MySQL Query", Detail=Query),
  (DeviceLogonEvents   | where ActionType == "LogonSuccess" and isnotempty(RemoteIP) | project TimeGenerated, Src="DeviceLogon", Detail=strcat(AccountName, " ", RemoteIP)),
  (DeviceNetworkEvents | where ActionType == "InboundConnectionAccepted" and RemoteIP == "64.89.163.168"
                       | project TimeGenerated, Src="DeviceNetwork", Detail=strcat(InitiatingProcessCommandLine, " <- ", RemoteIP))
| where TimeGenerated between (datetime(2026-09-13) .. datetime(2026-09-20))
| order by TimeGenerated asc
```


<img width="708" height="567" alt="image" src="https://github.com/user-attachments/assets/cdbc81e7-b93d-4d5f-a13d-4245beea73f3" />


---

## 6. Root Cause / Attack Vector

**Most likely vector:** authenticated root access to a MySQL service reachable from the internet. Remote `root@'%'` with full privileges was created on Sep 13 at 22:48. All 70 successful MySQL logons with a recorded user are root. The ransom session's first successful login came seconds after two no-password probes, so the attacker held a valid password.

- **Unknown:** how the root password was obtained. Only 2 of 193 failed logons used a password, so high-volume password guessing against MySQL is not evidenced. Credential reuse, a weak password, or prior theft are all possible.
- **Confirmed:** both services were open to the internet. `DeviceNetworkEvents` shows `mysqld.exe` accepted 106 inbound connections from 97 distinct public IPs (Sep 13 18:21 UTC–Sep 19 16:34 UTC), and `TermService` (RDP) accepted 146 from 136 distinct public IPs (Sep 14 04:22 UTC–Sep 19 16:31 UTC). The ransom IP `64.89.163.168` was accepted by `mysqld.exe` at 02:36:20 UTC, 9 seconds before its first successful root login, consistent with a single, direct connection rather than a proxy or pivot. `LocalPort` is not recorded in this table, so attribution is by accepting process; NSG rules and Traffic Analytics were not supplied.
- **Parallel RDP exposure:** 15 successful network logons as "administrator" from four IPs (Sep 14–15) after brute force. No processes, registry changes, or file activity attributable to that account appear in the Device tables, and none of these IPs touched MySQL. Whether RDP access exposed the MySQL credential is not determined.
- **Account mapping:** the `hgmuser` profile SID ends in `-500` (the built-in Administrator RID) per the registry paths, so how the "administrator" logon name maps to a local account should be verified.
- **Coverage gaps:** `DeviceLogonEvents` ends Sep 17 14:37 while MySQL probing continued to Sep 19. Some `DeviceLogonEvents` rows are duplicates with blank RemoteIP.

##### KQL:
```kql
// Brute force followed by success
DeviceLogonEvents | where LogonType == "Network" and isnotempty(RemoteIP)
| summarize Fail=countif(ActionType=="LogonFailed"), Success=countif(ActionType=="LogonSuccess"), FirstSuccess=minif(TimeGenerated, ActionType=="LogonSuccess") by RemoteIP, AccountName
| where Success > 0 and Fail > 5

// Who created remote root, and from where
MySQLAudit_CL_Query | where Query has_any ("CREATE USER", "GRANT ", "REVOKE") | project TimeGenerated, Query

// Exposure (LocalPort not recorded in this export; grouped by accepting process instead)
DeviceNetworkEvents | where DeviceName =~ "corp-han0-8598a" and ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public"
| summarize Conns=count(), DistinctIPs=dcount(RemoteIP), First=min(TimeGenerated), Last=max(TimeGenerated) by InitiatingProcessFileName

// Post-logon activity by the RDP account
DeviceProcessEvents | where AccountName =~ "administrator" | project TimeGenerated, ProcessCommandLine, InitiatingProcessCommandLine
```

<img width="426" height="76" alt="image" src="https://github.com/user-attachments/assets/f920d683-e412-4c0e-9afd-e112a38839a1" />

<img width="494" height="156" alt="image" src="https://github.com/user-attachments/assets/45ae2de9-c181-451a-b6ef-a993c75842ab" />

<img width="706" height="74" alt="image" src="https://github.com/user-attachments/assets/ff14c9b2-66b9-492b-9a88-fafc44dc9f10" />

---

## 7. Response Actions

**Taken:** Not determined from available logs. No containment, credential reset, or restore is visible; the only possibly related artefacts are the isolation-named registry value and Azure agent diagnostics at 11:35–11:37 on Sep 19, which are inconclusive.

| Phase | Recommended |
|---|---|
| **Containment** | Block inbound 3306 and 3389 from the internet at the NSG and host firewall now (confirmed reachable — see Section 6). Add the IPs in Section 4 to perimeter blocks and MDE custom indicators. Preserve evidence first (VM disk snapshot, MySQL general log, the `RECOVER_YOUR_DATA` table). Isolate the device in MDE if forensic acquisition is pending. |
| **Eradication** | Drop `root@'%'` and any other non-local root; reset root and all local admin passwords. Audit `mysql.user`, `mysql.db`, events, triggers, and UDFs for attacker additions. Review Windows Security 4624/4625 for the "administrator" sessions and rebuild the host if interactive use is found. Rotate every credential stored in `cr_corp_089.credentials`. |
| **Recovery** | Restore from an off-host backup (binary logs were purged, so on-host point-in-time recovery is unlikely). Validate integrity before reconnecting applications. Do not pay or contact the actor. Monitor for leaked data and the wallet addresses. Involve legal/privacy on notification duties if `cr_corp_089` is real customer or payment data. |

##### KQL:
```kql
// After containment: any remaining external root access?
MySQLAudit_CL_Auth | where TimeGenerated > datetime(<containment time UTC>)
| where ActionType == "LogonSuccess" and IpAddress !in ("localhost")
| summarize Logons=count() by IpAddress

// After containment: any remaining public inbound connections at all?
DeviceNetworkEvents | where DeviceName =~ "corp-han0-8598a" and TimeGenerated > datetime(<containment time UTC>)
| where ActionType == "InboundConnectionAccepted" and RemoteIPType == "Public"
| summarize Conns=count() by InitiatingProcessFileName

DeviceInfo | where DeviceName =~ "corp-han0-8598a" | summarize arg_max(TimeGenerated, *)
| project DeviceName, IsInternetFacing, InternetFacingReason, PublicIP
```


<img width="469" height="65" alt="image" src="https://github.com/user-attachments/assets/615efddb-1b8b-4e77-9548-60b3c95a9002" />


---

## 8. Evidence

| Artefact | Used for |
|---|---|
| `mysql_audit_query_logs.csv` (397 rows; Sep 13 21:53–Sep 19 11:33) | Ransom notes, reads, DROPs, log purge, CREATE USER, detection activity |
| `mysql_audit_auth_logs.csv` (269 rows: 193 failed, 76 successful) | Source IPs, root logins, probe patterns |
| `devicelogonevents` (134 rows; Sep 14 00:41–Sep 17 14:37) | RDP brute force and administrator logons |
| `devicenetworkevents` (17,118 rows; Sep 13 17:59–Sep 19 16:37 UTC) | Confirms internet exposure of MySQL (3306) and RDP (3389): 106 and 146 inbound connections accepted from 97 and 136 distinct public IPs respectively. Ties the ransom IP to a direct connection to `mysqld.exe` seconds before its first successful login. |
| `deviceprocessevents` (5,656), `deviceregistryevents` (7,505), `devicefileevents` (13,609) | MySQL install/service start, hgmuser session activity, and a search for attacker execution, persistence, and encryption (none found). High-volume net/auditpol/wevtutil/schtasks activity was traced to MsSense/SenseIR/MsMpEng collectors and excluded. |
| Not supplied | `NTANetAnalytics`, NSG flow logs, MySQL error log, backups, Windows Security log |

*Data-quality notes: a few auth rows have blank user/IP (bare "Connect" entries) and one "client" row; some rows show ingestion lag against RawData time; MySQL connection IDs reset several times (e.g. 175→12 between Sep 15 03:01 and 11:30), indicating service restarts or VM power cycles. `DeviceNetworkEvents` has no `LocalPort` field, so port-level attribution relies on the accepting process name.*

##### KQL:
```kql
union withsource=Table MySQLAudit_CL_Auth, MySQLAudit_CL_Query, DeviceLogonEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceFileEvents
| where DeviceName =~ "corp-han0-8598a"
| summarize Rows=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by Table
```


<img width="916" height="252" alt="image" src="https://github.com/user-attachments/assets/62444869-b849-4860-b873-1bc4a660e932" />


---

## 9. Lessons Learned / Recommendations

1. **Remove internet exposure of 3306 and 3389.** Confirmed open to the public internet (106 and 146 accepted connections from 97 and 136 distinct public IPs respectively). Bind `mysqld` to localhost or a private subnet; reach RDP through a bastion, VPN, or just-in-time access. This closes both observed entry paths.
2. **Eliminate `root@'%'` and shared admin credentials.** Use least-privilege application accounts per database, strong unique passwords, TLS required, and account lockout. Never grant `ALL ... WITH GRANT OPTION` to a remote-capable account.
3. **Keep tested, off-host backups.** The attacker purged binary logs, so local logs are not a recovery plan. Take scheduled dumps to separate storage and test a restore.
4. **Alert on the behaviours seen here.** Root login from a non-allowlisted IP; `DROP DATABASE`, `PURGE BINARY LOGS`, `RESET MASTER`; any database named `RECOVER_YOUR_DATA`; RDP success after 10+ failures from the same IP; new external IPs accepted by `mysqld.exe` or `TermService` outside a maintenance window.
5. **Close logging gaps.** Forward `NTANetAnalytics` for byte-level flow visibility (`DeviceNetworkEvents` has no port or volume fields), enable row-level visibility for bulk reads, and confirm why `DeviceLogonEvents` stops Sep 17 and MySQL audit is empty from Sep 18 02:47–Sep 19 11:23.
6. **Treat exposed data as compromised.** Rotate credentials held in `cr_corp_089`, assess notification duties with legal, and monitor for disclosure and for the wallet addresses in Section 4.

##### KQL:
```kql
// Detection rule candidate
MySQLAudit_CL_Query
| where Query matches regex @"(?i)^\s*(DROP\s+DATABASE|PURGE\s+BINARY|RESET\s+MASTER)" or Query has "RECOVER_YOUR_DATA"

MySQLAudit_CL_Auth
| where ActionType == "LogonSuccess" and Username == "root" and IpAddress !in ("localhost", "<allowlist>")

// New public IP reaching mysqld or RDP
DeviceNetworkEvents
| where ActionType == "InboundConnectionAccepted" and RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("mysqld.exe", "svchost.exe")
```



<img width="706" height="268" alt="image" src="https://github.com/user-attachments/assets/be3ae453-4a76-4a72-997e-b1d9bd74edc4" />

<img width="502" height="271" alt="image" src="https://github.com/user-attachments/assets/cfa989f8-9be9-464a-8608-73d0ef3a3e71" />




