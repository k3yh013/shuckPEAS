# shuckPEAS

`shuckPEAS.py` runs and/or analyzes [winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) output and surfaces the privilege-escalation that actually matters, token privileges, cleartext creds, misconfigs, grouped by severity with a next-step note for each hit. Built for OSCP.

## Why

winPEAS output is huge. shuckPEAS strips the ANSI coloring, scans every line against ~35 known Windows priv-esc rules, and prints a ranked report so you can go straight for the win instead of scrolling for ten minutes.

## Usage

### Analyze output you already captured

```bash
# on the target
./winPEAS.exe | tee winPoutput.txt

# then analyze
python3 shuckPEAS.py winPoutput.txt
```

Also reads from stdin or a redirect:

```bash
cat winPoutput.txt | python3 shuckPEAS.py
python3 shuckPEAS.py < winPoutput.txt
```

### Run winPEAS and analyze in one shot

`--run` launches winPEAS, streams its live output, tees the raw text to a file, then analyzes it automatically. **Any flavor works** — the extension decides how it's launched:

```bash
python3 shuckPEAS.py --run .\winPEASx64.exe --run-args "systeminfo userinfo"
python3 shuckPEAS.py --run .\winPEASany_ofs.exe --save loot.txt --md out.md
python3 shuckPEAS.py --run .\winPEAS.bat
python3 shuckPEAS.py --run .\winPEAS.ps1
```

| File type | How it's launched |
|-----------|-------------------|
| `.exe` (`winPEASx64` / `x86` / `any`, incl. `_ofs` obfuscated) | run directly |
| `.bat` (`winPEAS.bat`) | `cmd /c winPEAS.bat` |
| `.ps1` (`winPEAS.ps1`) | `powershell -NoProfile -ExecutionPolicy Bypass -File` |

`--run` has to run on a host that can execute the file: Windows for all of them, and the `.exe` builds also run under `wine`. `.bat`/`.ps1` need `cmd.exe` / `powershell` present. Ctrl+C mid-run still analyzes whatever was captured.

### Options

| Flag | Description |
|------|-------------|
| `--run FILE` | Execute a winPEAS file (any flavor), tee its output, then analyze. |
| `--run-args "ARGS"` | winPEAS's own switches, passed straight through. E.g. `"systeminfo userinfo"` runs only those modules. Quote the whole string. |
| `--save RAW.txt` | Where to tee raw output when using `--run` (default: `winPoutput.txt`). |
| `--md OUT.md` | Also write a Markdown report for your notes/report. |
| `--no-color` | Plain text output (for piping or logging). |

No dependencies — Python 3 standard library only. Runs anywhere, including a stock Kali box.

### winPEAS arguments you can pass via `--run-args`

These are winPEAS's *own* switches (from the [PEASS-ng docs](https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASexe/README.md)) — shuckPEAS just forwards them. With none, winPEAS runs all standard (non-slow) checks, which is usually what you want.

| winPEAS arg | Effect |
|-------------|--------|
| `systeminfo userinfo processinfo servicesinfo applicationsinfo networkinfo windowscreds browserinfo filesinfo eventsinfo` | Run only the module(s) you name (space-separated). |
| `domain` | Also enumerate domain information. |
| `searchall` | Search the expanded list of credential filenames. |
| `notcolor` | Disable winPEAS color output. |
| `wait` | Pause for input between tests. |
| `debug` | Extra debug detail. |
| `-lolbas` | Also run the (slower) LOLBAS search. |
| `-linpeas=<URL>` | Also fetch and run linpeas. |
| `log` | **Don't use with `--run`** — winPEAS writes to `out.txt` instead of stdout, so shuckPEAS gets nothing to analyze. Use `--save` for a raw copy instead. |

## What it flags

Findings are grouped into three tiers, each with the matching line numbers (so you can jump back into `winPoutput.txt`) and a short "why it matters / next step":

- **CRITICAL** — token privileges (`SeImpersonate`/`SeAssignPrimaryToken` → Potato/PrintSpoofer, `SeDebug`, `SeBackup`/`SeRestore`, `SeLoadDriver`, `SeTakeOwnership`, …), `AlwaysInstallElevated`, and cleartext creds (GPP `cpassword`, AutoLogon, `unattend.xml`, PowerShell history, saved `cmdkey` creds, PuTTY/WinSCP, VNC, web.config connection strings, WiFi keys, SNMP, private keys, modifiable service binaries).
- **HIGH** — unquoted service paths, writable `%PATH%` dirs (DLL hijack), writable autoruns/scheduled tasks, UAC posture, WDigest/LSA cleartext, cached creds, Credential Manager/DPAPI, weak file permissions, KeePass `.kdbx` and loose backups/notes.
- **INFO** — OS build + hotfix count (for kernel-exploit matching via [wesng](https://github.com/bitsadmin/wesng)/Watson), architecture, AV/Defender, your groups, listening ports, third-party software.

## Example

```
======================================================================
  shuckPEAS
======================================================================
CRITICAL: 11   HIGH: 5   INFO: 5

[CRITICAL]
  * SeImpersonatePrivilege [Token Privileges]
    why: Potato attack territory. If Enabled -> PrintSpoofer / GodPotato for SYSTEM.
      L14: SeImpersonatePrivilege   Impersonate a client after authentication  Enabled
  ...
```

## Caveats

This is an **analysis aid, not ground truth**. The rules are pattern-based and not exhaustive. The generic-password rule is tuned to skip policy noise (min length, max age), but it can still surface field *names* winPEAS prints without values, so eyeball each cred hit before you trust it.

## Disclaimer

For authorized penetration testing, CTFs, and educational use only. Use it only against systems you own or have explicit written permission to test.
