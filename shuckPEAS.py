
Analyze winpeas · PY
#!/usr/bin/env python3
"""
analyze_winpeas.py  -  Triage winPEAS output for OSCP privilege-escalation wins.
 
Usage:
    ./winPEAS.exe | tee winPoutput.txt      # on the target (or via your shell)
    python3 analyze_winpeas.py winPoutput.txt
 
    # other ways to feed it:
    python3 analyze_winpeas.py < winPoutput.txt
    cat winPoutput.txt | python3 analyze_winpeas.py
    python3 analyze_winpeas.py winPoutput.txt --md findings.md   # also save a report
    python3 analyze_winpeas.py winPoutput.txt --no-color         # plain text
 
What it does
------------
Strips winPEAS' ANSI colour codes, then scans every line against a rule set of
known Windows priv-esc vectors. Hits are grouped by severity:
 
    [CRITICAL] near-guaranteed / direct-to-SYSTEM vectors and cleartext creds
    [HIGH]     strong leads worth exploiting next
    [INFO]     context you should note (OS build for kernel exploits, AV, etc.)
 
Each hit shows the matching line(s) plus a short "why it matters / next step"
note. It is a triage aid, not a substitute for reading the full output.
"""
 
import argparse
import re
import sys
from collections import OrderedDict
 
# --------------------------------------------------------------------------- #
# Terminal colours
# --------------------------------------------------------------------------- #
ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')  # strip winPEAS' own colouring
 
 
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"
    MAG = "\033[95m"
    GRY = "\033[90m"
 
    _enabled = True
 
    @classmethod
    def disable(cls):
        cls._enabled = False
        for name in ("RESET", "BOLD", "DIM", "RED", "YEL", "GRN",
                     "CYN", "MAG", "GRY"):
            setattr(cls, name, "")
 
 
# Severity ordering / display
CRIT, HIGH, INFO = "CRITICAL", "HIGH", "INFO"
SEV_ORDER = {CRIT: 0, HIGH: 1, INFO: 2}
SEV_COLOR = {CRIT: lambda: C.RED, HIGH: lambda: C.YEL, INFO: lambda: C.CYN}
 
 
# --------------------------------------------------------------------------- #
# Rule model
# --------------------------------------------------------------------------- #
class Rule:
    """
    A detection rule.
 
    pattern  : compiled regex tested against each (ANSI-stripped) line.
    negate   : optional compiled regex; if it matches the line, the hit is
               dropped (used to kill obvious false positives / "not found").
    """
    __slots__ = ("severity", "category", "name", "pattern", "note", "negate")
 
    def __init__(self, severity, category, name, pattern, note, negate=None):
        self.severity = severity
        self.category = category
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.note = note
        self.negate = re.compile(negate, re.IGNORECASE) if negate else None
 
 
# A common "nothing here" pattern winPEAS prints; used to suppress noise.
NEG_NOT_FOUND = r'(not found|no .*found|does not exist|is not|couldn.?t|' \
                r'no .*detected|0 result|no results|nothing|denied to enumerate)'
 
RULES = [
    # ------------------------------------------------------------------- #
    # CRITICAL - token privileges (Potato / PrintSpoofer / driver loads)
    # ------------------------------------------------------------------- #
    Rule(CRIT, "Token Privileges", "SeImpersonatePrivilege",
         r'SeImpersonatePrivilege',
         "Potato attack territory. If Enabled -> PrintSpoofer / GodPotato / "
         "JuicyPotatoNG for instant SYSTEM. Classic on service accounts / IIS."),
    Rule(CRIT, "Token Privileges", "SeAssignPrimaryTokenPrivilege",
         r'SeAssignPrimaryTokenPrivilege',
         "Same family as SeImpersonate -> Potato attacks to SYSTEM."),
    Rule(CRIT, "Token Privileges", "SeDebugPrivilege",
         r'SeDebugPrivilege',
         "Inject into / dump SYSTEM processes (e.g. migrate to lsass, "
         "mimikatz, or ProcDump lsass for creds)."),
    Rule(CRIT, "Token Privileges", "SeBackupPrivilege",
         r'SeBackupPrivilege',
         "Read ANY file -> grab SAM+SYSTEM hives (reg save / robocopy /B) "
         "and dump local hashes offline with secretsdump."),
    Rule(CRIT, "Token Privileges", "SeRestorePrivilege",
         r'SeRestorePrivilege',
         "Write ANY file / registry -> overwrite a service binary, or "
         "utilman/sethc image-hijack for SYSTEM."),
    Rule(CRIT, "Token Privileges", "SeTakeOwnershipPrivilege",
         r'SeTakeOwnershipPrivilege',
         "Take ownership of any object -> re-ACL a SYSTEM binary/file you can "
         "then replace."),
    Rule(CRIT, "Token Privileges", "SeLoadDriverPrivilege",
         r'SeLoadDriverPrivilege',
         "Load a vulnerable/malicious driver (e.g. Capcom.sys) -> kernel code "
         "execution / SYSTEM."),
    Rule(CRIT, "Token Privileges", "SeManageVolumePrivilege",
         r'SeManageVolumePrivilege',
         "Can lead to full-disk write access -> SeManageVolumeExploit for "
         "SYSTEM."),
    Rule(CRIT, "Token Privileges", "SeTcbPrivilege",
         r'SeTcbPrivilege',
         "Act as part of the OS -> craft a token with SYSTEM/admin groups."),
    Rule(CRIT, "Token Privileges", "SeCreateTokenPrivilege",
         r'SeCreateTokenPrivilege',
         "Create arbitrary tokens -> forge a SYSTEM token."),
 
    # ------------------------------------------------------------------- #
    # CRITICAL - AlwaysInstallElevated
    # ------------------------------------------------------------------- #
    Rule(CRIT, "Misconfig", "AlwaysInstallElevated",
         r'AlwaysInstallElevated',
         "If set to 1 in BOTH HKLM and HKCU: any .msi runs as SYSTEM. "
         "msfvenom -f msi -> msiexec /quiet /qn /i evil.msi.",
         negate=r'(set to 0|= 0\b|not.*enabled|is not set)'),
 
    # ------------------------------------------------------------------- #
    # CRITICAL - cleartext / stored credentials
    # ------------------------------------------------------------------- #
    Rule(CRIT, "Credentials", "GPP cpassword",
         r'cpassword|Groups\.xml|gpp',
         "Group Policy Preferences password. cpassword is AES-encrypted with a "
         "public key -> gpp-decrypt / Get-GPPPassword for cleartext creds."),
    Rule(CRIT, "Credentials", "AutoLogon password",
         r'DefaultPassword|AutoAdminLogon|DefaultUserName',
         "Registry autologon creds in Winlogon. If AutoAdminLogon=1, "
         "DefaultUserName/DefaultPassword are usable cleartext creds."),
    Rule(CRIT, "Credentials", "Unattend / sysprep file",
         r'unattend\.xml|unattended\.xml|sysprep\.(xml|inf)|autounattend',
         "Install-time answer files often hold a base64 or cleartext local "
         "admin password."),
    Rule(CRIT, "Credentials", "PowerShell history",
         r'ConsoleHost_history|PSReadline',
         "PowerShell console history frequently contains typed passwords, "
         "connection strings, or -AsPlainText secrets."),
    Rule(CRIT, "Credentials", "Saved Windows credentials (cmdkey)",
         r'cmdkey|currently stored credentials|Target:\s*(Domain|Legacy)',
         "Stored creds usable with runas /savecred /user:... even without "
         "knowing the password."),
    Rule(CRIT, "Credentials", "PuTTY / WinSCP / SSH sessions",
         r'putty|winscp|\.ppk\b|ProxyPassword|SessionPassword|Sessions\\',
         "Saved session secrets. PuTTY ProxyPassword and WinSCP sessions store "
         "recoverable/cleartext passwords."),
    Rule(CRIT, "Credentials", "VNC password",
         r'\bvnc\b|winvnc|vncviewer|UltraVNC|password.*vnc',
         "VNC passwords are stored with a fixed DES key -> trivially "
         "decryptable (vncpwd)."),
    Rule(CRIT, "Credentials", "Web/app config secrets",
         r'connectionString|web\.config|applicationHost\.config|\.config.*password|'
         r'appsettings\.json',
         "Config files commonly hold DB connection strings and service "
         "account passwords in cleartext."),
    Rule(CRIT, "Credentials", "WiFi password (netsh)",
         r'Key Content|wlan.*profile|SSID name',
         "netsh wlan show profile ... key=clear reveals cleartext WiFi keys - "
         "often password-reuse gold."),
    Rule(CRIT, "Credentials", "SNMP community string",
         r'snmp.*(community|string)|community.*string',
         "SNMP community strings are effectively passwords and are frequently "
         "reused elsewhere."),
    Rule(CRIT, "Credentials", "Generic password in text",
         r'(pass(word)?|pwd|passwd)\s*[:=]\s*\S',
         "A key=value with a password. Verify it is a real secret (winPEAS "
         "also lists field NAMES), then try it everywhere (creds reuse).",
         negate=r'(passwordreveal|passwordexpires|password required|maxpassword|'
                r'minpassword|password history|password age|password changeable|'
                r'password expires|password last set|password not req|'
                r'password complexity|=\s*(0|1|-1|yes|no|true|false|never|'
                r'\(null\)|n/a|none)\s*$|policy)'),
    Rule(CRIT, "Credentials", "Private key material",
         r'BEGIN (RSA|OPENSSH|DSA|EC|PRIVATE) PRIVATE KEY|id_rsa|\.pem\b|\.pfx\b',
         "Private key on disk -> reuse for SSH/RDP/cert auth to other hosts."),
    Rule(CRIT, "Credentials", "Hash / SAM material",
         r'\bSAM\b.*hive|reg save.*sam|:[0-9a-f]{32}:[0-9a-f]{32}:::|'
         r'aad3b435b51404ee',
         "Looks like an NTLM hash or SAM hive reference -> pass-the-hash or "
         "offline cracking."),
 
    # ------------------------------------------------------------------- #
    # CRITICAL/HIGH - services
    # ------------------------------------------------------------------- #
    Rule(CRIT, "Services", "Modifiable service binary/config",
         r'you can (modify|change|write)|permissions.*(everyone|authenticated '
         r'users|users|BUILTIN\\Users).*(write|fullcontrol|allaccess|modify)|'
         r'WriteData/AddFile|WriteDAC|WriteOwner|Service permissions',
         "You can alter a service's binary or config -> point it at your payload "
         "and restart (or wait for reboot) for SYSTEM. Check with sc/accesschk."),
    Rule(HIGH, "Services", "Unquoted service path",
         r'unquoted|no quotes.*path',
         "Unquoted path with spaces + a writable parent dir -> drop "
         "C:\\Program.exe style payload. Confirm write perms on the folder."),
    Rule(HIGH, "Services", "Writable service registry key",
         r'HKLM\\.*services.*(write|fullcontrol|modify)|service registry.*write',
         "Writable service registry key -> change ImagePath to your binary."),
 
    # ------------------------------------------------------------------- #
    # HIGH - DLL hijacking / PATH / autoruns / scheduled tasks
    # ------------------------------------------------------------------- #
    Rule(HIGH, "DLL Hijack", "Writable folder in %PATH%",
         r'writable.*path|path.*writable|dll hijack|hijackable',
         "A writable directory that is in the system PATH -> DLL/exe hijacking "
         "against services or admin-run tools."),
    Rule(HIGH, "Autoruns", "Writable autorun / startup",
         r'autorun|startup.*writable|writable.*startup|run key.*writable|'
         r'HKLM\\.*\\Run',
         "Writable autorun binary or startup entry -> replace it; executes when "
         "an admin logs in."),
    Rule(HIGH, "Scheduled Tasks", "Modifiable scheduled task",
         r'scheduled task|schtasks|taskcache|task.*writable|writable.*task',
         "A scheduled task running as a privileged user whose binary/script you "
         "can write -> swap payload and wait for the trigger."),
 
    # ------------------------------------------------------------------- #
    # HIGH - UAC / creds harvesting posture
    # ------------------------------------------------------------------- #
    Rule(HIGH, "UAC", "UAC configuration",
         r'EnableLUA|ConsentPromptBehavior|FilterAdministratorToken|'
         r'LocalAccountTokenFilterPolicy',
         "Check UAC posture. EnableLUA=0 or LocalAccountTokenFilterPolicy=1 "
         "eases lateral/admin token use; also relevant for UAC bypasses."),
    Rule(HIGH, "Credentials", "WDigest / LSA cleartext",
         r'UseLogonCredential|wdigest|LSA Protection|RunAsPPL|LmCompatibility',
         "UseLogonCredential=1 (or WDigest enabled) means cleartext creds sit in "
         "LSASS -> mimikatz. RunAsPPL=0 means LSASS isn't protected."),
    Rule(HIGH, "Credentials", "Cached domain credentials",
         r'cached.*credential|cachedlogonscount|CACHEDLOGONS',
         "Cached domain logons can be dumped (cached hashes) and cracked "
         "offline."),
    Rule(HIGH, "Credentials", "Credential Manager / Vault",
         r'credential manager|vault|Windows Vault|dpapi',
         "Credential Manager / DPAPI blobs may be decryptable to recover stored "
         "web/RDP/network passwords."),
 
    # ------------------------------------------------------------------- #
    # HIGH - interesting file/registry perms
    # ------------------------------------------------------------------- #
    Rule(HIGH, "Permissions", "Weak file/folder permissions",
         r'(everyone|authenticated users|BUILTIN\\Users|\bUsers\b).*'
         r'(fullcontrol|allaccess|modify|write|F |M )|Interesting Permissions',
         "A privileged binary/dir writable by your group -> replace/plant. "
         "Confirm exactly which principal and access with accesschk."),
    Rule(HIGH, "Misconfig", "Interesting file found",
         r'interesting file|\.kdbx|\.git\b|\bnotes?\.txt|password.*\.txt|'
         r'creds?\.txt|backup.*\.(bak|zip|7z)|\.vhd',
         "Loose secrets/backups. .kdbx = KeePass DB (crack with keepass2john). "
         "Check backups and notes for creds."),
 
    # ------------------------------------------------------------------- #
    # INFO - context for kernel exploits & environment
    # ------------------------------------------------------------------- #
    Rule(INFO, "System", "OS build / hostname",
         r'Host Name|OS Name|OS Version|Microsoft Windows.*Build|'
         r'System Boot Time|Original Install',
         "Record exact build/version for kernel-exploit matching "
         "(Watson / wesng / windows-exploit-suggester)."),
    Rule(INFO, "System", "Hotfixes / patch level",
         r'\bKB\d{6,7}\b|hotfix|hoyfix|installed.*update',
         "Few hotfixes -> higher chance a kernel exploit (MS16-032, MS15-051, "
         "etc.) applies. Feed systeminfo to a suggester."),
    Rule(INFO, "System", "Architecture",
         r'System Type|x64-based|x86-based|AMD64|PROCESSOR_ARCHITECTURE',
         "Match your payload/exploit architecture (x86 vs x64) to the target."),
    Rule(INFO, "Defenses", "Antivirus / Defender",
         r'defender|antivirus|\bAV\b|MpPreference|WinDefend|firewall',
         "Know what's watching. Affects which payloads/tools survive - may need "
         "AMSI bypass or obfuscation."),
    Rule(INFO, "Users", "Privileged / admin accounts",
         r'is member of.*administrators|part of.*admin|Administrators group|'
         r'currently logged on|whoami',
         "Note your groups and other admins. Confirms whether you're already "
         "elevated or which account to target."),
    Rule(INFO, "Network", "Listening ports / internal services",
         r'listening|0\.0\.0\.0:|127\.0\.0\.1:|LISTENING|Active Connections',
         "Internal-only ports may expose services to pivot/port-forward to "
         "(e.g. a local admin panel or DB)."),
    Rule(INFO, "Software", "Installed software / running processes",
         r'installed software|program files|running.*as SYSTEM|'
         r'non Microsoft.*process',
         "Third-party software (esp. running as SYSTEM) is a prime exploit "
         "target - version-check each against exploit-db."),
]
 
 
# --------------------------------------------------------------------------- #
# Core
# --------------------------------------------------------------------------- #
def scan(lines):
    """Return OrderedDict: (severity, category, name, note) -> [ (lineno, text) ]"""
    findings = OrderedDict()
    for idx, raw in enumerate(lines, 1):
        line = ANSI_RE.sub("", raw).rstrip("\n")
        stripped = line.strip()
        if not stripped:
            continue
        for rule in RULES:
            if rule.pattern.search(line):
                if rule.negate and rule.negate.search(line):
                    continue
                key = (rule.severity, rule.category, rule.name, rule.note)
                findings.setdefault(key, [])
                # de-dupe identical text, cap evidence lines per rule
                if len(findings[key]) < 12 and stripped not in \
                        [t for _, t in findings[key]]:
                    findings[key].append((idx, stripped))
    return findings
 
 
def render(findings, use_color=True):
    if not use_color:
        C.disable()
 
    out = []
    banner = "winPEAS OSCP triage"
    out.append(f"{C.BOLD}{C.MAG}{'=' * 70}{C.RESET}")
    out.append(f"{C.BOLD}{C.MAG}  {banner}{C.RESET}")
    out.append(f"{C.BOLD}{C.MAG}{'=' * 70}{C.RESET}")
 
    # group keys by severity
    by_sev = {CRIT: [], HIGH: [], INFO: []}
    for key in findings:
        by_sev[key[0]].append(key)
 
    counts = {s: len(by_sev[s]) for s in by_sev}
    out.append(
        f"{C.RED}CRITICAL: {counts[CRIT]}{C.RESET}   "
        f"{C.YEL}HIGH: {counts[HIGH]}{C.RESET}   "
        f"{C.CYN}INFO: {counts[INFO]}{C.RESET}"
    )
    out.append("")
 
    if not findings:
        out.append(f"{C.GRN}No rule matched. Read the raw output manually - "
                   f"triage rules are not exhaustive.{C.RESET}")
        return "\n".join(out)
 
    for sev in (CRIT, HIGH, INFO):
        keys = by_sev[sev]
        if not keys:
            continue
        col = SEV_COLOR[sev]()
        out.append(f"{col}{C.BOLD}{'-' * 70}{C.RESET}")
        out.append(f"{col}{C.BOLD}[{sev}]  ({len(keys)} finding type"
                   f"{'s' if len(keys) != 1 else ''}){C.RESET}")
        out.append(f"{col}{C.BOLD}{'-' * 70}{C.RESET}")
        # keep RULES order within a severity
        keys_sorted = sorted(keys, key=lambda k: [r.name for r in RULES]
                             .index(k[2]) if k[2] in [r.name for r in RULES]
                             else 999)
        for (s, category, name, note) in keys_sorted:
            evidence = findings[(s, category, name, note)]
            out.append(f"{col}{C.BOLD}  * {name}{C.RESET} "
                       f"{C.GRY}[{category}]{C.RESET}")
            out.append(f"    {C.DIM}why: {note}{C.RESET}")
            for lineno, text in evidence:
                shown = text if len(text) <= 160 else text[:157] + "..."
                out.append(f"      {C.GRY}L{lineno}:{C.RESET} {shown}")
            out.append("")
 
    out.append(f"{C.MAG}{'=' * 70}{C.RESET}")
    out.append(f"{C.DIM}Triage only - always skim the full winPoutput.txt. "
               f"Line numbers (Lxxx) point back into that file.{C.RESET}")
    return "\n".join(out)
 
 
def render_markdown(findings):
    md = ["# winPEAS OSCP triage\n"]
    by_sev = {CRIT: [], HIGH: [], INFO: []}
    for key in findings:
        by_sev[key[0]].append(key)
    md.append(f"**CRITICAL:** {len(by_sev[CRIT])} &nbsp; "
              f"**HIGH:** {len(by_sev[HIGH])} &nbsp; "
              f"**INFO:** {len(by_sev[INFO])}\n")
    order = [r.name for r in RULES]
    for sev in (CRIT, HIGH, INFO):
        if not by_sev[sev]:
            continue
        md.append(f"## {sev}\n")
        keys_sorted = sorted(by_sev[sev],
                             key=lambda k: order.index(k[2])
                             if k[2] in order else 999)
        for (s, category, name, note) in keys_sorted:
            evidence = findings[(s, category, name, note)]
            md.append(f"### {name}  _({category})_")
            md.append(f"**Why:** {note}\n")
            md.append("```")
            for lineno, text in evidence:
                md.append(f"L{lineno}: {text}")
            md.append("```\n")
    return "\n".join(md)
 
 
def read_input(path):
    if path and path != "-":
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    if sys.stdin.isatty():
        sys.exit("No input. Pass a file: python3 analyze_winpeas.py "
                 "winPoutput.txt  (or pipe via stdin).")
    return sys.stdin.readlines()
 
 
def main():
    ap = argparse.ArgumentParser(
        description="Triage winPEAS output for OSCP priv-esc wins.")
    ap.add_argument("file", nargs="?", default="-",
                    help="winPEAS output file (default: read stdin).")
    ap.add_argument("--md", metavar="OUT.md",
                    help="Also write a Markdown report for your notes.")
    ap.add_argument("--no-color", action="store_true",
                    help="Disable coloured terminal output.")
    args = ap.parse_args()
 
    lines = read_input(args.file)
    findings = scan(lines)
 
    print(render(findings, use_color=not args.no_color))
 
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(findings))
        tag = "" if args.no_color else C.GRN
        end = "" if args.no_color else C.RESET
        print(f"\n{tag}[+] Markdown report written to {args.md}{end}")
 
 
if __name__ == "__main__":
    main()
 

