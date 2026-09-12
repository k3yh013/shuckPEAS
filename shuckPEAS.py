#!/usr/bin/env python3
"""
shuckPEAS.py  -  Run and/or analyze winPEAS OR linPEAS output for OSCP
privilege-escalation wins. Auto-detects Windows vs Linux (override with --os).
 
Usage:
    # 1) Analyze an output file you already captured
    ./winPEAS.exe | tee winPoutput.txt
    ./linpeas.sh | tee linPoutput.txt
    python3 shuckPEAS.py winPoutput.txt
    python3 shuckPEAS.py linPoutput.txt
 
    # 2) Let shuckPEAS run PEAS for you and analyse automatically
    python3 shuckPEAS.py --run .\winPEASx64.exe --run-args "systeminfo userinfo"
    python3 shuckPEAS.py --run .\winPEASany_ofs.exe --save loot.txt --md out.md
    python3 shuckPEAS.py --run .\winPEAS.bat
    python3 shuckPEAS.py --run .\winPEAS.ps1
    python3 shuckPEAS.py --run ./linpeas.sh --run-args "-a"

    # other ways to feed it output:
    python3 shuckPEAS.py < winPoutput.txt
    cat winPoutput.txt | python3 shuckPEAS.py
    python3 shuckPEAS.py winPoutput.txt --md findings.md   # also save a report
    python3 shuckPEAS.py linPoutput.txt --no-color         # plain text
 
What it does
------------
Optionally runs PEAS and scans every line against a rule set
of known priv-esc vectors. Hits are grouped by severity:
 
    [CRITICAL] near-guaranteed / direct-to-SYSTEM vectors and cleartext creds
    [HIGH]     strong leads worth exploiting next
    [INFO]     context you should note (OS build, AV, etc.)
 
Each hit shows the matching line(s) plus a short "why it matters / next step"
note. It is an analysis aid, not a substitute for reading the full output.
"""
 
import argparse
import os
import re
import shlex
import subprocess
import sys
from collections import OrderedDict
 
# --------------------------------------------------------------------------- #
# Terminal colors
# --------------------------------------------------------------------------- #
# Strip ANSI/VT escapes: CSI (colors/cursor), OSC (title), and other 2-byte
# escapes. winPEAS/linPEAS colour output heavily; carriage returns (CRLF) and
# stray control bytes are removed separately in scan().
ANSI_RE = re.compile(
    r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)'   # OSC ... (BEL or ST terminated)
    r'|\x1b\[[0-?]*[ -/]*[@-~]'            # CSI (SGR colors, cursor moves, ...)
    r'|\x1b[@-Z\\-_]'                      # other single escapes
)
CTRL_RE = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')  # leftover control bytes (keep \t=09)

# --------------------------------------------------------------------------- #
# Noise / absence filters (real winPEAS-ng & linPEAS output is very chatty)
# --------------------------------------------------------------------------- #
# Lines that are scaffolding/hints, not findings - skipped before rule matching.
_NOISE = re.compile(
    r'hacktricks'                                  # help links (every section)
    r'|carlospolop|peass|@hacktricks_live'
    r'|^\s*[ÈÉÍ»ºÌÄ¿ÀÙÚ³│┌└├─╔╚╠║╣═]'              # hint bullet / section bars
    r'|Check if you|Check for |Check if the|Check 3rd|Check the '
    r'|Indicates (a|an|the)|special privilege over an object|colou?r'
    r'|^\s*ADVISORY|Do you like PEASS|Follow on|Learn Cloud|Linux PE &'
    r'|at winPEAS\.|System\.Management|ManagementException|^\s*at [A-Za-z]'
    r'|You can (find|learn)|for help, run|winpeass?\.exe --help'
    r'|^\s*\[[-X]\]'                                # winPEAS negative/error markers
    r'|^\s*https?://\S+\s*$',
    re.IGNORECASE)
# Lines that assert something is absent / not exploitable - also skipped.
_ABSENT = re.compile(
    r"isn'?t (available|present|vulnerable|set)|is not (available|present|vulnerable|set|enabled)"
    r"|not vulnerable|no obvious|does ?n'?t grant|access denied|cannot open"
    r"|\bnot found\b|no results|0 results?|nothing found|could ?n'?t"
    r"|unable to (enumerate|open|access|read)|\[error\]"
    r"|no .{0,30} (found|detected|configured)|were not found|are not found",
    re.IGNORECASE)


def clean_line(raw):
    """Strip ANSI escapes, carriage returns, and stray control bytes."""
    return CTRL_RE.sub("", ANSI_RE.sub("", raw).replace("\r", "")).rstrip("\n")
 
 
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
# Banner - three peas dancing in a pod + pipe-font wordmark
# --------------------------------------------------------------------------- #
# Each row is (role, text); role picks the colour. UTF-8 first, ASCII fallback.
_BANNER_UTF = [
    ("rule", "╔══════════════════════════════════════════════════╗"),
    ("pea",  "       \\╪/        \\╪/           \\╪/"),
    ("pea",  "     \\(•ᴗ•)/     ᕕ(•ᴗ•)ᕗ      \\(•ᴗ•)/"),
    ("pea",  "        ╯ ╰         ╯ ╰           ╯ ╰"),
    ("gap",  ""),
    ("word", "      ┌─┐┬ ┬┬ ┬┌─┐┬┌─   ┌─┐┌─┐┌─┐┌─┐"),
    ("word", "      └─┐├─┤│ ││  ├┴┐   ├─┘├┤ ├─┤└─┐"),
    ("word", "      └─┘┴ ┴└─┘└─┘┴ ┴   ┴  └─┘┴ ┴└─┘"),
    ("gap",  ""),
    ("tag",  "     winPEAS + linPEAS  ─►  ranked priv-esc wins"),
    ("rule", "╚══════════════════════════════════════════════════╝"),
]
_BANNER_ASCII = [
    ("rule", "+==================================================+"),
    ("pea",  "      \\o/          \\o/        \\o/"),
    ("pea",  "     <(^o^)>      <(^o^)>      <(^o^)>"),
    ("pea",  "      / \\          / \\        / \\"),
    ("gap",  ""),
    ("word", "               s h u c k P E A S"),
    ("gap",  ""),
    ("tag",  "     winPEAS + linPEAS  ->  ranked priv-esc wins"),
    ("rule", "+==================================================+"),
]


def print_banner(use_color=True, stream=None):
    """Print the dancing-peas banner (UTF-8, ASCII fallback) to stderr."""
    stream = stream or sys.stderr
    enc = getattr(stream, "encoding", None) or "utf-8"
    try:
        "╔•ᴗᕕ╲╪─►".encode(enc)      # can this terminal render the fancy glyphs?
        lines = _BANNER_UTF
    except (UnicodeEncodeError, LookupError):
        lines = _BANNER_ASCII

    role_color = {
        "rule": C.BOLD + C.GRN,
        "pea":  C.BOLD + C.GRN,
        "word": C.BOLD + C.MAG,
        "tag":  C.DIM + C.CYN,
        "gap":  "",
    }
    for role, text in lines:
        if use_color:
            stream.write(f"{role_color[role]}{text}{C.RESET}\n")
        else:
            stream.write(text + "\n")
    stream.write("\n")
    stream.flush()
 
 
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
 
WIN_RULES = [
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


# =========================================================================== #
# LINUX rules (linPEAS)
# =========================================================================== #
LINUX_RULES = [
    # ------------------------------------------------------------------- #
    # CRITICAL - sudo / SUID / capabilities (direct root)
    # ------------------------------------------------------------------- #
    Rule(CRIT, "Sudo", "Sudo rights (sudo -l)",
         r'NOPASSWD|\(ALL(\s*:\s*ALL)?\)|may run the following commands|'
         r'is allowed to run',
         "sudo -l output. NOPASSWD or (ALL) ALL on a binary -> run its GTFOBins "
         "sudo entry for a root shell. Check every allowed command on GTFOBins.",
         negate=r'not allowed to run sudo|may not run'),
    Rule(CRIT, "Sudo", "Sudo env_keep / LD_PRELOAD",
         r'env_keep|LD_PRELOAD|LD_LIBRARY_PATH|SETENV|setenv',
         "sudo env_keep+=LD_PRELOAD (or SETENV) -> compile a malicious .so and "
         "load it as root via any sudo-allowed command."),
    Rule(CRIT, "Sudo", "Sudo version (Baron Samedit)",
         r'sudo version|CVE-2021-3156|Baron Samedit|CVE-2019-14287',
         "Check the sudo version: <1.9.5p2 is vulnerable to Baron Samedit "
         "(CVE-2021-3156) heap overflow -> root. Also note the '!-1'/-u#-1 bug "
         "(CVE-2019-14287)."),
    Rule(CRIT, "SUID/SGID", "SUID binary",
         r'r-s|rws|\bSUID\b|suid',
         "SUID-root binary -> check GTFOBins; known ones (find, vim, nmap, bash, "
         "cp, python, etc.) give instant root. linPEAS highlights the juicy ones."),
    Rule(CRIT, "SUID/SGID", "SGID binary",
         r'\bSGID\b|sgid|--s---|-r-s',
         "SGID binary -> GTFOBins SGID entry can escalate to that group (e.g. "
         "shadow/disk) or aid a chain to root."),
    Rule(CRIT, "Capabilities", "Linux capabilities",
         r'cap_setuid|cap_setgid|cap_dac_read_search|cap_dac_override|'
         r'cap_sys_admin|cap_sys_ptrace|cap_sys_module|capabilities',
         "A binary with cap_setuid+ep (or similar) -> GTFOBins capabilities entry "
         "(e.g. python -c 'import os;os.setuid(0);os.system(\"/bin/sh\")')."),

    # ------------------------------------------------------------------- #
    # CRITICAL - passwd/shadow, groups, NFS, container escapes
    # ------------------------------------------------------------------- #
    Rule(CRIT, "Files", "Writable /etc/passwd or /etc/shadow",
         r'/etc/passwd.*writ|writ.*/etc/passwd|/etc/shadow.*writ|'
         r'writ.*/etc/shadow|passwd file.*writ',
         "Writable /etc/passwd -> add a root user (openssl passwd -1). Writable "
         "/etc/shadow -> replace root's hash. Instant root."),
    Rule(CRIT, "Files", "Readable /etc/shadow",
         r'/etc/shadow.*(read|:.*:)|shadow.*readable|root:\$[0-9y]',
         "Readable /etc/shadow -> crack root's hash offline (john/hashcat) or "
         "pass it around."),
    Rule(CRIT, "Groups", "Dangerous group (docker/lxd/disk/adm)",
         r'\b(docker|lxd|lxc)\b|docker\.sock|inside the docker|'
         r'\bdisk\b group|group.*\b(docker|lxd|disk|adm|shadow)\b',
         "docker/lxd -> mount host / run privileged container = root. disk -> "
         "read raw fs (debugfs). shadow/adm -> read hashes/logs. GTFOBins covers "
         "the container escapes."),
    Rule(CRIT, "NFS", "NFS no_root_squash",
         r'no_root_squash|/etc/exports|insecure.*export',
         "no_root_squash export -> mount it as a low-priv user elsewhere, drop a "
         "SUID-root shell into it, run it on the victim as root."),
    Rule(CRIT, "Kernel", "pkexec / Polkit (PwnKit)",
         r'pkexec|polkit|PwnKit|CVE-2021-4034',
         "Vulnerable pkexec -> PwnKit local root (CVE-2021-4034). Nearly "
         "universal on unpatched 2021-era Linux."),

    # ------------------------------------------------------------------- #
    # CRITICAL - credentials
    # ------------------------------------------------------------------- #
    Rule(CRIT, "Credentials", "Private SSH key",
         r'BEGIN (RSA|OPENSSH|DSA|EC|PRIVATE) PRIVATE KEY|id_rsa|id_dsa|'
         r'id_ed25519|\.pem\b',
         "Readable private key -> SSH as its owner (or to other hosts). Check "
         "authorized_keys/known_hosts for where it lands."),
    Rule(CRIT, "Credentials", "Passwords in files / history / env",
         r'\.bash_history|mysql_history|\.netrc|wp-config|\.env\b|database\.yml|'
         r'settings\.py|DB_PASS|(pass(word)?|passwd|pwd)\s*[:=]\s*\S',
         "Config/history/.env files and password= assignments frequently hold DB "
         "or service creds. Try every one for su/ssh (credential reuse).",
         negate=r'password\s+(required|sufficient|requisite|optional|\[)|'
                r'pam_|=\s*(0|1|-1|yes|no|true|false|""|\x27\x27)\s*$'),

    # ------------------------------------------------------------------- #
    # CRITICAL/HIGH - cron / services / PATH
    # ------------------------------------------------------------------- #
    Rule(CRIT, "Cron", "Writable cron job / root script",
         r'writ.*cron|cron.*writ|/etc/cron.*writ|writable.*\.(sh|py)|'
         r'crontab.*root',
         "A cron/script running as root that you can write -> drop a reverse "
         "shell or SUID payload and wait for the schedule."),
    Rule(HIGH, "Cron", "Cron jobs / wildcards",
         r'/etc/cron|crontab|cron\.d|\* \* \* \*|wildcard|tar .*\*',
         "Review cron entries for writable scripts, relative paths, or wildcard "
         "injection (tar/rsync/chown wildcards -> arg injection)."),
    Rule(HIGH, "Services", "Writable systemd/init service",
         r'\.service.*writ|writ.*\.service|/etc/systemd.*writ|init\.d.*writ|'
         r'writ.*init\.d|writable.*timer',
         "Writable service unit or its ExecStart binary -> replace it; runs as "
         "root on next start/reboot (or trigger it)."),
    Rule(HIGH, "PATH", "Writable folder in $PATH / '.' in PATH",
         r'writ.*PATH|PATH.*writ|\bPATH=.*(::|:\.|:\s|^\.)|\.\s+in.*PATH',
         "A writable dir in root's PATH (or '.' present) -> plant a binary a root "
         "script calls by bare name."),

    # ------------------------------------------------------------------- #
    # HIGH - kernel exploits, perms, groups
    # ------------------------------------------------------------------- #
    Rule(HIGH, "Kernel", "Possible kernel exploit",
         r'Dirty ?COW|DirtyPipe|CVE-2016-5195|CVE-2022-0847|CVE-2021-22555|'
         r'CVE-2017-16995|Linux version [0-3]\.|exploit suggester',
         "Old kernel -> DirtyCOW (CVE-2016-5195), DirtyPipe (5.8-5.16.11, "
         "CVE-2022-0847), etc. Confirm exact version; run linux-exploit-suggester "
         "(les.sh). Kernel exploits are a last resort in OSCP - can crash the box."),
    Rule(HIGH, "Permissions", "World/group-writable sensitive file",
         r'is writable|writable by|group writable|world writable|Writable file|'
         r'\bo\+w\b|777',
         "A root-owned file/dir writable by you or your group -> tamper for "
         "escalation. Confirm exact owner + perms with ls -la / find."),
    Rule(HIGH, "Files", "Interesting / backup files",
         r'\.kdbx|\.git\b|backup|\.bak\b|\.old\b|\.swp\b|creds?\.|password.*\.txt|'
         r'\.ovpn\b|\.kdb\b',
         "Loose secrets/backups. .kdbx = KeePass (keepass2john). Check backups, "
         ".ovpn, and dotfiles for creds."),

    # ------------------------------------------------------------------- #
    # INFO - environment / context
    # ------------------------------------------------------------------- #
    Rule(INFO, "System", "OS / kernel / distro",
         r'Linux version|Kernel version|uname|/etc/os-release|DISTRIB_|'
         r'Distributor|Operative system',
         "Record exact kernel + distro for kernel-exploit matching "
         "(linux-exploit-suggester)."),
    Rule(INFO, "Users", "Users / current context",
         r'uid=\d|gid=\d|Current user|whoami|home directories|/etc/passwd content',
         "Note your uid/gid/groups and other users -> confirms privilege level "
         "and su targets."),
    Rule(INFO, "Network", "Listening ports / internal services",
         r'LISTEN|127\.0\.0\.1:|0\.0\.0\.0:|netstat|\bss -|Active Internet',
         "Internal-only ports -> pivot/port-forward targets (local DB, admin "
         "panel, redis, etc.)."),
    Rule(INFO, "Software", "Installed software / processes",
         r'dpkg -l|rpm -qa|installed|Useful software|running as root|ps aux|'
         r'Process.*root',
         "Software/processes running as root are exploit targets - version-check "
         "each against exploit-db / GTFOBins."),
]


# =========================================================================== #
# OS auto-detection (winPEAS vs linPEAS output)
# =========================================================================== #
WIN_MARKERS = re.compile(
    r'SeImpersonate|HKLM|HKCU|AlwaysInstallElevated|winPEAS|C:\\\\|'
    r'\bAdministrator|\bNTLM\b|System32|Microsoft Windows|\.exe\b', re.I)
LIN_MARKERS = re.compile(
    r'/etc/passwd|/etc/shadow|\bSUID\b|\bsudo\b|uid=\d|gid=\d|/home/|/root/|'
    r'Linux version|cap_setuid|linpeas|/usr/bin|/bin/(ba)?sh|GTFOBins', re.I)


def detect_os(lines):
    """Return 'linux' or 'win' by counting OS-specific markers in the output."""
    w = l = 0
    for raw in lines:
        s = ANSI_RE.sub("", raw)
        w += len(WIN_MARKERS.findall(s))
        l += len(LIN_MARKERS.findall(s))
    return "linux" if l > w else "win"


def rules_for(os_key):
    """(rules, label) for an os key ('win' or 'linux')."""
    if os_key == "linux":
        return LINUX_RULES, "linPEAS"
    return WIN_RULES, "winPEAS"
 
 
# --------------------------------------------------------------------------- #
# Run winPEAS
# --------------------------------------------------------------------------- #
def build_command(exe, extra_args):
    """
    Build the launch command for any winPEAS flavor based on its extension:
 
        .exe  (winPEASany / winPEASx64 / winPEASx86, incl. *_ofs obfuscated)
              -> run the binary directly
        .bat  (winPEAS.bat)  -> cmd /c winPEAS.bat
        .ps1  (winPEAS.ps1)  -> powershell -NoProfile -ExecutionPolicy Bypass -File
        anything else        -> run directly and hope for the best
 
    .bat and .ps1 are Windows-only; the .exe builds also run under wine.
    """
    ext = os.path.splitext(exe)[1].lower()
    if ext == ".ps1":
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", exe] + extra_args
    if ext in (".bat", ".cmd"):
        return ["cmd", "/c", exe] + extra_args
    if ext == ".sh":                      # linpeas.sh (Linux)
        return ["bash", exe] + extra_args
    return [exe] + extra_args
 
 
def run_winpeas(exe, extra_args, save_path, use_color=True):
    """
    Launch winPEAS (any flavor), stream its live (coloured) output to the
    terminal, capture every line, and tee the raw text to save_path.
    Returns the captured lines.
    """
    cmd = build_command(exe, extra_args)
    hdr = "" if not use_color else C.BOLD + C.MAG
    end = "" if not use_color else C.RESET
    dim = "" if not use_color else C.DIM
    grn = "" if not use_color else C.GRN
 
    sys.stderr.write(f"{hdr}[*] Running: {' '.join(shlex.quote(c) for c in cmd)}{end}\n")
    sys.stderr.write(f"{dim}[*] Live winPEAS output below; analysis runs when it "
                     f"finishes...{end}\n\n")
    sys.stderr.flush()
 
    lines = []
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            universal_newlines=True,
            errors="replace",
        )
    except FileNotFoundError:
        sys.exit(f"[!] Could not launch: {' '.join(shlex.quote(c) for c in cmd)}\n"
                 f"    Check the path exists. winPEAS .exe/.bat/.ps1 are Windows "
                 f"payloads - run on the target (Windows), or use the .exe builds "
                 f"under wine. (.bat needs cmd.exe, .ps1 needs powershell.)")
    except OSError as e:
        sys.exit(f"[!] Failed to launch '{exe}': {e}")
 
    try:
        for line in proc.stdout:
            sys.stdout.write(line)     # echo winPEAS' own colours live
            sys.stdout.flush()
            lines.append(line)
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        sys.stderr.write(f"\n{dim}[*] winPEAS interrupted - triaging what we "
                         f"captured so far...{end}\n")
 
    if save_path:
        try:
            with open(save_path, "w", encoding="utf-8", errors="replace") as fh:
                fh.writelines(lines)
            sys.stderr.write(f"\n{grn}[+] Raw output saved to {save_path}{end}\n")
        except OSError as e:
            sys.stderr.write(f"\n[!] Could not save raw output to "
                             f"{save_path}: {e}\n")
    sys.stderr.write("\n")
    sys.stderr.flush()
    return lines
 
 
# --------------------------------------------------------------------------- #
# Core
# --------------------------------------------------------------------------- #
def scan(lines, rules):
    """Return OrderedDict: (severity, category, name, note) -> [ (lineno, text) ]"""
    findings = OrderedDict()
    for idx, raw in enumerate(lines, 1):
        line = clean_line(raw)
        stripped = line.strip()
        if not stripped:
            continue
        # skip winPEAS/linPEAS scaffolding, help links, and "not found" noise
        if _NOISE.search(stripped) or _ABSENT.search(stripped):
            continue
        for rule in rules:
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
 
 
def render(findings, use_color=True, rules=None, os_label="winPEAS"):
    if not use_color:
        C.disable()
    rules = rules if rules is not None else WIN_RULES

    out = []
    banner = f"{os_label} OSCP analysis"
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
                   f"analysis rules are not exhaustive.{C.RESET}")
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
        keys_sorted = sorted(keys, key=lambda k: [r.name for r in rules]
                             .index(k[2]) if k[2] in [r.name for r in rules]
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
    out.append(f"{C.DIM}Analysis only - always skim the full winPoutput.txt. "
               f"Line numbers (Lxxx) point back into that file.{C.RESET}")
    return "\n".join(out)
 
 
def render_markdown(findings, rules=None, os_label="winPEAS"):
    rules = rules if rules is not None else WIN_RULES
    md = [f"# {os_label} OSCP analysis\n"]
    by_sev = {CRIT: [], HIGH: [], INFO: []}
    for key in findings:
        by_sev[key[0]].append(key)
    md.append(f"**CRITICAL:** {len(by_sev[CRIT])} &nbsp; "
              f"**HIGH:** {len(by_sev[HIGH])} &nbsp; "
              f"**INFO:** {len(by_sev[INFO])}\n")
    order = [r.name for r in rules]
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
        sys.exit("No input. Pass a file (python3 shuckPEAS.py winPoutput.txt), "
                 "pipe via stdin, or run winPEAS with --run.")
    return sys.stdin.readlines()
 
 
def main():
    ap = argparse.ArgumentParser(
        description="Run and/or analyze winPEAS output for OSCP priv-esc wins.")
    ap.add_argument("file", nargs="?", default="-",
                    help="winPEAS output file to analyze (default: read stdin). "
                         "Ignored when --run is used.")
    ap.add_argument("--run", metavar="PEAS_FILE",
                    help="Execute this winPEAS/linPEAS file, tee its output, "
                         "then analyze it. Any flavor works: winPEASx64/x86/any "
                         "(incl. _ofs) .exe, winPEAS.bat, winPEAS.ps1, or "
                         "linpeas.sh. Must run on a host that can execute it "
                         "(Windows for winPEAS, .exe also under wine; Linux for "
                         "linpeas.sh).")
    ap.add_argument("--run-args", metavar='"ARGS"', default="",
                    help='Extra args passed straight to winPEAS (its own '
                         'switches), e.g. --run-args "systeminfo userinfo" to '
                         'run only those modules. Quote the whole string. Do '
                         "NOT use winPEAS's 'log' here - it writes to out.txt "
                         "instead of stdout; use shuckPEAS --save for a raw copy.")
    ap.add_argument("--save", metavar="RAW.txt",
                    help="Where to tee raw winPEAS output when using --run "
                         "(default: winPoutput.txt).")
    ap.add_argument("--md", metavar="OUT.md",
                    help="Also write a Markdown report for your notes.")
    ap.add_argument("--os", choices=["auto", "win", "linux"], default="auto",
                    help="Which PEAS output to expect: win (winPEAS) or linux "
                         "(linPEAS). Default auto-detects from the content.")
    ap.add_argument("--no-color", action="store_true",
                    help="Disable coloured terminal output.")
    ap.add_argument("--no-banner", action="store_true",
                    help="Suppress the dancing-peas startup banner.")
    args = ap.parse_args()
 
    use_color = not args.no_color
    if not args.no_banner:
        print_banner(use_color=use_color, stream=sys.stderr)

    if args.run:
        is_sh = args.run.lower().endswith(".sh")
        save_path = args.save or ("linpoutput.txt" if is_sh else "winPoutput.txt")
        extra = shlex.split(args.run_args) if args.run_args else []
        lines = run_winpeas(args.run, extra, save_path, use_color=use_color)
        # a .sh run is linPEAS unless the user forced --os
        run_hint = "linux" if is_sh else "win"
    else:
        if args.save:
            sys.stderr.write("[!] --save only applies with --run; ignoring.\n")
        lines = read_input(args.file)
        run_hint = None

    if args.os != "auto":
        os_key = args.os
    elif run_hint:
        os_key = run_hint
    else:
        os_key = detect_os(lines)
    rules, os_label = rules_for(os_key)

    how = "auto-detected" if args.os == "auto" else "forced"
    d = C.DIM if use_color else ""
    end = C.RESET if use_color else ""
    sys.stderr.write(f"{d}[*] Analyzing as {os_label} output ({how}).{end}\n\n")

    findings = scan(lines, rules)

    print(render(findings, use_color=use_color, rules=rules, os_label=os_label))

    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(findings, rules=rules, os_label=os_label))
        tag = C.GRN if use_color else ""
        end = C.RESET if use_color else ""
        print(f"\n{tag}[+] Markdown report written to {args.md}{end}")
 
 
if __name__ == "__main__":
    main()
