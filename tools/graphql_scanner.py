import json, re
from typing import Optional, Dict
import requests

from tools.log_utils import get_logger

logger = get_logger("graphql_scanner")

GRAPHQL_PATHS = [
    '/graphql', '/graphiql', '/v1/graphql', '/v2/graphql',
    '/api/graphql', '/query',
]

INTROSPECTION_QUERY = json.dumps({
    "query": "query { __schema { types { name fields { name type { name kind ofType { name kind } } } } } }"
})

COMMON_MUTATIONS = [
    'mutation { login(username: "test", password: "test") { token } }',
    'mutation { createUser(username: "admin", password: "admin") { id } }',
    '{ __typename }',
]


def has_graphql_schema(body: str) -> bool:
    try:
        j = json.loads(body)
        data = j.get("data", {})
        if "__schema" in data or "__typename" in str(data):
            return True
        schema = data.get("__schema", {})
        if isinstance(schema, dict) and "types" in schema:
            types = schema["types"]
            return isinstance(types, list) and len(types) > 5
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return False


def check(url: str, param: str = None, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "endpoints": [], "introspection": False, "evidence": []}

    base = url.rstrip("/")

    if any(p in base for p in ["/graphql", "/query", "/graphiql"]):
        graphql_url = base
    else:
        graphql_url = base + "/graphql"

    endpoints_to_test = [graphql_url]
    for p in GRAPHQL_PATHS:
        if p not in graphql_url:
            endpoints_to_test.append(base + p)

    for endpoint in set(endpoints_to_test):
        try:
            r = sess.post(endpoint, json=json.loads(INTROSPECTION_QUERY),
                          timeout=timeout, verify=False)
            if r.status_code == 200 and has_graphql_schema(r.text):
                result["endpoints"].append(endpoint)
                result["introspection"] = True
                result["evidence"].append("introspection enabled at %s" % endpoint)
                result["vulnerable"] = True
                try:
                    schema = r.json().get("data", {}).get("__schema", {})
                    result["types_found"] = len(schema.get("types", []))
                except Exception:
                    pass
                break
        except Exception as e:
            logger.debug("graphql introspection at %s: %s", endpoint, e)

    if not result["vulnerable"]:
        for endpoint in endpoints_to_test[:3]:
            try:
                r = sess.get(endpoint, timeout=timeout, verify=False)
                if r.status_code == 200 and has_graphql_schema(r.text):
                    result["endpoints"].append(endpoint)
                    result["vulnerable"] = True
                    result["evidence"].append("graphql endpoint found: %s" % endpoint)
                    break
            except Exception as e:
                logger.debug("graphql get %s: %s", endpoint, e)

    if not result["vulnerable"]:
        for mutation in COMMON_MUTATIONS:
            try:
                r = sess.post(graphql_url, json=json.loads(mutation),
                              timeout=timeout, verify=False)
                if r.status_code == 200:
                    try:
                        j = r.json()
                        if "data" in j and j["data"]:
                            result["endpoints"].append(graphql_url)
                            result["evidence"].append("mutation accepted: %s" % mutation[:30])
                            result["vulnerable"] = True
                            break
                    except Exception:
                        pass
            except Exception as e:
                logger.debug("graphql mutation: %s", e)

    return result
