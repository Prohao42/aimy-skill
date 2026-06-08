import json, re
from typing import Optional, Dict
import requests

GRAPHQL_PATTERNS = [
    r'/graphql',
    r'/graphiql',
    r'/v1/graphql',
    r'/v2/graphql',
    r'/api/graphql',
    r'/query',
    r'graphql',
]

INTROSPECTION_QUERY = """{"query":"query { __schema { types { name fields { name type { name kind ofType { name kind } } } } } }"}"""

COMMON_MUTATIONS = [
    'mutation { login(username: "test", password: "test") { token } }',
    'mutation { createUser(username: "admin", password: "admin") { id } }',
    '{ __typename }',
]


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

    for endpoint in [graphql_url, base + "/query", base + "/graphiql", base + "/v1/graphql"]:
        try:
            h = {"Content-Type": "application/json"}
            r = sess.post(endpoint, data=INTROSPECTION_QUERY, headers=h,
                          timeout=timeout, verify=False)
            if r.status_code == 200:
                try:
                    j = r.json()
                    if "__schema" in str(j) or "types" in str(j) or "data" in j:
                        result["endpoints"].append(endpoint)
                        result["introspection"] = True
                        result["evidence"].append("introspection enabled at %s" % endpoint)
                        result["vulnerable"] = True
                        schema = j.get("data", {}).get("__schema", {})
                        types = schema.get("types", [])
                        result["types_found"] = len(types)
                        break
                except:
                    pass
            r2 = sess.get(endpoint, timeout=timeout, verify=False)
            if "graphql" in r2.text.lower() or "__schema" in r2.text:
                result["endpoints"].append(endpoint)
                result["vulnerable"] = True
        except:
            pass

    if not result["vulnerable"]:
        for mutation in COMMON_MUTATIONS:
            try:
                r = sess.post(graphql_url, data=mutation,
                              headers={"Content-Type": "application/json"},
                              timeout=timeout, verify=False)
                if r.status_code == 200:
                    try:
                        j = r.json()
                        if "data" in j and j["data"]:
                            result["endpoints"].append(graphql_url)
                            result["evidence"].append("mutation accepted: %s" % mutation[:30])
                            result["vulnerable"] = True
                            break
                    except:
                        pass
            except:
                pass

    return result
