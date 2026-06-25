import re
from typing import Dict, List, Optional
import requests

from tools.log_utils import get_logger

logger = get_logger("recon.tech")

TECH_SIGNATURES = [
    ("nginx", "nginx", re.compile(r"nginx[/\s]", re.I), "header", "Server"),
    ("apache", "Apache HTTPD", re.compile(r"Apache", re.I), "header", "Server"),
    ("iis", "IIS", re.compile(r"IIS", re.I), "header", "Server"),
    ("cloudflare", "Cloudflare", re.compile(r"cloudflare", re.I), "header", "Server"),
    ("openresty", "OpenResty", re.compile(r"openresty", re.I), "header", "Server"),
    ("caddy", "Caddy", re.compile(r"caddy", re.I), "header", "Server"),
    ("gunicorn", "Gunicorn", re.compile(r"gunicorn", re.I), "header", "Server"),
    ("tomcat", "Tomcat", re.compile(r"Apache-Coyote|Tomcat", re.I), "header", "Server"),
    ("jetty", "Jetty", re.compile(r"Jetty", re.I), "header", "Server"),
    ("weblogic", "WebLogic", re.compile(r"WebLogic", re.I), "header", "Server"),
    ("websphere", "WebSphere", re.compile(r"WebSphere", re.I), "header", "Server"),
    ("php", "PHP", re.compile(r"PHP[/\s]", re.I), "header", "X-Powered-By"),
    ("asp.net", "ASP.NET", re.compile(r"ASP\.NET", re.I), "header", "X-Powered-By"),
    ("python", "Python", re.compile(r"Python", re.I), "header", "Server"),
    ("wsgi", "WSGI", re.compile(r"WSGI", re.I), "header", "Server"),

    ("wordpress", "WordPress", re.compile(r"/wp-content/|/wp-includes/|/wp-admin/|wp-json", re.I), "body", None),
    ("joomla", "Joomla", re.compile(r"/components/|/modules/|/templates/|Joomla", re.I), "body", None),
    ("drupal", "Drupal", re.compile(r"Drupal|/sites/default/|/core/", re.I), "body", None),
    ("magento", "Magento", re.compile(r"Magento|/skin/frontend/|/media/", re.I), "body", None),
    ("shopify", "Shopify", re.compile(r"Shopify|myshopify\.com", re.I), "body", None),
    ("woocommerce", "WooCommerce", re.compile(r"/wp-content/plugins/woocommerce", re.I), "body", None),

    ("spring", "Spring", re.compile(r"Spring|org\.springframework|/actuator/|/swagger-resources", re.I), "body", None),
    ("django", "Django", re.compile(r"csrfmiddlewaretoken|__cfduid|Django", re.I), "body", None),
    ("flask", "Flask", re.compile(r"Flask|Jinja|Werkzeug", re.I), "header", "Server"),
    ("express", "Express", re.compile(r"Express|connect.sid", re.I), "header", "X-Powered-By"),
    ("rails", "Ruby on Rails", re.compile(r"Rails|rails|\.erb", re.I), "header", "X-Powered-By"),
    ("laravel", "Laravel", re.compile(r"Laravel|XSRF-TOKEN|laravel_session", re.I), "header", "Set-Cookie"),
    ("symfony", "Symfony", re.compile(r"symfony|symphony", re.I), "body", None),
    ("thinkphp", "ThinkPHP", re.compile(r"ThinkPHP", re.I), "body", None),
    ("yii", "Yii", re.compile(r"Yii|__csrf|_csrf", re.I), "body", None),
    ("cakephp", "CakePHP", re.compile(r"CakePHP", re.I), "body", None),

    ("react", "React", re.compile(r"react|_react|ReactDOM|createRoot", re.I), "body", None),
    ("vue", "Vue.js", re.compile(r"vue\.js|vue\.min\.js|__vue__|createApp", re.I), "body", None),
    ("angular", "Angular", re.compile(r"angular|ng-app|ng-version|_angular", re.I), "body", None),
    ("jquery", "jQuery", re.compile(r"jquery|jQuery", re.I), "body", None),
    ("nextjs", "Next.js", re.compile(r"__NEXT_DATA__|/_next/", re.I), "body", None),
    ("nuxt", "Nuxt.js", re.compile(r"__NUXT__|nuxt", re.I), "body", None),
    ("gatsby", "Gatsby", re.compile(r"___gatsby", re.I), "body", None),

    ("nginx_ingress", "Nginx Ingress", re.compile(r"nginx-ingress", re.I), "header", "Server"),
    ("kong", "Kong", re.compile(r"kong", re.I), "header", "Server"),
    ("traefik", "Traefik", re.compile(r"traefik", re.I), "header", "Server"),
    ("haproxy", "HAProxy", re.compile(r"HAProxy", re.I), "header", "Server"),
    ("envoy", "Envoy", re.compile(r"envoy", re.I), "header", "Server"),
    ("istio", "Istio", re.compile(r"istio", re.I), "header", "Server"),

    ("swagger", "Swagger", re.compile(r"swagger|/api-docs|/swagger-resources", re.I), "body", None),
    ("graphql", "GraphQL", re.compile(r"graphql|__typename|__schema", re.I), "body", None),
    ("prometheus", "Prometheus", re.compile(r"prometheus", re.I), "body", None),
    ("grafana", "Grafana", re.compile(r"grafana", re.I), "body", None),
    ("kibana", "Kibana", re.compile(r"kibana", re.I), "body", None),
    ("jenkins", "Jenkins", re.compile(r"Jenkins|jenkins", re.I), "header", "X-Jenkins"),
    ("gitlab", "GitLab", re.compile(r"GitLab|gitlab", re.I), "body", None),
    ("redmine", "Redmine", re.compile(r"Redmine", re.I), "body", None),

    ("redis", "Redis", re.compile(r"redis", re.I), "header", "Server"),
    ("mysql", "MySQL", re.compile(r"MySQL", re.I), "header", "Server"),
    ("postgres", "PostgreSQL", re.compile(r"PostgreSQL|postgres", re.I), "header", "Server"),
    ("mongodb", "MongoDB", re.compile(r"MongoDB|mongo", re.I), "header", "Server"),
    ("elasticsearch", "Elasticsearch", re.compile(r"Elasticsearch", re.I), "header", "Server"),

    ("akamai", "AkamaiGHost", re.compile(r"AkamaiGHost", re.I), "header", "Server"),
    ("fastly", "Fastly", re.compile(r"Fastly|X-Served-By.*Fastly", re.I), "header", "Server"),
    ("cloudfront", "CloudFront", re.compile(r"CloudFront|x-amz-cf-id", re.I), "header", "Server"),
    ("s3", "AWS S3", re.compile(r"x-amz-request-id|x-amz-id-2|<Code>NoSuchBucket</Code>", re.I), "header", None),
    ("azure", "Azure", re.compile(r"azure|Azure", re.I), "header", "Server"),
]


def fingerprint_tech(url: str, sess: Optional[requests.Session] = None,
                     timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
        sess.verify = False
        sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    result = {
        "url": url,
        "technologies": [],
        "headers": {},
        "status": None,
        "body_hints": [],
    }

    try:
        r = sess.get(url, timeout=timeout)
        result["status"] = r.status_code
        result["headers"] = dict(r.headers)
        body_lower = r.text.lower()[:50000] if r.text else ""

        for tech_id, name, pattern, source, header in TECH_SIGNATURES:
            matched = False
            if source == "header" and header:
                val = r.headers.get(header, "")
                matched = bool(pattern.search(val))
            elif source == "body":
                matched = bool(pattern.search(body_lower))
            if matched:
                result["technologies"].append({
                    "id": tech_id,
                    "name": name,
                    "confidence": "high",
                    "source": source,
                })

        if r.elapsed:
            result["response_time"] = r.elapsed.total_seconds()

        interesting = [
            "actuator", "swagger", "graphql", "phpinfo", "debug",
            "health", "metrics", "prometheus", ".env", "git",
            "admin", "login", "dashboard", "api/health",
        ]
        hints = [h for h in interesting if h in body_lower]
        result["body_hints"] = hints

        if "X-Frame-Options" not in r.headers:
            result["missing_security_headers"] = result.get("missing_security_headers", []) + ["X-Frame-Options"]
        if "Content-Security-Policy" not in r.headers:
            result["missing_security_headers"] = result.get("missing_security_headers", []) + ["CSP"]
        if "X-Content-Type-Options" not in r.headers:
            result["missing_security_headers"] = result.get("missing_security_headers", []) + ["X-Content-Type-Options"]

    except requests.RequestException as e:
        logger.debug("tech fingerprint %s: %s", url, e)

    return result
