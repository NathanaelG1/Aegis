#!/usr/bin/env python3
"""Restricted HTTP/MCP client. Needs only its own role token; never a provider key.

No third-party Python packages. TLS is mandatory except for literal loopback IPs.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 16384
AGENT_METHODS = (
    "discover_operations", "prepare_operation", "request_approval",
    "invoke_approved", "get_run_status", "cancel",
)
OWNER_METHODS = ("pending", "inspect", "approve", "cancel", "revoke", "evidence")


class ClientError(Exception):
    """Static, non-sensitive errors only."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ClientError("redirect_denied")


class Client:
    def __init__(self, url, token_file, role, instance=None):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/") or not parsed.hostname):
            raise ClientError("invalid_url")
        if parsed.scheme != "https":
            try:
                loopback = ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError:
                loopback = False
            if parsed.scheme != "http" or not loopback:
                raise ClientError("tls_required")
        path = Path(token_file)
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid() or metadata.st_size != 65):
            raise ClientError("invalid_token_file")
        value = path.read_text()
        if (not value.endswith("\n") or len(value) != 65
                or any(c not in "0123456789abcdef" for c in value[:-1])):
            raise ClientError("invalid_token_file")
        self._token = value[:-1]
        self.url = url.rstrip("/")
        self.role = role
        self.instance = instance
        # No ambient proxy configuration or redirects can reroute Authorization.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        if data is not None and len(data) > MAX_BYTES:
            raise ClientError("invalid_request")
        request = urllib.request.Request(
            self.url + path, data=data,
            headers={"Authorization": "Bearer " + self._token,
                     "Content-Type": "application/json"},
            method="GET" if body is None else "POST",
        )
        try:
            with self.opener.open(request, timeout=5) as response:
                raw = response.read(131073)
            if len(raw) > 131072:
                raise ClientError("invalid_response")
            result = json.loads(raw)
        except urllib.error.HTTPError as error:
            # Never print HTTP exception objects, request headers, or response dumps.
            raise ClientError("http_" + str(error.code)) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise ClientError("broker_unavailable") from None
        if not isinstance(result, dict):
            raise ClientError("invalid_response")
        if self.instance and result.get("instance_id") != self.instance:
            raise ClientError("instance_changed")
        return result

    def session(self):
        session = self.request("/v1/session")
        instance = session.get("instance_id")
        if (not isinstance(instance, str) or len(instance) != 64
                or any(c not in "0123456789abcdef" for c in instance)):
            raise ClientError("invalid_response")
        return session

    def call(self, method, params=None):
        if not self.instance:
            raise ClientError("instance_id_required")
        if method not in (AGENT_METHODS if self.role == "agent" else OWNER_METHODS):
            raise ClientError("method_denied")
        action = {"method": method}
        if params is not None:
            action["params"] = params
        body = {"instance_id": self.instance}
        if self.role == "agent":
            body["request"] = {"version": 1, "action": action}
        else:
            body["action"] = action
        return self.request("/v1/" + self.role, body)


def tools():
    handle = {"type": "object", "properties": {"prepared_request_id": {"type": "integer", "minimum": 1}},
              "required": ["prepared_request_id"], "additionalProperties": False}
    prepare = {"type": "object", "properties": {
        "request_id": {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[A-Za-z0-9_-]+$"},
        "profile_id": {"type": "string", "enum": ["issue-status"]},
        "parameters": {"type": "object", "properties": {
            "repository_id": {"type": "integer", "enum": [4242]},
            "issue_number": {"type": "integer", "minimum": 1, "maximum": 4294967295}},
            "required": ["repository_id", "issue_number"], "additionalProperties": False}},
        "required": ["request_id", "profile_id", "parameters"], "additionalProperties": False}
    return [{"name": method, "description": "Synthetic operation only; owner approval occurs separately.",
             "inputSchema": prepare if method == "prepare_operation" else
             {"type": "object", "properties": {}, "additionalProperties": False}
             if method == "discover_operations" else handle} for method in AGENT_METHODS]


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_member")
        result[key] = value
    return result


def mcp(client):
    """Thin stdio MCP client: pins one broker instance for the process lifetime."""
    if client.role != "agent":
        raise ClientError("method_denied")
    client.instance = client.session()["instance_id"]
    initialized = False
    for _ in range(256):
        line = sys.stdin.buffer.readline(MAX_BYTES + 1)
        if not line:
            return
        identifier = None
        try:
            if len(line) > MAX_BYTES or not line.endswith(b"\n"):
                raise ValueError("invalid_request")
            request = json.loads(line, object_pairs_hook=unique_object)
            if not isinstance(request, dict):
                raise ValueError("invalid_request")
            identifier = request.get("id")
            if (request.get("jsonrpc") != "2.0" or isinstance(identifier, bool)
                    or identifier is None and "id" in request
                    or identifier is not None and not isinstance(identifier, (str, int))
                    or set(request) - {"id", "jsonrpc", "method", "params"}):
                raise ValueError("invalid_request")
            if "id" not in request:  # Notifications never invoke tools.
                continue
            method = request.get("method")
            params = request.get("params", {})
            if method == "initialize" and not initialized:
                if (not isinstance(params, dict) or params.get("protocolVersion") != "2025-11-25"
                        or not isinstance(params.get("capabilities"), dict)
                        or not isinstance(params.get("clientInfo"), dict)):
                    raise ValueError("unsupported_version")
                initialized = True
                result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "aegis-sprite-demo", "version": "0.1.0"},
                          "instructions": "Fake-secret operations only. Ask the owner to inspect and approve; never supply a secret."}
            elif method == "ping":
                result = {}
            elif not initialized:
                raise ClientError("interaction_required")
            elif method == "tools/list" and params == {}:
                result = {"tools": tools()}
            elif method == "tools/call":
                if (not isinstance(params, dict) or set(params) != {"name", "arguments"}
                        or params["name"] not in AGENT_METHODS or not isinstance(params["arguments"], dict)):
                    raise ValueError("invalid_request")
                name, arguments = params["name"], params["arguments"]
                if name == "discover_operations" and arguments:
                    raise ValueError("invalid_request")
                response = client.call(name, None if name == "discover_operations" else arguments)
                result = {"content": [{"type": "text", "text": json.dumps(response)}],
                          "isError": response.get("error") is not None}
            else:
                raise ValueError("invalid_request")
            output = {"jsonrpc": "2.0", "id": identifier, "result": result}
        except (ValueError, TypeError, KeyError, RecursionError):
            output = {"jsonrpc": "2.0", "id": identifier if isinstance(identifier, (str, int)) else None,
                      "error": {"code": -32600, "message": "invalid_request"}}
        except ClientError as error:
            output = {"jsonrpc": "2.0", "id": identifier,
                      "error": {"code": -32000, "message": str(error)}}
        print(json.dumps(output), flush=True)
        if len(line) > MAX_BYTES or not line.endswith(b"\n"):
            return


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--role", choices=("owner", "agent"), required=True)
    parser.add_argument("--instance-id")
    parser.add_argument("method", help="session, mcp (agent only), review (owner only), or role API method")
    parser.add_argument("params", nargs="?", help="JSON parameters, or request ID for review")
    args = parser.parse_args()
    client = Client(args.url, args.token_file, args.role, args.instance_id)
    if args.method == "mcp":
        mcp(client)
        return
    if args.method == "session":
        result = client.session()
    elif args.method == "review" and args.role == "owner":
        review = client.call("inspect", {"prepared_request_id": int(args.params)})
        if review.get("error"):
            result = review
        else:
            print(json.dumps(review["result"]["plan"], indent=2), file=sys.stderr)
            if input("Type approve to authorize this exact plan (15-second request lifetime): ") != "approve":
                raise ClientError("approval_canceled")
            result = client.call("approve", {"review_id": review["result"]["review_id"]})
    else:
        params = json.loads(args.params, object_pairs_hook=unique_object) if args.params is not None else None
        result = client.call(args.method, params)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ClientError, OSError, ValueError, TypeError, EOFError, RecursionError):
        # Do not dump exceptions/tracebacks containing credentials or HTTP internals.
        print("client_failed; check role, instance, connection, and private token file", file=sys.stderr)
        sys.exit(1)
