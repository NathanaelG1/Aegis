#!/usr/bin/env python3
"""Trusted local verifier for the fake-secret HTTP/MCP workflow.

This harness knows owner credentials to drive both roles. Its separate MCP agent
process receives only an agent token file. It does not attest OS/Sprite isolation.
Only scanned, non-sensitive artifacts are exported. Never point it at real secrets.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import select
import signal
import subprocess
import sys
import tempfile
import time

from sprite_client import Client, ClientError


class EvidenceFailure(Exception):
    pass


def verify(binary, output_dir=None):
    checks = []
    transcript = []
    owner_responses = []
    server_logs = []
    child_outputs = []
    root = Path(__file__).resolve().parent.parent
    client_script = root / "scripts/sprite_client.py"
    binary = Path(binary).resolve()
    server = None
    agent = None
    log_handle = None
    clean_env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}

    def check(name, condition):
        if not condition:
            raise EvidenceFailure(name)
        checks.append(name)

    with tempfile.TemporaryDirectory(prefix="aegis-sprite-evidence-") as temporary:
        workspace = Path(temporary).resolve()
        state = workspace / "owner-state"
        agent_home = workspace / "agent-client"
        agent_home.mkdir(mode=0o700)

        def run(*arguments):
            result = subprocess.run([str(binary), *arguments], capture_output=True, timeout=10, env=clean_env)
            child_outputs.extend([result.stdout, result.stderr])
            return result

        def stop_server():
            nonlocal server, log_handle
            if server is not None:
                server.send_signal(signal.SIGINT)
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
                server = None
            if log_handle is not None:
                log_handle.close()
                log_handle = None

        def start_server():
            nonlocal server, log_handle
            log_path = workspace / f"service-{len(server_logs)}.log"
            server_logs.append(log_path)
            log_handle = log_path.open("wb")
            server = subprocess.Popen(
                [str(binary), "sprite-demo-serve", "--state-dir", str(state), "--listen", "127.0.0.1:0"],
                stdout=log_handle, stderr=log_handle, env=clean_env,
            )
            for _ in range(100):
                if server.poll() is not None:
                    raise EvidenceFailure("server_start")
                for line in log_path.read_text().splitlines():
                    if line.startswith("sprite_demo_ready "):
                        return "http://" + line.split()[1]
                time.sleep(0.05)
            raise EvidenceFailure("server_ready_deadline")

        def raw(url, name, token, path, body=None, extra_headers=(), method="POST"):
            port = int(url.rsplit(":", 1)[1])
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            payload = body if isinstance(body, bytes) else json.dumps(body or {}).encode()
            try:
                connection.putrequest(method, path)
                if token is not None:
                    connection.putheader("Authorization", "Bearer " + token)
                connection.putheader("Content-Type", "application/json")
                connection.putheader("Content-Length", str(len(payload)))
                for key, value in extra_headers:
                    connection.putheader(key, value)
                connection.endheaders(payload)
                response = connection.getresponse()
                data = response.read(131073)
                check(name + "_bounded", len(data) <= 131072)
                check(name + "_no_store", response.getheader("Cache-Control") == "no-store")
                transcript.append({"case": name, "status": response.status, "body": data.decode()})
                return response.status, json.loads(data)
            finally:
                connection.close()

        def agent_call(client, method, params=None):
            result = client.call(method, params)
            transcript.append({"case": method, "body": result})
            return result

        def owner_call(client, method, params=None):
            result = client.call(method, params)
            owner_responses.append(result)
            return result

        def approve(owner, identifier):
            review = owner_call(owner, "inspect", {"prepared_request_id": identifier})
            check("owner_resolved_exact_plan", review["result"]["plan"]["parameters"] == {
                "repository_id": 4242, "issue_number": 7})
            receipt = review["result"]["review_id"]
            approval = owner_call(owner, "approve", {"review_id": receipt})
            check("owner_approved_review", approval["result"]["state"] == "approved")
            replay = owner_call(owner, "approve", {"review_id": receipt})
            check("review_receipt_single_use", replay["error"] == "approval_required")

        try:
            check("initialize", run("sprite-demo-init", "--state-dir", str(state)).returncode == 0)
            check("initialize_refuses_overwrite", run("sprite-demo-init", "--state-dir", str(state)).returncode != 0)
            owner_key = (state / "owner.key").read_text().strip()
            agent_key = (state / "agent.key").read_text().strip()
            fake_key = (state / "fake-secret.key").read_text().strip()
            check("independent_credentials", owner_key != agent_key and fake_key not in (owner_key, agent_key))
            check("fresh_fake_fixture", fake_key.startswith("AEGIS_FAKE_ONLY_") and len(fake_key) == 80)
            agent_token_file = agent_home / "agent.key"
            agent_token_file.write_text(agent_key + "\n")
            agent_token_file.chmod(0o600)
            check("refuse_nonloopback", run("sprite-demo-serve", "--state-dir", str(state), "--listen", "0.0.0.0:8080").returncode != 0)
            (state / "owner.key").chmod(0o644)
            check("refuse_world_readable_key", run("sprite-demo-serve", "--state-dir", str(state), "--listen", "127.0.0.1:0").returncode != 0)
            (state / "owner.key").chmod(0o600)
            (state / "owner.key").write_text(agent_key + "\n")
            check("refuse_equal_role_keys", run("sprite-demo-serve", "--state-dir", str(state), "--listen", "127.0.0.1:0").returncode != 0)
            (state / "owner.key").write_text(owner_key + "\n")
            (state / "fake-secret.key").write_text("REAL_SECRET_NOT_SUPPORTED\n")
            check("refuse_nonfixture_key", run("sprite-demo-serve", "--state-dir", str(state), "--listen", "127.0.0.1:0").returncode != 0)
            (state / "fake-secret.key").write_text(fake_key + "\n")

            url = start_server()
            agent_http = Client(url, agent_token_file, "agent")
            instance = agent_http.session()["instance_id"]
            agent_http.instance = instance
            owner = Client(url, state / "owner.key", "owner", instance)
            transcript.append({"case": "session", "body": agent_http.session()})
            owner_body = {"instance_id": instance, "action": {"method": "evidence"}}
            for name, token, path in [
                ("missing_auth", None, "/v1/session"),
                ("wrong_auth", "0" * 64, "/v1/agent"),
                ("agent_cannot_owner", agent_key, "/v1/owner"),
                ("owner_cannot_agent", owner_key, "/v1/agent"),
            ]:
                status, _ = raw(url, name, token, path, owner_body)
                check(name, status == 401)
            status, _ = raw(url, "duplicate_auth", agent_key, "/v1/agent", {},
                            [("Authorization", "Bearer " + owner_key)])
            check("duplicate_auth_rejected", status == 401)
            status, _ = raw(url, "origin", agent_key, "/v1/agent", {}, [("Origin", "https://example.invalid")])
            check("browser_origin_rejected", status == 400)
            status, _ = raw(url, "query_auth", agent_key, "/v1/agent?token=placeholder", {})
            check("query_rejected", status == 400)
            status, _ = raw(url, "oversize", agent_key, "/v1/agent", b"x" * 16385)
            check("oversize_rejected", status == 400)
            for path in ("/get_secret", "/secrets", "/files", "/debug", "/env", "/metrics"):
                status, _ = raw(url, "no_export_route", agent_key, path)
                check("no_export_route", status == 404)
            for method in ("get_secret", "approve", "export", "exec", "read_file"):
                body = {"instance_id": instance, "request": {"version": 1, "action": {"method": method}}}
                status, _ = raw(url, "forbidden_agent_method", agent_key, "/v1/agent", body)
                check("forbidden_agent_method", status == 400)
            body = {"instance_id": instance, "request": {"version": 1, "action": {"method": "discover_operations"}},
                    "owner": True, "approved": True}
            status, _ = raw(url, "owner_impersonation_fields", agent_key, "/v1/agent", body)
            check("owner_impersonation_fields_rejected", status == 400)
            injection = {"instance_id": instance, "request": {"version": 1, "action": {
                "method": "prepare_operation", "params": {"request_id": "injection", "profile_id": "issue-status",
                "parameters": {"repository_id": 4242, "issue_number": 7, "url": "https://example.invalid",
                               "secret_ref": "owner.key"}}}}}
            status, _ = raw(url, "destination_injection", agent_key, "/v1/agent", injection)
            check("destination_injection_rejected", status == 400)
            duplicate = ('{"instance_id":"' + instance + '","instance_id":"other",'
                         '"request":{"version":1,"action":{"method":"discover_operations"}}}').encode()
            status, _ = raw(url, "duplicate_json", agent_key, "/v1/agent", duplicate)
            check("duplicate_json_rejected", status == 400)
            body = {"instance_id": "stale", "request": {"version": 1, "action": {"method": "discover_operations"}}}
            status, _ = raw(url, "stale_instance", agent_key, "/v1/agent", body)
            check("stale_instance_rejected", status == 409)
            try:
                Client("http://example.invalid", agent_token_file, "agent")
            except ClientError:
                check("client_requires_tls_for_remote", True)
            else:
                check("client_requires_tls_for_remote", False)

            # A separate agent process has only the agent credential path and sanitized env.
            agent = subprocess.Popen(
                [sys.executable, str(client_script), "--url", url, "--token-file", str(agent_token_file),
                 "--role", "agent", "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=clean_env, cwd=agent_home,
            )

            def rpc(identifier, method, params):
                request = {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}
                agent.stdin.write(json.dumps(request).encode() + b"\n")
                agent.stdin.flush()
                if not select.select([agent.stdout], [], [], 8)[0]:
                    raise EvidenceFailure("mcp_response_deadline")
                line = agent.stdout.readline(16385)
                transcript.append({"case": "mcp", "request": request, "response": line.decode()})
                return json.loads(line)

            init = rpc(1, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                        "clientInfo": {"name": "evidence-agent", "version": "1"}})
            check("separate_agent_mcp_initialized", "result" in init)
            catalog = rpc(2, "tools/list", {})
            check("agent_tools_only", {tool["name"] for tool in catalog["result"]["tools"]} == {
                "discover_operations", "prepare_operation", "request_approval", "invoke_approved", "get_run_status", "cancel"})

            def tool(identifier, method, arguments):
                response = rpc(identifier, "tools/call", {"name": method, "arguments": arguments})
                return json.loads(response["result"]["content"][0]["text"])

            prepared = tool(3, "prepare_operation", {"request_id": "evidence-main", "profile_id": "issue-status",
                           "parameters": {"repository_id": 4242, "issue_number": 7}})
            identifier = prepared["result"]["prepared_request_id"]
            handle = {"prepared_request_id": identifier}
            check("invoke_before_approval_blocked", tool(4, "invoke_approved", handle)["error"] == "approval_required")
            check("agent_requests_approval_only", tool(5, "request_approval", handle)["result"]["state"] == "awaiting_approval")
            check("owner_pending", owner_call(owner, "pending")["result"][0]["prepared_request_id"] == identifier)
            check("approve_requires_review", owner_call(owner, "approve", {"review_id": "unknown"})["error"] == "approval_required")
            approve(owner, identifier)
            succeeded = tool(6, "invoke_approved", handle)
            check("approved_fake_secret_operation_succeeds", succeeded["result"]["result"] == {
                "repository_id": 4242, "issue_number": 7, "state": "open"})
            with ThreadPoolExecutor(max_workers=4) as executor:
                retries = list(executor.map(lambda _: agent_http.call("invoke_approved", handle), range(4)))
            transcript.extend({"case": "concurrent_retry", "body": item} for item in retries)
            check("concurrent_retry_same_result", all(item == succeeded for item in retries))
            evidence = owner_call(owner, "evidence")["result"]
            check("provider_key_used_once", evidence["provider_authenticated_calls"] == 1 and evidence["remaining_uses"] == 19)
            check("agent_cannot_call_approval_tool", "error" in rpc(7, "tools/call", {"name": "approve", "arguments": handle}))
            denied = agent_call(agent_http, "prepare_operation", {"request_id": "wrong-resource", "profile_id": "issue-status",
                                "parameters": {"repository_id": 9999, "issue_number": 7}})
            check("resource_scope_enforced", denied["error"] == "scope_denied")
            conflict = agent_call(agent_http, "prepare_operation", {"request_id": "evidence-main", "profile_id": "issue-status",
                                 "parameters": {"repository_id": 4242, "issue_number": 8}})
            check("idempotency_conflict", conflict["error"] == "request_id_conflict")

            cancel_request = agent_call(agent_http, "prepare_operation", {"request_id": "cancel", "profile_id": "issue-status",
                                       "parameters": {"repository_id": 4242, "issue_number": 7}})
            cancel_handle = {"prepared_request_id": cancel_request["result"]["prepared_request_id"]}
            agent_call(agent_http, "request_approval", cancel_handle)
            review = owner_call(owner, "inspect", cancel_handle)["result"]
            owner_call(owner, "cancel", cancel_handle)
            check("canceled_request_cannot_approve", owner_call(owner, "approve", {"review_id": review["review_id"]})["error"] == "request_canceled")
            canceled = agent_call(agent_http, "invoke_approved", cancel_handle)
            check("canceled_request_cannot_invoke", canceled["result"]["state"] == "canceled"
                  and canceled["result"]["error"] == "request_canceled")
            pending_restart = agent_call(agent_http, "prepare_operation", {
                "request_id": "restart-pending", "profile_id": "issue-status",
                "parameters": {"repository_id": 4242, "issue_number": 7}})["result"]
            restart_handle = {"prepared_request_id": pending_restart["prepared_request_id"]}
            agent_call(agent_http, "request_approval", restart_handle)
            restart_review = owner_call(owner, "inspect", restart_handle)["result"]
            altered_approval = {"instance_id": instance, "action": {"method": "approve", "params": {
                "review_id": restart_review["review_id"], "prepared_request_id": identifier}}}
            check("approval_cannot_rebind_handle", raw(url, "approval_rebinding", owner_key,
                  "/v1/owner", altered_approval)[0] == 400)
            owner_call(owner, "revoke")
            check("revocation_blocks_authority", agent_call(agent_http, "prepare_operation", {
                "request_id": "after-revoke", "profile_id": "issue-status",
                "parameters": {"repository_id": 4242, "issue_number": 7}})["error"] == "grant_revoked")

            stop_server()
            url = start_server()
            fresh_agent = Client(url, agent_token_file, "agent")
            fresh_instance = fresh_agent.session()["instance_id"]
            check("restart_changes_instance", fresh_instance != instance)
            old_body = {"instance_id": instance, "request": {"version": 1, "action": {"method": "invoke_approved", "params": handle}}}
            check("old_handle_rejected_after_restart", raw(url, "restart_replay", agent_key, "/v1/agent", old_body)[0] == 409)
            fresh_owner = Client(url, state / "owner.key", "owner", fresh_instance)
            old_receipt = {"instance_id": fresh_instance, "action": {"method": "approve", "params": {"review_id": restart_review["review_id"]}}}
            check("review_not_restored", raw(url, "old_review", owner_key, "/v1/owner", old_receipt)[1]["error"] == "approval_required")
            check("restart_has_no_dispatches", owner_call(fresh_owner, "evidence")["result"]["provider_authenticated_calls"] == 0)
            fresh_agent.instance = fresh_instance
            fresh_request = agent_call(fresh_agent, "prepare_operation", {
                "request_id": "evidence-main", "profile_id": "issue-status",
                "parameters": {"repository_id": 4242, "issue_number": 7}})["result"]
            check("restart_requires_fresh_approval", agent_call(fresh_agent, "invoke_approved", {
                "prepared_request_id": fresh_request["prepared_request_id"]})["error"] == "approval_required")

            # Existing MCP bridge remains pinned to its original instance and fails closed.
            # The new server uses another port here; no automatic discovery/reconnect occurs.
            check("old_mcp_connection_cannot_resume", "error" in rpc(8, "tools/call", {"name": "get_run_status", "arguments": handle}))
            agent.stdin.close()
            agent.wait(timeout=5)
            child_outputs.append(agent.stdout.read())
            child_outputs.append(agent.stderr.read())
            agent = None
            stop_server()
            logs = b"\n".join(path.read_bytes() for path in server_logs)
            captured = (json.dumps(transcript).encode() + json.dumps(owner_responses).encode()
                        + logs + b"\n".join(child_outputs))
            needles = []
            for value in (fake_key, fake_key.removeprefix("AEGIS_FAKE_ONLY_"), owner_key, agent_key):
                needles.extend([value.encode(), value.encode().hex().encode(), base64.b64encode(value.encode())])
            check("no_fixture_or_auth_keys_in_captured_outputs", not any(needle in captured for needle in needles))
            check("service_logs_contain_no_tracebacks", b"Traceback" not in logs and b"panic" not in logs)

            sources = sorted([*root.glob("src/*.rs"), *root.glob("scripts/sprite_*.py"), root / "Cargo.toml", root / "Cargo.lock"])
            report = {
                "schema_version": 1, "passed": True, "generated_at": datetime.now(timezone.utc).isoformat(),
                "platform": platform.platform(), "python": platform.python_version(),
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "source_sha256": {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
                "checks_passed": len(checks), "checks": checks,
                "provider_authenticated_calls_before_restart": evidence["provider_authenticated_calls"],
                "agent_capture_entries": len(transcript),
                "evidence_scope": "fresh fake key; local HTTP and separate stdio MCP agent process; owner verifier drives approvals",
                "limitations": ["No deployed Sprite, TLS gateway, filesystem/process isolation or administrator exclusion attested",
                                "Verifier has both role credentials; agent child is not an OS sandbox",
                                "Captured-output absence is bounded evidence, not proof against every disclosure path",
                                "Fake provider is in-process; no real provider, vault, encryption-at-rest or protected application delivery"],
            }
            if output_dir:
                output = Path(output_dir)
                output.mkdir(mode=0o700, parents=True, exist_ok=False)
                (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
                (output / "agent-transcript.jsonl").write_text("".join(json.dumps(item) + "\n" for item in transcript))
                (output / "service.log").write_bytes(logs)
            return report
        finally:
            if agent is not None:
                agent.kill()
                agent.communicate(timeout=5)
            stop_server()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output-dir")
    args = parser.parse_args()
    try:
        report = verify(args.binary, args.output_dir)
        print(json.dumps({"passed": True, "checks_passed": report["checks_passed"], "output_dir": args.output_dir}))
    except EvidenceFailure as error:
        print(json.dumps({"passed": False, "error": str(error)}))
        return 1
    except Exception:
        # Failed assertions never print request objects, keys, or private subprocess output.
        print(json.dumps({"passed": False, "error": "evidence_verification_failed"}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
