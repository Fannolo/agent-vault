#!/usr/bin/env python3
"""Exercise the built CLI and MCP protocol using only isolated synthetic data."""
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import termios
import time
import uuid


class RPC:
    def __init__(self, command):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        self.buffer = b""
        self.sequence = 0

    def notify(self, method):
        self._send({"jsonrpc": "2.0", "method": method})

    def call(self, method, params=None):
        self.sequence += 1
        self._send({"jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params or {}})
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                response = json.loads(line)
                if response.get("id") == self.sequence:
                    if "error" in response:
                        raise AssertionError("Unexpected JSON-RPC error")
                    return response["result"]
                continue
            if not select.select([self.process.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
                break
            data = os.read(self.process.stdout.fileno(), 65536)
            if not data:
                raise AssertionError("MCP process exited before responding")
            self.buffer += data
            if len(self.buffer) > 1_048_576:
                raise AssertionError("Unexpected oversized protocol output")
        raise AssertionError("MCP response timed out")

    def _send(self, message):
        self.process.stdin.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")
        self.process.stdin.flush()

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.process.stdout.close()
        self.process.stderr.close()


def tool_payload(result):
    return json.loads(result["content"][0]["text"])


def enroll_from_tty(command, value):
    master, slave = pty.openpty()

    def controlling_tty():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    process = subprocess.Popen(command + ["enroll", "github"], stdin=slave, stdout=slave,
                               stderr=slave, preexec_fn=controlling_tty)
    os.close(slave)
    output = b""
    sent = False
    deadline = time.monotonic() + 10
    try:
        while time.monotonic() < deadline:
            if not select.select([master], [], [], 0.1)[0]:
                if process.poll() is not None:
                    break
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            output += chunk
            if not sent and b"(hidden): " in output:
                os.write(master, value + b"\n")
                sent = True
        process.wait(timeout=2)
        assert sent and value not in output, "Private TTY input was not hidden"
        return process.returncode, output
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keychain-demo", action="store_true")
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    binary = args.binary or root / ".build/debug/agent-vault"
    if not binary.is_file():
        raise SystemExit("Build first with swift build")
    namespace = "io.agent-vault.smoke." + str(uuid.uuid4())
    with tempfile.TemporaryDirectory(prefix="agent-vault-smoke-") as temporary:
        command = [str(binary), "--state-dir", temporary, "--keychain-namespace", namespace]

        def admin(*arguments):
            result = subprocess.run(command + list(arguments), capture_output=True, check=True, timeout=15)
            return json.loads(result.stdout)

        rpc = None
        try:
            if args.keychain_demo:
                fixture = admin("demo")
            else:
                fixture = admin("client")
                fixture["accountId"] = str(uuid.uuid4())
            rpc = RPC(command + ["mcp", "--client-id", fixture["clientId"], "--development"])
            initialized = rpc.call("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                                   "clientInfo": {"name": "synthetic-smoke-client", "version": "1"}})
            assert initialized["serverInfo"]["name"] == "agent-vault"
            rpc.notify("notifications/initialized")
            tools = rpc.call("tools/list")["tools"]
            assert {tool["name"] for tool in tools} == {"accounts_list", "action_run"}
            listed = tool_payload(rpc.call("tools/call", {"name": "accounts_list", "arguments": {}}))
            assert len(listed["accounts"]) == (1 if args.keychain_demo else 0)
            result = rpc.call("tools/call", {"name": "action_run", "arguments": {
                "accountId": fixture["accountId"], "action": "demo.status"}})
            if args.keychain_demo:
                assert tool_payload(result) == {"status": "ready"}
                admin("revoke-grant", "--grant-id", fixture["grantId"])
                result = rpc.call("tools/call", {"name": "action_run", "arguments": {
                    "accountId": fixture["accountId"], "action": "demo.status"}})
            assert result["isError"] is True
            assert result["content"][0]["text"] == "access_denied"
            for name, arguments in [
                ("get_password", {}),
                ("accounts_list", {"clientId": str(uuid.uuid4())}),
                ("action_run", {"accountId": fixture["accountId"], "action": "demo.status",
                                "url": "https://elsewhere.invalid", "password": "SYNTHETIC-leak-check"}),
            ]:
                response = rpc.call("tools/call", {"name": name, "arguments": arguments})
                assert response["isError"] is True
                assert response["content"][0]["text"] == "invalid_input"
                assert "SYNTHETIC-leak-check" not in json.dumps(response)
            # Invalid limits must not silently become a default grant.
            result = subprocess.run(command + ["grant", "--client-id", fixture["clientId"],
                                                "--account-id", fixture["accountId"], "--seconds", "bad"],
                                    capture_output=True, timeout=10)
            assert result.returncode != 0
            # Noninteractive credential entry is refused without echoing stdin.
            result = subprocess.run(command + ["enroll", "github"], input=b"SYNTHETIC-stdin-token\n",
                                    capture_output=True, timeout=10)
            assert result.returncode != 0
            assert b"SYNTHETIC-stdin-token" not in result.stdout + result.stderr
            assert "SYNTHETIC-leak-check" not in Path(temporary, "state.json").read_text()
            # Separate CLI processes must serialize their metadata updates.
            peers = [subprocess.Popen(command + ["client"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                     for _ in range(12)]
            for peer in peers:
                peer.communicate(timeout=10)
                assert peer.returncode == 0
            assert len(json.loads(Path(temporary, "state.json").read_text())["clients"]) == 13
            if args.keychain_demo:
                token = b"SYNTHETIC-long-token-" + b"a" * 160
                code, output = enroll_from_tty(command, token)
                assert code == 0
                account = json.loads(output[output.index(b"{"):])
                assert account["service"] == "github"
                code, output = enroll_from_tty(command, b"SYNTHETIC-too-long-" + b"a" * 500)
                assert code != 0 and b"invalid_input" in output
            print("PASS: MCP lifecycle, narrow tools, authorization, strict inputs and private-entry checks"
                  + (", native Keychain, revocation and hidden TTY overflow checks" if args.keychain_demo else ""))
        finally:
            if rpc:
                rpc.close()
            if args.keychain_demo:
                # Unique synthetic namespace only. Never target normal user entries.
                # At most two entries are created. Also cover interrupted enrollment.
                for _ in range(3):
                    deleted = subprocess.run(["security", "delete-generic-password", "-s", namespace],
                                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                    if deleted.returncode != 0:
                        break


if __name__ == "__main__":
    main()
