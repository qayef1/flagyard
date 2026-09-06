#!/usr/bin/env python3
"""Solve one FlagYard event challenge locally with Codex CLI."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests


API_BASE = "https://api.flagyard.com/api"
SSO_URL = "https://sso.tuwaiq.edu.sa/auth/realms/main/protocol/openid-connect/token"
URL_RE = re.compile(
    r"^/events/(?P<event>[0-9a-fA-F-]+)/challenges/(?P<challenge>[A-Za-z0-9_-]+)/?$"
)
FLAG_RE = re.compile(r"BHFlagY\{[^{}\r\n]{1,242}\}")
SENSITIVE_KEYS = {
    "clientsecret",
    "correctflag",
    "password",
    "secret",
    "token",
    "visualizationtokenkey",
    "visualizationtokenvalue",
}


class SolverError(RuntimeError):
    """User-facing workflow failure."""


def _load_config() -> dict[str, str]:
    path = Path.home() / ".binarypilot" / "cli-config.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raw = {}
    stored = raw.get("env", {}) if isinstance(raw, dict) else {}
    if not isinstance(stored, dict):
        stored = {}
    keys = (
        "FLAGYARD_USERNAME",
        "FLAGYARD_PASSWORD",
        "FLAGYARD_ACCESS_TOKEN",
        "FLAGYARD_API_BASE",
    )
    return {key: str(os.environ.get(key) or stored.get(key) or "") for key in keys}


def _parse_url(value: str) -> tuple[str, str]:
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.netloc.lower() not in {
        "flagyard.com",
        "www.flagyard.com",
        "ctf.flagyard.com",
    }:
        raise SolverError("Expected an HTTPS FlagYard challenge URL")
    match = URL_RE.fullmatch(parsed.path)
    if not match:
        raise SolverError(
            "Expected URL shape: https://flagyard.com/events/<event_id>/challenges/<challenge_id>"
        )
    return match.group("event"), match.group("challenge")


class Flagyard:
    def __init__(self, config: dict[str, str]) -> None:
        self.base = (config.get("FLAGYARD_API_BASE") or API_BASE).rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {"Accept": "application/json", "User-Agent": "binarypilot/1.0"}
        )
        token = config.get("FLAGYARD_ACCESS_TOKEN")
        if not token:
            username = config.get("FLAGYARD_USERNAME")
            password = config.get("FLAGYARD_PASSWORD")
            if not username or not password:
                raise SolverError(
                    "FlagYard credentials missing; configure ~/.binarypilot/cli-config.json"
                )
            response = self.session.post(
                SSO_URL,
                data={
                    "grant_type": "password",
                    "client_id": "flagyard",
                    "username": username,
                    "password": password,
                },
                timeout=30,
            )
            if response.status_code != 200:
                raise SolverError(
                    f"FlagYard login failed (HTTP {response.status_code})"
                )
            token = response.json().get("access_token")
        if not token:
            raise SolverError("FlagYard returned no access token")
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def request(self, method: str, path: str, *, payload: Any = None) -> Any:
        response = self.session.request(
            method,
            f"{self.base}{path}",
            json=payload,
            timeout=60,
        )
        try:
            data = response.json()
        except ValueError:
            data = None
        if response.status_code >= 400:
            message = ""
            if isinstance(data, dict):
                message = str(data.get("message") or data.get("error") or "")
            raise SolverError(
                f"FlagYard API {method} {path} failed (HTTP {response.status_code})"
                + (f": {message[:200]}" if message else "")
            )
        return data


def _data(response: Any) -> Any:
    return response.get("data") if isinstance(response, dict) else None


def _safe_name(value: str, fallback: str) -> str:
    name = Path(value or fallback).name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name or fallback


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[redacted]" if key.lower() in SENSITIVE_KEYS else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _download_files(
    api: Flagyard, base: str, details: dict[str, Any], dest: Path
) -> list[Path]:
    if not details.get("hasChallengeFiles") and not details.get("files"):
        return []
    response = api.request("GET", f"{base}/challenge-files")
    signed = ((_data(response) or {}).get("files")) or []
    metadata = details.get("files") or []
    downloaded: list[Path] = []
    for index, item in enumerate(signed):
        url = item.get("url") if isinstance(item, dict) else None
        if not url:
            continue
        meta = metadata[index] if index < len(metadata) else {}
        requested = item.get("fileName") or item.get("name") or meta.get("fileName")
        filename = _safe_name(str(requested or ""), f"attachment_{index}")
        target = dest / filename
        # Signed URLs authenticate themselves. Do not forward the FlagYard bearer
        # header to the separate file-storage host.
        with requests.get(url, stream=True, timeout=180) as response:
            response.raise_for_status()
            with target.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        handle.write(chunk)
        downloaded.append(target)
        print(f"[+] Downloaded {target.name} ({target.stat().st_size} bytes)")
    return downloaded


def _instance_address(details: dict[str, Any]) -> str | None:
    instance = details.get("currentRunningInstanceForUser") or {}
    return instance.get("instanceAddress") if isinstance(instance, dict) else None


def _start_instance(
    api: Flagyard, base: str, details: dict[str, Any]
) -> tuple[str | None, bool]:
    address = _instance_address(details)
    if address:
        print(f"[+] Reusing running instance: {address}")
        return str(address), False
    if details.get("internalPort") is None:
        print("[i] Offline challenge: no instance required")
        return None, False
    api.request("POST", f"{base}/instance", payload={})
    print("[+] Instance start requested; waiting for address")
    deadline = time.time() + 90
    while time.time() < deadline:
        refreshed = _data(api.request("GET", base)) or {}
        address = _instance_address(refreshed)
        if address:
            print(f"[+] Instance ready: {address}")
            return str(address), True
        time.sleep(3)
    try:
        api.request("DELETE", f"{base}/instance")
    except SolverError:
        pass
    raise SolverError("Instance did not become ready within 90 seconds")


def _write_schema(path: Path) -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "status": {"type": "string", "enum": ["solved", "unsolved"]},
            "flag": {"type": ["string", "null"]},
            "summary": {"type": "string"},
            "writeup_path": {"type": ["string", "null"]},
        },
        "required": ["status", "flag", "summary", "writeup_path"],
    }
    path.write_text(json.dumps(schema, indent=2), encoding="utf-8")


def _build_prompt(
    challenge_url: str,
    details: dict[str, Any],
    files: list[Path],
    address: str | None,
    instruction: str,
) -> str:
    category = details.get("category") or {}
    if isinstance(category, dict):
        category = category.get("name") or category.get("nameEn")
    description = str(details.get("description") or "")
    file_lines = "\n".join(f"- {path.name}" for path in files) or "- none"
    target = address or "offline/local files only"
    return f"""Solve this authorized FlagYard CTF challenge completely on this host.

Challenge URL: {challenge_url}
Name: {details.get("name")}
Category: {category}
Description:
{description}

Local attachments in the current directory:
{file_lines}

Challenge instance: {target}

Operator instruction:
{instruction}

Rules:
- Work only on the provided attachment files and challenge instance. Do not attack FlagYard itself, its API, leaderboard, or other players.
- Solve the challenge completely using a focused, practical approach. Inspect any attachments before choosing an approach, and do not overengineer the solution.
- Do not brute-force unless it is the last reasonable option after analytical approaches have been exhausted.
- Search the internet for relevant exploits, CVEs, documentation, research, and technical articles whenever they may help.
- Download or install any tools, libraries, exploits, or reference material needed to solve the challenge.
- Use any available MCP server or tool when it can help with analysis or exploitation.
- Keep solver scripts and a reproducible writeup in this directory.
- Continue until you recover an exact BHFlagY{{...}} value or exhaust sound approaches.
- Return the required JSON object. Set status=solved only with an exact recovered flag and set writeup_path to the generated markdown file.
"""


def _run_codex(
    run_dir: Path,
    prompt: str,
    *,
    model: str,
    effort: str,
) -> dict[str, Any]:
    schema = run_dir / "result-schema.json"
    result_file = run_dir / "result.json"
    _write_schema(schema)
    command = [
        "codex",
        "exec",
        "--model",
        model,
        "-c",
        f'model_reasoning_effort="{effort}"',
        "--approve-for-me",
        "--skip-git-repo-check",
        "--cd",
        str(run_dir),
        "--output-schema",
        str(schema),
        "--output-last-message",
        str(result_file),
        "-",
    ]
    print(f"[+] Starting Codex on host ({model}, effort={effort})")
    completed = subprocess.run(command, input=prompt, text=True, check=False)
    if completed.returncode != 0:
        raise SolverError(f"Codex exited with status {completed.returncode}")
    try:
        result = json.loads(result_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SolverError("Codex did not produce valid structured output") from exc
    return result


def _run_codex_interactive(
    run_dir: Path,
    prompt: str,
    *,
    model: str,
    effort: str,
) -> dict[str, Any]:
    prompt_file = run_dir / "challenge-prompt.md"
    flag_file = run_dir / "recovered-flag.txt"
    result_file = run_dir / "result.json"
    prompt_file.write_text(prompt, encoding="utf-8")
    flag_file.unlink(missing_ok=True)
    interactive_prompt = (
        prompt
        + "\nInteractive session instructions:\n"
        + "- Collaborate with the operator in this TUI while solving.\n"
        + f"- As soon as the exact flag is recovered, write only that flag to {flag_file.name}.\n"
        + "- Do not submit the flag yourself; the wrapper handles submission after this session exits.\n"
    )
    command = [
        "codex",
        "--model",
        model,
        "-c",
        f'model_reasoning_effort="{effort}"',
        "--dangerously-bypass-approvals-and-sandbox",
        "--search",
        "--cd",
        str(run_dir),
        interactive_prompt,
    ]
    print(f"[+] Opening Codex TUI on host ({model}, effort={effort})")
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        raise SolverError(f"Codex TUI exited with status {completed.returncode}")

    flag = ""
    try:
        candidate = flag_file.read_text(encoding="utf-8").strip()
        if FLAG_RE.fullmatch(candidate):
            flag = candidate
    except OSError:
        pass
    if not flag and sys.stdin.isatty():
        candidate = input("Flag (leave blank to finish without submitting): ").strip()
        if candidate and FLAG_RE.fullmatch(candidate) is None:
            raise SolverError("Entered value is not a valid BHFlagY{...} flag")
        flag = candidate

    result = {
        "status": "solved" if flag else "unsolved",
        "flag": flag or None,
        "summary": (
            "Flag recovered in interactive Codex session"
            if flag
            else "Interactive Codex session ended without a recorded flag"
        ),
        "writeup_path": None,
    }
    result_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _submit(api: Flagyard, base: str, flag: str) -> Any:
    if FLAG_RE.fullmatch(flag) is None:
        raise SolverError("Codex output did not contain a valid BHFlagY{...} flag")
    response = api.request("POST", f"{base}/flag", payload={"flag": flag})
    if not isinstance(response, dict) or response.get("isSuccess") is False:
        raise SolverError("FlagYard rejected the submitted flag")
    print("[+] Flag accepted by FlagYard")
    return response


def _slug(details: dict[str, Any], challenge_id: str) -> str:
    return _safe_name(str(details.get("name") or ""), challenge_id).lower()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download, start, solve, and submit a FlagYard event challenge using host Codex"
    )
    parser.add_argument("challenge_url")
    parser.add_argument(
        "--instruction",
        default=(
            "Solve this CTF challenge completely. Use a focused, practical approach and do "
            "not overengineer the solution. Do not brute-force unless it is the last reasonable "
            "option. Search the internet for relevant exploits, CVEs, documentation, and "
            "technical articles whenever useful. Download or install anything needed to help "
            "solve the challenge, and use any available MCP server or tool when beneficial."
        ),
    )
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument(
        "--effort", choices=["low", "medium", "high", "xhigh", "max"], default="xhigh"
    )
    parser.add_argument("--run-root", type=Path, default=Path.home() / "flagyard_runs")
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="Download only; do not start or solve",
    )
    parser.add_argument(
        "--no-submit", action="store_true", help="Recover but do not submit the flag"
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Open the Codex TUI after downloading files and starting the instance",
    )
    parser.add_argument("--keep-instance", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started = False
    api: Flagyard | None = None
    base = ""
    try:
        event_id, challenge_id = _parse_url(args.challenge_url)
        api = Flagyard(_load_config())
        base = f"/events/{event_id}/challenges/{challenge_id}"
        details = _data(api.request("GET", base)) or {}
        if not isinstance(details, dict) or not details.get("name"):
            raise SolverError("Challenge metadata is missing")
        run_dir = args.run_root.expanduser().resolve() / _slug(details, challenge_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "challenge.json").write_text(
            json.dumps(_redact(details), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[+] Challenge: {details['name']}")
        print(f"[+] Workspace: {run_dir}")
        files = _download_files(api, base, details, run_dir)
        if args.prepare_only:
            print("[+] Preparation complete")
            return 0
        address, started = _start_instance(api, base, details)
        prompt = _build_prompt(
            args.challenge_url, details, files, address, args.instruction
        )
        if args.interactive:
            result = _run_codex_interactive(
                run_dir, prompt, model=args.model, effort=args.effort
            )
        else:
            result = _run_codex(run_dir, prompt, model=args.model, effort=args.effort)
        flag = str(result.get("flag") or "").strip()
        if result.get("status") != "solved" or not flag:
            print(f"[-] Codex did not recover a flag: {result.get('summary', '')}")
            return 2
        print(f"[+] Recovered flag: {flag}")
        if not args.no_submit:
            _submit(api, base, flag)
        else:
            print("[i] Submission skipped (--no-submit)")
        print(f"[+] Result: {run_dir / 'result.json'}")
        return 0
    except (SolverError, requests.RequestException) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if api is not None and base and started and not args.keep_instance:
            try:
                api.request("DELETE", f"{base}/instance")
                print("[+] Instance stopped")
            except Exception as exc:  # cleanup must not hide the primary result
                print(f"warning: could not stop instance: {exc}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
