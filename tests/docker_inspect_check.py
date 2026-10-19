#!/usr/bin/env python3
"""Explicit Docker CLI check for the supervisor's real inspect-template framing.

Parent-run command (from the repository root):
    python tests/docker_inspect_check.py --image sha256:<64-lowercase-hex-digest>

This is intentionally not named test_*, so normal test discovery never launches
Docker. The probe container is created but never started and has no network.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
import subprocess
import sys
import uuid


_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from lab import secure_cohort_supervisor as supervisor


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_CID = re.compile(r"[0-9a-f]{64}", re.ASCII)
_TEMPLATE_OUTPUT_LIMIT = 4096
_FULL_JSON_LIMIT = 256 * 1024
_STDERR_LIMIT = 4096
_COMMAND_TIMEOUT_SECONDS = 15


class ProbeError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _run(argv: list[str], *, output_limit: int) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=_COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        raise ProbeError("docker_timeout") from None
    except OSError:
        raise ProbeError("docker_unavailable") from None
    if len(result.stdout) > output_limit or len(result.stderr) > _STDERR_LIMIT:
        raise ProbeError("docker_output_limit")
    return result


def _validate_full_inspect(raw: bytes, *, name: str, owner: str, role: str,
                           image: str, expected_cid: str | None) -> str:
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError):
        raise ProbeError("full_inspect_json") from None
    if type(value) is not dict:
        raise ProbeError("full_inspect_shape")
    cid = value.get("Id")
    config = value.get("Config")
    state = value.get("State")
    if (type(cid) is not str or _CID.fullmatch(cid) is None
            or (expected_cid is not None and cid != expected_cid)
            or value.get("Name") != "/" + name
            or type(config) is not dict or config.get("Image") != image
            or type(config.get("Labels")) is not dict
            or config["Labels"].get(supervisor._OWNER_LABEL) != owner
            or config["Labels"].get(supervisor._ROLE_LABEL) != role
            or type(state) is not dict or state.get("Running") is not False
            or state.get("Status") != "created"):
        raise ProbeError("full_inspect_identity_or_state")
    return cid


def _inspect_full_json(docker: str, target: str, *, name: str, owner: str,
                       role: str, image: str, expected_cid: str | None) -> str:
    result = _run(
        [docker, "inspect", "--type", "container", "--format", "{{json .}}", target],
        output_limit=_FULL_JSON_LIMIT)
    if result.returncode != 0:
        raise ProbeError("full_inspect_failed")
    return _validate_full_inspect(
        result.stdout, name=name, owner=owner, role=role,
        image=image, expected_cid=expected_cid)


def run_check(*, docker: str, image: str) -> tuple[bool, dict]:
    if type(image) is not str or _DIGEST.fullmatch(image) is None:
        raise ProbeError("image_must_be_sha256_digest")
    token = uuid.uuid4().hex
    name = "steamboat-inspect-check-" + token[:20]
    owner = token
    role = "operator"
    cid = None
    failure = None
    template_checked = False
    cleanup_confirmed = False
    creation_attempted = False

    try:
        creation_attempted = True
        created = _run(
            [
                docker, "create", "--pull=never", "--name", name,
                "--label", f"{supervisor._OWNER_LABEL}={owner}",
                "--label", f"{supervisor._ROLE_LABEL}={role}",
                "--network=none", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--cpus=0.1",
                "--memory=64m", "--pids-limit=32", "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=8m", image,
            ],
            output_limit=256)
        if created.returncode != 0:
            raise ProbeError("container_create_failed")
        candidate = created.stdout.decode("ascii", "strict").strip()
        if _CID.fullmatch(candidate) is not None:
            cid = candidate
        else:
            failure = "container_id_invalid"

        if cid is not None:
            inspected = _run(
                [docker, *_inspect_argv(cid)], output_limit=_TEMPLATE_OUTPUT_LIMIT)
            if inspected.returncode != 0:
                raise ProbeError("template_inspect_failed")
            text = inspected.stdout.decode("ascii", "strict").strip()
            supervisor.verify_container_inspect(
                text, cid=cid, name=name, owner_label=owner,
                role=role, image=image)
            template_checked = True
    except ProbeError as error:
        failure = failure or error.code
    except (UnicodeError, supervisor.SupervisorError):
        failure = failure or "template_inspect_invalid"
    finally:
        if creation_attempted:
            try:
                verified_cid = _inspect_full_json(
                    docker, cid or name, name=name, owner=owner, role=role,
                    image=image, expected_cid=cid)
                removed = _run([docker, "rm", verified_cid], output_limit=256)
                if removed.returncode != 0:
                    raise ProbeError("container_remove_failed")
                cleanup_confirmed = True
            except ProbeError as error:
                failure = failure or error.code

    result = {
        "check": "docker_inspect_template",
        "ok": failure is None and template_checked and cleanup_confirmed,
        "template_checked": template_checked,
        "cleanup_confirmed": cleanup_confirmed,
        "failure_type": failure,
    }
    return result["ok"], result


def _inspect_argv(cid: str) -> list[str]:
    # Reuse the exact argv so this exercises the production seven-field template.
    return supervisor._container_inspect_argv(cid)[1:]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True,
                        help="already-present immutable sha256:<64 lowercase hex> image ID")
    parser.add_argument("--docker", default="docker",
                        help="Docker CLI executable (default: docker)")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ok, result = run_check(docker=args.docker, image=args.image)
    except ProbeError as error:
        print(json.dumps({
            "check": "docker_inspect_template", "ok": False,
            "template_checked": False, "cleanup_confirmed": False,
            "failure_type": error.code,
        }, sort_keys=True, separators=(",", ":")))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
