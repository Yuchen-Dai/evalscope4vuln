"""Offline import: extract report data from a Turing sessions export JSON.

Replays an already-finished Turing vuln-hunt run without re-submitting a scan:
the export is the response body of ``GET /api/projects/{pid}/jobs/{jid}/sessions``.
findings / detections / validations live inside ``blackboard_submit_artifact``
tool calls; a submission actually landed in Turing's blackboard only when its
``output.artifact_id`` is non-empty (MCP validation failures return an error
string, or a dict with an empty artifact_id — both were rejected and must NOT
count towards the evaluation).
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, NamedTuple

_REJECT_SAMPLE_CAP = 5

# UUID-shaped job_id/project_id inside tool payloads (knowledge records echo both;
# values appear as JSON "k": "v" or python-repr 'k': 'v')
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_ID_PATTERNS = {
    "job_id": re.compile(rf"['\"]job_id['\"]\s*[:=]\s*['\"]({_UUID})['\"]"),
    "project_id": re.compile(rf"['\"]project_id['\"]\s*[:=]\s*['\"]({_UUID})['\"]"),
}


class OfflineReport(NamedTuple):
    """Extraction result: findings (report-data compatible dicts) + import stats."""

    findings: list[dict]
    stats: dict[str, Any]


def _output_dict(part: dict) -> dict:
    """Tool output -> dict. Strings are attempted as JSON; unparseable means rejected."""
    out = part.get("output")
    if isinstance(out, str):
        try:
            out = json.loads(out)
        except (ValueError, TypeError):
            return {}
    return out if isinstance(out, dict) else {}


def _data_dict(inp: dict) -> dict | None:
    """Tool input ``data`` -> dict. JSON-string form is defensive-only (it gets rejected)."""
    d = inp.get("data")
    if isinstance(d, str):
        try:
            d = json.loads(d)
        except (ValueError, TypeError):
            return None
    return d if isinstance(d, dict) else None


def _norm_line(v: Any) -> int | None:
    """Normalize a line number to int; unparseable -> None.

    Session exports carry raw model output, where lines like ``"167, 212"``
    (a range) appear; take the first parsable number. None keeps the location
    file-only (Loc.line is optional; line_match treats it as no line info).
    """
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        for tok in v.replace(";", ",").split(","):
            tok = tok.strip()
            if tok.lstrip("-").isdigit():
                try:
                    return int(tok)
                except ValueError:
                    continue
    return None


def _normalize_finding(d: dict) -> dict:
    """Coerce line fields of source/sink/call_chain to int (see _norm_line)."""
    for key in ("source", "sink"):
        obj = d.get(key)
        if isinstance(obj, dict) and "line" in obj:
            obj = dict(obj)
            obj["line"] = _norm_line(obj["line"])
            d[key] = obj
    cc = d.get("call_chain")
    if isinstance(cc, list):
        d["call_chain"] = [{
            **step, "line": _norm_line(step.get("line"))
        } if isinstance(step, dict) else step for step in cc]
    return d


def _extract_context_ids(sessions: list) -> tuple[str, str]:
    """Best-effort (project_id, job_id) of the exported run, aligned with the
    online pipeline which records both into prediction metadata.

    Session objects themselves carry no ids; they surface inside tool payloads
    (e.g. knowledge records echo ``{'job_id': ..., 'project_id': ...}``).
    Majority vote keeps a stray mention from winning.
    """
    from collections import Counter
    votes = {key: Counter() for key in _ID_PATTERNS}
    for s in sessions:
        for p in (s.get("session") or {}).get("parts") or []:
            if not isinstance(p, dict) or p.get("type") != "tool":
                continue
            for field in ("input", "output"):
                v = p.get(field)
                if not v:
                    continue
                text = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
                for key, rx in _ID_PATTERNS.items():
                    votes[key].update(rx.findall(text))
    pid = votes["project_id"].most_common(1)[0][0] if votes["project_id"] else ""
    jid = votes["job_id"].most_common(1)[0][0] if votes["job_id"] else ""
    return pid, jid


def extract_report_from_sessions(data: dict) -> OfflineReport:
    """Extract effective findings from a Turing sessions export body.

    Only submissions whose output carries a non-empty ``artifact_id`` count
    (i.e. what Turing actually stored, mirroring report-data). Validation
    artifacts are merged back into their finding as ``validation_result``.
    """
    sessions = data.get("sessions") if isinstance(data, dict) else None
    if not isinstance(sessions, list):
        raise ValueError(
            "invalid sessions export: missing 'sessions' list "
            "(expected the body of GET /api/projects/{pid}/jobs/{jid}/sessions)"
        )

    findings: list[dict] = []
    validation_result: dict[str, str] = {}  # finding artifact_id -> validation_result
    seen: set[str] = set()
    st: dict[str, Any] = {
        "sessions": len(sessions),
        "detections": 0,
        "detections_rejected": 0,
        "findings": 0,
        "findings_rejected": 0,
        "validations": 0,
        "validations_rejected": 0,
        "duplicates": 0,
        "model_ids": set(),
        "reject_samples": [],
    }

    for s in sessions:
        if not isinstance(s, dict):
            continue
        info = ((s.get("session") or {}).get("info") or {})
        if info.get("modelID"):
            st["model_ids"].add(info["modelID"])
        for p in (s.get("session") or {}).get("parts") or []:
            if not isinstance(p, dict) or p.get("type") != "tool":
                continue
            if "submit" not in str(p.get("tool") or ""):
                continue
            inp = p.get("input") or {}
            if not isinstance(inp, dict):
                continue
            artifact_type = inp.get("artifact_type")
            out = _output_dict(p)
            ok = bool(out.get("artifact_id"))
            if artifact_type == "finding":
                d = _data_dict(inp)
                if not ok or d is None:
                    st["findings_rejected"] += 1
                    if len(st["reject_samples"]) < _REJECT_SAMPLE_CAP:
                        raw = p.get("output")
                        st["reject_samples"].append(f"[finding] {str(raw)[:120]}")
                    continue
                fid = out["artifact_id"]
                if fid in seen:
                    st["duplicates"] += 1
                    continue
                seen.add(fid)
                f = _normalize_finding(dict(d))
                f["id"] = fid
                f.setdefault("display_id", out.get("display_id") or "")
                f.setdefault("task_id", inp.get("task_id") or s.get("task_id") or "")
                findings.append(f)
                st["findings"] += 1
            elif artifact_type == "detection":
                st["detections" if ok else "detections_rejected"] += 1
            elif artifact_type == "validation":
                if not ok:
                    st["validations_rejected"] += 1
                    continue
                st["validations"] += 1
                vd = _data_dict(inp) or {}
                if vd.get("finding_id") and vd.get("validation_result"):
                    validation_result[vd["finding_id"]] = vd["validation_result"]

    for f in findings:
        if f["id"] in validation_result:
            f["validation_result"] = validation_result[f["id"]]

    st["model_ids"] = sorted(st["model_ids"])
    st["project_id"], st["job_id"] = _extract_context_ids(sessions)
    return OfflineReport(findings, st)


def load_sessions_report(path: str) -> OfflineReport:
    """Read a sessions export file and extract the report from it.

    Raises FileNotFoundError when missing; ValueError on bad JSON or non-sessions shape.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"sessions_file not found: {path}")
    with open(path, encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as e:
            raise ValueError(f"sessions_file is not valid JSON: {path} ({e})") from e
    return extract_report_from_sessions(data)
