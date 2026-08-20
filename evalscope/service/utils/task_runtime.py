"""Task runtime bookkeeping for reconciliation of async eval tasks.

Each async invoke writes ``<work_dir>/task_runtime.json`` recording the child
process pid plus its kernel start-ticks (field 22 of ``/proc/<pid>/stat``).
The start-ticks guard against pid reuse: if the recorded pid now belongs to a
different process, the original child is gone.

This module also provides :func:`patch_progress` so the *parent* service can
write a terminal status into ``progress.json`` when the child died without
being able to write one itself (OOM, SIGKILL, service restart, user stop).

All helpers are pure filesystem functions on purpose — no Flask / app state —
so they are trivially unit-testable.
"""

import json
import os

RUNTIME_FILE = 'task_runtime.json'
PROGRESS_FILE = 'progress.json'


def write_runtime(work_dir: str, pid: int, start_ticks: int = None) -> None:
    """Atomically persist the child-process identity for *work_dir*."""
    os.makedirs(work_dir, exist_ok=True)
    state = {'pid': pid, 'start_ticks': start_ticks}
    tmp = os.path.join(work_dir, RUNTIME_FILE + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    os.replace(tmp, os.path.join(work_dir, RUNTIME_FILE))


def read_runtime(work_dir: str) -> dict:
    """Return the recorded runtime info, or None when absent/corrupt."""
    path = os.path.join(work_dir, RUNTIME_FILE)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def proc_start_ticks(pid: int) -> int:
    """Read the kernel start-ticks of *pid* from /proc.

    Returns None on non-Linux platforms or when the process no longer exists.
    """
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            stat = f.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return None
    # comm (field 2) is parenthesised and may contain spaces/parens itself,
    # so split after the LAST closing paren; starttime is field 22 overall,
    # i.e. the 20th field counting from state (field 3).
    tail = stat.rsplit(')', 1)[-1].split()
    if len(tail) < 20:
        return None
    try:
        return int(tail[19])
    except ValueError:
        return None


def is_process_alive(pid: int, start_ticks: int = None) -> bool:
    """True when *pid* is alive and (when known) still the same process.

    When *start_ticks* is None (unsupported platform or unknown), fall back to
    a bare existence probe.
    """
    if pid is None or pid <= 0:
        return False
    current = proc_start_ticks(pid)
    if current is None:
        # Either the process is gone or /proc is unavailable. Distinguish via
        # a signal-0 probe so non-Linux platforms still work.
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # exists but owned by someone else
        except OSError:
            return False
        return start_ticks is None
    if start_ticks is None:
        return True
    return current == start_ticks


def patch_progress(work_dir: str, status: str, error: str = None) -> bool:
    """Atomically overwrite the status of an existing ``progress.json``.

    Only ``status`` and ``error`` are touched; every other field (percent,
    counts, updated_at, ...) is preserved. Returns True on success, False
    when the file is missing or unreadable (nothing to patch).
    """
    path = os.path.join(work_dir, PROGRESS_FILE)
    try:
        with open(path, 'r', encoding='utf-8') as f:
            state = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return False
    if not isinstance(state, dict):
        return False
    state['status'] = status
    state['error'] = error
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    return True
