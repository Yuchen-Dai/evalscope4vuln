import contextlib
import io
import multiprocessing
import os
import queue
import signal
import sys
import threading
import time
import traceback

from evalscope.config import TaskConfig
from evalscope.run import run_task
from evalscope.utils.logger import get_logger

logger = get_logger()

# ---------------------------------------------------------------------------
# Active process registry – allows external stop by task_id
# ---------------------------------------------------------------------------

_active_processes: dict[str, multiprocessing.Process] = {}
"""Maps task_id → the subprocess currently running that task."""

_adopted: dict[str, tuple[int, int]] = {}
"""Maps task_id → (pid, start_ticks) for orphaned children adopted after a
service restart. These processes are still alive but no longer owned by this
process tree, so they can only be identified/killed via their pid."""

_active_lock = threading.Lock()


def register_process(task_id: str, proc: multiprocessing.Process) -> None:
    """Register a running subprocess so it can be stopped later."""
    with _active_lock:
        _active_processes[task_id] = proc


def unregister_process(task_id: str) -> None:
    """Remove a finished / stopped subprocess from the registry."""
    with _active_lock:
        _active_processes.pop(task_id, None)
        _adopted.pop(task_id, None)


def adopt_task(task_id: str, pid: int, start_ticks: int = None) -> None:
    """Adopt an orphaned child process (alive but not in this process tree)."""
    with _active_lock:
        _adopted[task_id] = (pid, start_ticks)


def _stop_adopted(pid: int, start_ticks: int) -> bool:
    """Terminate an adopted process by pid (SIGTERM, escalate to SIGKILL)."""
    from .task_runtime import is_process_alive

    if not is_process_alive(pid, start_ticks):
        return True  # Already gone; nothing to do.
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        return is_process_alive(pid, start_ticks) is False
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if not is_process_alive(pid, start_ticks):
            return True
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    return not is_process_alive(pid, start_ticks)


def stop_process(task_id: str) -> bool:
    """Terminate the subprocess associated with *task_id*.

    Also covers adopted (orphaned) processes from before a service restart,
    killed by pid. Returns True if a process was found and terminated.
    """
    with _active_lock:
        proc = _active_processes.pop(task_id, None)
        adopted = _adopted.pop(task_id, None) if proc is None else None
    if proc is None:
        if adopted is None:
            return False
        stopped = _stop_adopted(*adopted)
        if stopped:
            logger.info(f'Task {task_id} (adopted pid {adopted[0]}) stopped by user.')
        return stopped
    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=3)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=2)
    logger.info(f'Task {task_id} stopped by user.')
    return True


def list_active_processes():
    """Snapshot of currently-registered (task_id, Process) pairs (under lock)."""
    with _active_lock:
        return list(_active_processes.items())


def is_task_running(task_id: str) -> bool:
    """True if task_id is registered AND its process is still alive.

    Falls back to a pid liveness probe for adopted (orphaned) tasks.
    """
    from .task_runtime import is_process_alive

    with _active_lock:
        proc = _active_processes.get(task_id)
        if proc is not None:
            return proc.is_alive()
        adopted = _adopted.get(task_id)
    if adopted is None:
        return False
    return is_process_alive(*adopted)


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _capture_stderr():
    """Context manager that redirects sys.stderr to a StringIO buffer.

    Yields the buffer so the caller can read captured output after the block.
    Always restores the original sys.stderr on exit.
    """
    buf = io.StringIO()
    original = sys.stderr
    sys.stderr = buf
    try:
        yield buf
    finally:
        sys.stderr = original


def _process_worker(func, result_queue, *args, **kwargs):
    """Target for multiprocessing.Process — executes *func* and posts result.

    stderr is captured and forwarded through the queue so the parent process
    can surface it even when the child crashes before *func* is reached.
    """
    with _capture_stderr() as stderr_buf:
        try:
            result = func(*args, **kwargs)
            result_queue.put({'status': 'success', 'result': result})
        except BaseException as e:
            result_queue.put({
                'status': 'error',
                'error': str(e),
                'traceback': traceback.format_exc(),
                'stderr': stderr_buf.getvalue(),
            })


def run_in_subprocess(func, *args, task_id=None, **kwargs):
    """Run *func* in a child process and return its result (blocks caller).

    Returns the function's return value on success; raises on error.

    If *task_id* is provided the child process is registered in the active
    process registry so it can be terminated via :func:`stop_process`.

    Design note — why polling instead of p.join() then queue.get():
    ``multiprocessing.Queue`` is backed by an OS pipe whose buffer is typically
    only 64 KB.  If the child calls ``queue.put()`` with a payload larger than
    that buffer it will *block* until the parent drains the pipe.  But if the
    parent is sitting in ``p.join()`` waiting for the child to exit first, both
    sides wait on each other forever — a classic deadlock.
    """
    # Use spawn context to avoid fork-based deadlocks on Linux and to
    # ensure consistent cross-platform behaviour (macOS defaults to spawn,
    # Linux defaults to fork).
    ctx = multiprocessing.get_context('spawn')
    result_queue = ctx.Queue()
    p = ctx.Process(target=_process_worker, args=(func, result_queue, *args), kwargs=kwargs)
    p.start()

    if task_id:
        register_process(task_id, p)

    res = None
    # Poll for the result while the child is alive so we continuously drain
    # the underlying pipe and never let queue.put() block in the child.
    while p.is_alive():
        try:
            res = result_queue.get(timeout=0.1)
            break  # Got the result; let the child finish normally.
        except queue.Empty:
            continue  # Child still running — keep draining.

    # Wait for the child to clean up after we have the result (or it crashed).
    p.join()

    if task_id:
        unregister_process(task_id)

    if res is not None:
        if res['status'] == 'error':
            stderr_info = res.get('stderr', '')
            stderr_section = f'\n[stderr]\n{stderr_info}' if stderr_info.strip() else ''
            raise RuntimeError(f"Subprocess error: {res['error']}\n{res.get('traceback', '')}{stderr_section}")
        return res['result']

    # res is still None: the child exited without putting anything in the queue
    # (OOM, SIGKILL, import error, segfault, etc.).
    # Do one final non-blocking check in case the item arrived between the last
    # loop iteration and p.join() returning.
    try:
        res = result_queue.get_nowait()
        if res['status'] == 'error':
            stderr_info = res.get('stderr', '')
            stderr_section = f'\n[stderr]\n{stderr_info}' if stderr_info.strip() else ''
            raise RuntimeError(f"Subprocess error: {res['error']}\n{res.get('traceback', '')}{stderr_section}")
        return res['result']
    except queue.Empty:
        pass

    raise RuntimeError(
        f'Subprocess terminated unexpectedly (exit code {p.exitcode}). '
        'The child process may have crashed due to OOM, a missing import, '
        'GPU initialisation failure, or a signal (e.g. SIGKILL).'
    ) from None


def start_subprocess(func, *args, task_id=None, **kwargs):
    """异步：启动子进程跑 func，立即返回 Process（不阻塞、不收集结果）。

    service invoke 异步提交用——子进程后台跑，进度/结果经 progress.json + reports/
    落地（不走 result_queue，避免大 payload 死锁子进程退出）。完成检测靠 monitor
    线程查 proc.is_alive()（调用方负责 unregister + close）。
    """
    ctx = multiprocessing.get_context('spawn')
    p = ctx.Process(target=func, args=args, kwargs=kwargs)
    p.start()
    if task_id:
        register_process(task_id, p)
    return p


# ---------------------------------------------------------------------------
# Task wrappers (thin shims kept for clarity / future extension)
# ---------------------------------------------------------------------------


def run_eval_wrapper(task_config: TaskConfig):
    """Run an evaluation task and return the result."""
    return run_task(task_config)


def serialize_result(result):
    """Convert Pydantic model objects (or containers of them) to plain dicts for JSON.

    Recursively walks dicts and lists, converting any Pydantic ``BaseModel``
    instances (``Report``, ``BenchmarkSummary``, ``PercentileResult``, etc.)
    to plain dicts via ``model_dump()`` / ``to_dict()``.
    """
    from pydantic import BaseModel

    if isinstance(result, BaseModel):
        # Report has a custom to_dict() that delegates to model_dump()
        if hasattr(result, 'to_dict'):
            return result.to_dict()
        return result.model_dump()
    if isinstance(result, dict):
        return {k: serialize_result(v) for k, v in result.items()}
    if isinstance(result, list):
        return [serialize_result(v) for v in result]
    return result
