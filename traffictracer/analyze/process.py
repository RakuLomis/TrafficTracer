"""Job-scoped cancellation for analysis subprocesses without pipe deadlocks."""

from contextlib import contextmanager
from contextvars import ContextVar
import os
import io
import signal
import subprocess
import tempfile
import time
from threading import Thread

from traffictracer.jobs.cancellation import CancellationToken
from traffictracer.process_env import external_process_env

_token: ContextVar[CancellationToken | None] = ContextVar("analysis_token", default=None)


class AnalysisCommandLimitError(RuntimeError):
    """A command exceeded a bound; never report partial output as success."""


def analysis_checkpoint():
    token = _token.get()
    if token is not None:
        token.checkpoint()


@contextmanager
def analysis_process_scope(token):
    handle = _token.set(token)
    try:
        yield
    finally:
        _token.reset(handle)


def run_analysis_command(command, **kwargs):
    consumer = kwargs.pop("stdout_consumer", None)
    kwargs["env"] = external_process_env(kwargs.get("env"))
    token = _token.get()
    if token is None:
        result = subprocess.run(command, **kwargs)
        if consumer is not None and result.returncode == 0:
            result.stdout = consumer(io.StringIO(result.stdout))
        return result
    token.checkpoint()
    capture = kwargs.pop("capture_output", False)
    text = kwargs.pop("text", False)
    check = kwargs.pop("check", False)
    timeout = kwargs.pop("timeout", float(os.environ.get("TRAFFICTRACER_ANALYSIS_COMMAND_TIMEOUT_SECONDS", "1800")))
    started = time.monotonic()
    with tempfile.TemporaryFile() as output:
        kwargs["stdout"] = output if capture else kwargs.get("stdout", subprocess.DEVNULL)
        # Keep diagnostics off pipes; bounded reads on completion avoid retaining
        # arbitrary stderr in Python memory.
        kwargs["stderr"] = subprocess.PIPE
        process = subprocess.Popen(command, start_new_session=True, **kwargs)
        diagnostics = bytearray()
        def drain_errors():
            with process.stderr:
                while True:
                    chunk = process.stderr.read(4096)
                    if not chunk:
                        break
                    diagnostics.extend(chunk)
                    del diagnostics[:-8192]
        drainer = Thread(target=drain_errors, name="analysis-stderr", daemon=True)
        drainer.start()
        try:
            while process.poll() is None:
                token.checkpoint()
                if timeout is not None and time.monotonic() - started > timeout:
                    raise subprocess.TimeoutExpired(command, timeout)
                if capture and consumer is None and os.fstat(output.fileno()).st_size > 64 * 1024 * 1024:
                    raise AnalysisCommandLimitError("ANALYSIS_COMMAND_OUTPUT_LIMIT: use streamed output for large results")
                token.wait(.2)
            token.checkpoint()
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
            drainer.join(timeout=2)
            raise
        drainer.join(timeout=2)
        output.seek(0)
        if capture and consumer is None and os.fstat(output.fileno()).st_size > 64 * 1024 * 1024:
            raise AnalysisCommandLimitError("ANALYSIS_COMMAND_OUTPUT_LIMIT: use streamed output for large results")
        if consumer is not None and process.returncode == 0:
            wrapper = io.TextIOWrapper(output, encoding="utf-8", errors="replace")
            try:
                stdout = consumer(wrapper)
            finally:
                wrapper.detach()
        else:
            stdout = output.read(8192 if consumer else -1) if capture else None
        stderr = bytes(diagnostics)
        if text:
            stdout = stdout.decode(errors="replace") if isinstance(stdout, bytes) else stdout
            stderr = stderr.decode(errors="replace")
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        if check:
            result.check_returncode()
        return result
