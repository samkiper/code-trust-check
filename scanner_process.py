"""Stop the entire scanner process group before returning a timeout."""
import os
import signal
import subprocess


def run_scanner(command, *, capture_output=True, text=True, timeout, check=False, env=None):
    isolated = os.getenv("AUDIT_ISOLATED_WORKER") == "1"
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=text, env=env, start_new_session=not isolated) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            # Semgrep's CLI can spawn a core engine. Killing just the CLI can
            # leave the core consuming the slot's CPU after the caller returns.
            try:
                if isolated:process.kill()
                else:os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:process.communicate(timeout=1)
            except subprocess.TimeoutExpired:pass
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
