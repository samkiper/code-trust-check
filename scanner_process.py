"""Stop the entire scanner process group before returning a timeout."""
import os
import signal
import subprocess


def run_scanner(command, *, capture_output=True, text=True, timeout, check=False, env=None):
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=text, env=env, start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            # Semgrep's CLI can spawn a core engine. Killing just the CLI can
            # leave the core consuming the slot's CPU after the caller returns.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
