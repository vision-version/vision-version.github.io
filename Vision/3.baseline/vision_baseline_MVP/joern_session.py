from pathlib import Path
import sys
import pexpect
import traceback
import shutil

import re

def shesc(sometext):
    ansi_escape = re.compile(
        r"""
        \x1B  
        (?:   
            [@-Z\\-_]
        |    
            \[
            [0-?]*  
            [ -/]*  
            [@-~]   
        )
    """,
        re.VERBOSE,
    )
    return ansi_escape.sub("", sometext)

class JoernSession:
    def __init__(self, worker_id: int = 0, logfile=None, clean=False, work_dir="/path/to/joern"):
        self.proc = pexpect.spawn(f"{work_dir}/joern --nocolors", timeout=60000, logfile=logfile)
        self.read_until_prompt()
        self.worker_id = worker_id

        if worker_id != 0:
            workspace = "workers/" + str(worker_id)
            self.switch_workspace(workspace)
        else:
            workspace = "workspace"

        workspace_dir = Path(workspace)
        if clean and workspace_dir.exists():
            shutil.rmtree(workspace_dir)

    def get_worker_id():
        return self.worker_id
    def read_until_prompt(self, zonk_line=False, timeout=-1):
        pattern = "joern>"
        if zonk_line:
            pattern += ".*\n"
        out = self.proc.expect(pattern, timeout=timeout)
        return shesc(self.proc.before.decode()).strip("\r")

    def close(self, force=True):
        self.proc.timeout = 5
        try:
            self.proc.sendline("exit")
            self.proc.sendline("y")
            self.proc.expect(pexpect.EOF)
            return shesc(self.proc.before.decode().strip("\r")).strip()
        except pexpect.exceptions.TIMEOUT:
            print("could not exit cleanly. terminating with force")
            self.proc.terminate(force)
            return shesc(self.proc.before.decode().strip("\r")).strip()

    def send_line(self, cmd: str):
        self.proc.sendline(cmd)
        self.read_until_prompt(zonk_line=True) 

    def run_command(self, command, timeout=-1):
        self.send_line(command)
        return self.read_until_prompt(timeout=timeout).strip()

    def import_script(self, script: str):
        scriptdir: Path = Path("script")
        scriptdir_str = str(scriptdir)
        if scriptdir_str.endswith("/"):
            scriptdir_str = scriptdir_str[:-1]
        scriptdir_str = scriptdir_str.replace("/", ".")
        self.run_command("import $file." + str(scriptdir_str) + "." + str(script))

    def run_script(self, script: str, params, import_first=True, timeout=-1):
        if import_first:
            self.import_script(script)

        def get_str_repr(k, v):
            if isinstance(v, str) or isinstance(v, Path):
                return str(k) + '="' + str(v) + '"'
            elif isinstance(v, bool):
                return str(k) + "=" + str(v).lower()
            elif isinstance(v, int):
                return str(k) + "=" + str(v)
            else:
                raise NotImplementedError(
                    str(k) + ": " + str(v) + " (" + str(type(v)) + ")"
                )

        params_str = ", ".join(get_str_repr(k, v) for k, v in params.items())
        return self.run_command(script + ".exec(" + params_str + ")", timeout=timeout)

    def switch_workspace(self, filepath: str):
        return self.run_command('switchWorkspace("' + filepath + '")')

    def import_code(self, filepath: str):
        return self.run_command('importCode("' + str(filepath) + '")')

    def import_cpg(self, cpgpath: str, filepath: str):
        if Path(cpgpath).exists():
            return self.run_command('importCpg("' + cpgpath + '")')
        else:
            print("cpg missing, import code", filepath)
            ret = self.import_code(filepath)
            try:
                shutil.copyfile(self.cpg_path(), cpgpath)
            except Exception:
                traceback.print_exc()
            return ret

    def delete(self):
        return self.run_command(f"delete")

    def list_workspace(self):
        return self.run_command("workspace")

    def cpg_path(self):
        project_path = self.run_command("print(project.path)")
        cpg_path = Path(project_path) / "cpg.bin"
        return cpg_path

def test_close():
    sess = JoernSession(logfile=sys.stdout.buffer)
    sess.send_line(
        """for (i <- 1 to 1000) {println(s"iteration $i"); Thread.sleep(1000);}""")
    sess.close()


def test_get_cpg():
    sess = JoernSession(logfile=sys.stdout.buffer)
    try:
        sess.import_code("x42/c/X42.c")
        cpg_path = sess.cpg_path()
        assert cpg_path.exists(), cpg_path
        sess.delete()
    finally:
        sess.close()


def test_interaction():
    sess = JoernSession(logfile=sys.stdout.buffer)
    try:
        sess.list_workspace()
        sess.import_code("x42/c/X42.c")
        sess.list_workspace()
        sess.delete()
        sess.list_workspace()
    finally:
        sess.close()