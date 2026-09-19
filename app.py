import asyncio
import errno
import fcntl
import grp
import os
import pty
import pwd
import signal
import struct
import termios

import asyncssh

try:
    import pam
except ImportError:
    pam = None

HOST_KEY_PATH = os.environ.get("SSH_HOST_KEY", "ssh_host_key")
# sshd の AuthorizedKeysFile と同じく %h (ホーム) と %u (ユーザ名) を展開する
AUTHORIZED_KEYS_FILE = os.environ.get(
    "AUTHORIZED_KEYS_FILE", ".ssh/authorized_keys"
)
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SFTP_SERVER_PATHS = [
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
]


def load_host_key():
    if os.path.exists(HOST_KEY_PATH):
        return asyncssh.read_private_key(HOST_KEY_PATH)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(HOST_KEY_PATH)
    return key


def lookup_user(username):
    try:
        pw = pwd.getpwnam(username)
    except KeyError:
        return None
    # root で動いていなければ、自分以外のユーザにはなれない
    if os.geteuid() != 0 and pw.pw_uid != os.geteuid():
        return None
    return pw


def authorized_keys_path(pw):
    path = AUTHORIZED_KEYS_FILE.replace("%h", pw.pw_dir).replace("%u", pw.pw_name)
    return os.path.join(pw.pw_dir, path)


def find_sftp_server():
    for path in SFTP_SERVER_PATHS:
        if os.access(path, os.X_OK):
            return path
    return None


def pam_service():
    return "sshd" if os.path.exists("/etc/pam.d/sshd") else "login"


class Server(asyncssh.SSHServer):
    def connection_made(self, conn):
        self._conn = conn
        self._pw = None

    def begin_auth(self, username):
        self._pw = lookup_user(username)
        keys = asyncssh.import_authorized_keys("")
        if self._pw:
            try:
                keys = asyncssh.read_authorized_keys(authorized_keys_path(self._pw))
            except (OSError, ValueError):
                pass
        self._conn.set_authorized_keys(keys)
        return True

    def public_key_auth_supported(self):
        return True

    def password_auth_supported(self):
        return pam is not None

    async def validate_password(self, username, password):
        # PermitRootLogin prohibit-password 相当
        if self._pw is None or self._pw.pw_uid == 0:
            return False
        return await asyncio.to_thread(
            pam.pam().authenticate, username, password, service=pam_service()
        )

    def session_requested(self):
        return Session()

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        return True

    def server_requested(self, listen_host, listen_port):
        # 一般ユーザには特権ポートでの待ち受けを許さない
        if 0 < listen_port < 1024 and self._pw.pw_uid != 0:
            return False
        return True


class Session(asyncssh.SSHServerSession):
    def __init__(self):
        self._chan = None
        self._pw = None
        self._command = None
        self._subsystem = None
        self._term_type = None
        self._term_size = None
        self._proc = None
        self._stdin = None
        self._outputs = {}
        self._pending = b""
        self._stdin_eof = False
        self._started = False
        self._done = None
        self._task = None

    def connection_made(self, chan):
        self._chan = chan
        self._pw = lookup_user(chan.get_extra_info("username"))

    def pty_requested(self, term_type, term_size, term_modes):
        self._term_type = term_type
        self._term_size = term_size
        return True

    def shell_requested(self):
        return True

    def exec_requested(self, command):
        self._command = command
        return True

    def subsystem_requested(self, subsystem):
        if subsystem == "sftp":
            self._subsystem = find_sftp_server()
        return self._subsystem is not None

    def session_started(self):
        self._task = asyncio.get_running_loop().create_task(self._run())

    def _environment(self, tty_name):
        pw = self._pw
        # AcceptEnv LANG LC_* 相当
        env = {
            k: v
            for k, v in self._chan.get_environment().items()
            if k == "LANG" or k.startswith("LC_")
        }
        peer_host, peer_port = self._chan.get_extra_info("peername")[:2]
        local_host, local_port = self._chan.get_extra_info("sockname")[:2]
        env.update(
            HOME=pw.pw_dir,
            USER=pw.pw_name,
            LOGNAME=pw.pw_name,
            SHELL=pw.pw_shell or "/bin/sh",
            PATH=DEFAULT_PATH,
            SSH_CLIENT=f"{peer_host} {peer_port} {local_port}",
            SSH_CONNECTION=f"{peer_host} {peer_port} {local_host} {local_port}",
        )
        if tty_name:
            env["TERM"] = self._term_type or "dumb"
            env["SSH_TTY"] = tty_name
        agent_path = self._chan.get_agent_path()
        if agent_path:
            if os.geteuid() == 0:
                os.chown(os.path.dirname(agent_path), pw.pw_uid, pw.pw_gid)
                os.chown(agent_path, pw.pw_uid, pw.pw_gid)
            env["SSH_AUTH_SOCK"] = agent_path
        key_env = self._chan.get_connection().get_key_option("environment")
        if key_env:
            env.update(key_env)
        return env

    def _argv(self, env):
        shell = self._pw.pw_shell or "/bin/sh"
        forced = self._chan.get_connection().get_key_option("command")
        if forced:
            if self._command is not None:
                env["SSH_ORIGINAL_COMMAND"] = self._command
            return shell, [shell, "-c", forced]
        if self._subsystem:
            return self._subsystem, [self._subsystem]
        if self._command is not None:
            return shell, [shell, "-c", self._command]
        # ログインシェルとして起動する
        return shell, ["-" + os.path.basename(shell)]

    async def _run(self):
        pw = self._pw
        use_pty = self._term_type is not None and not self._subsystem
        kwargs = {"start_new_session": True}
        if os.geteuid() == 0:
            kwargs.update(
                user=pw.pw_uid,
                group=pw.pw_gid,
                extra_groups=os.getgrouplist(pw.pw_name, pw.pw_gid),
            )
        cwd = pw.pw_dir if os.path.isdir(pw.pw_dir) else "/"

        if use_pty:
            master, slave = pty.openpty()
            self._set_winsize(master, *self._term_size[:2])
            if os.geteuid() == 0:
                try:
                    tty_gid = grp.getgrnam("tty").gr_gid
                except KeyError:
                    tty_gid = -1
                os.fchown(slave, pw.pw_uid, tty_gid)
                os.fchmod(slave, 0o620)
            tty_name = os.ttyname(slave)
            child_fds = (slave, slave, slave)
            self._stdin = master
            self._outputs = {master: None}
            kwargs["preexec_fn"] = lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        else:
            stdin_r, self._stdin = os.pipe()
            stdout_r, stdout_w = os.pipe()
            stderr_r, stderr_w = os.pipe()
            tty_name = None
            child_fds = (stdin_r, stdout_w, stderr_w)
            self._outputs = {
                stdout_r: None,
                stderr_r: asyncssh.EXTENDED_DATA_STDERR,
            }

        env = self._environment(tty_name)
        executable, argv = self._argv(env)
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *argv,
                executable=executable,
                stdin=child_fds[0],
                stdout=child_fds[1],
                stderr=child_fds[2],
                cwd=cwd,
                env=env,
                **kwargs,
            )
        except OSError as exc:
            self._chan.write_stderr(f"{executable}: {exc.strerror}\r\n".encode())
            self._chan.exit(1)
            return
        finally:
            for fd in set(child_fds):
                os.close(fd)

        loop = asyncio.get_running_loop()
        self._done = loop.create_future()
        for fd in self._outputs:
            os.set_blocking(fd, False)
            loop.add_reader(fd, self._read_ready, fd)
        os.set_blocking(self._stdin, False)
        # 起動前に届いていた入力を流す
        self._started = True
        if self._pending:
            self._write_ready()
        elif self._stdin_eof:
            self._close_stdin()

        returncode = await self._proc.wait()
        if use_pty:
            # シェル終了後に残った出力を流しきってから閉じる
            self._read_ready(master)
            self._close_output(master)
        if self._outputs:
            await self._done
        self._close_stdin()

        if returncode < 0:
            self._chan.exit_with_signal(signal.Signals(-returncode).name[3:])
        else:
            self._chan.exit(returncode)

    @staticmethod
    def _set_winsize(fd, width, height):
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))

    def _read_ready(self, fd):
        while fd in self._outputs:
            try:
                data = os.read(fd, 65536)
            except BlockingIOError:
                return
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                data = b""
            if not data:
                self._close_output(fd)
                return
            self._chan.write(data, self._outputs[fd])

    def _close_output(self, fd):
        if fd not in self._outputs:
            return
        asyncio.get_running_loop().remove_reader(fd)
        del self._outputs[fd]
        if fd != self._stdin:
            os.close(fd)
        if not self._outputs and self._done and not self._done.done():
            self._done.set_result(None)

    def _close_stdin(self):
        if self._stdin is None:
            return
        asyncio.get_running_loop().remove_writer(self._stdin)
        os.close(self._stdin)
        self._stdin = None

    def _write_ready(self):
        try:
            n = os.write(self._stdin, self._pending)
        except BlockingIOError:
            n = 0
        except OSError:
            self._pending = b""
            n = 0
        self._pending = self._pending[n:]
        if not self._pending:
            asyncio.get_running_loop().remove_writer(self._stdin)
            if self._stdin_eof:
                self._close_stdin()
        else:
            asyncio.get_running_loop().add_writer(self._stdin, self._write_ready)

    def data_received(self, data, datatype):
        if self._started and self._stdin is None:
            return
        was_pending = bool(self._pending)
        self._pending += data
        if self._started and not was_pending:
            self._write_ready()

    def eof_received(self):
        # PTY は入出力で同じ fd を共有しているので閉じない
        if self._term_type is not None and not self._subsystem:
            return True
        self._stdin_eof = True
        if self._started and self._stdin is not None and not self._pending:
            self._close_stdin()
        return True

    def pause_writing(self):
        for fd in self._outputs:
            asyncio.get_running_loop().remove_reader(fd)

    def resume_writing(self):
        for fd in self._outputs:
            asyncio.get_running_loop().add_reader(fd, self._read_ready, fd)

    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        if self._term_type is not None and self._stdin is not None:
            self._set_winsize(self._stdin, width, height)

    def signal_received(self, signame):
        signum = getattr(signal, "SIG" + signame, None)
        if self._proc and self._proc.returncode is None and signum:
            self._proc.send_signal(signum)

    def connection_lost(self, exc):
        if self._proc and self._proc.returncode is None:
            self._proc.send_signal(signal.SIGHUP)


async def main():
    port = int(os.environ["SERVER_PORT"])
    await asyncssh.create_server(
        Server,
        "",
        port,
        server_host_keys=[load_host_key()],
        encoding=None,
        agent_forwarding=True,
    )
    print(f"Listening on port {port}", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
