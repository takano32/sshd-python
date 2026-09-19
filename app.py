import asyncio
import os

import asyncssh

HOST_KEY_PATH = os.environ.get("SSH_HOST_KEY", "ssh_host_key")


def load_host_key():
    if os.path.exists(HOST_KEY_PATH):
        return asyncssh.read_private_key(HOST_KEY_PATH)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(HOST_KEY_PATH)
    return key


class Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        # 認証なしでログインを許可する
        return False


async def handle_client(process):
    username = process.get_extra_info("username")
    process.stdout.write(f"Hello, {username}!\r\n")
    process.exit(0)


async def main():
    port = int(os.environ["SERVER_PORT"])
    await asyncssh.create_server(
        Server,
        "",
        port,
        server_host_keys=[load_host_key()],
        process_factory=handle_client,
    )
    print(f"Listening on port {port}", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
