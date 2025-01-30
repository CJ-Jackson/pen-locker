#!/usr/bin/env python3
import argparse
import getpass
import json
import os
import pathlib
import string
import subprocess
import sys
import time
import tomllib

parser = argparse.ArgumentParser(description="Pen-locker handler")

parser.add_argument('toml')
parser.add_argument('--cmd', required=True)

args = parser.parse_args()

arg_toml = args.toml
flag_command = args.cmd

commands: dict = {}


def valid_name(name: str) -> bool:
    return not set(name).difference(string.ascii_letters + string.digits + "_-")


class ValidNameError(Exception): pass


def get_user_config() -> dict:
    real_toml = os.path.realpath(arg_toml)
    os.chdir(os.path.dirname(real_toml))
    with open(real_toml, "rb") as f:
        data: dict = tomllib.load(f)
    if not valid_name(data["name"]):
        print("Invalid name", file=sys.stderr)
        exit(1)
    data["image"] = os.path.realpath(data["image"])
    data["mount"] = os.path.realpath(data["mount"])
    return data


def handle_recv_fifo(fifo_path: str):
    while not os.access(fifo_path, os.R_OK):
        time.sleep(1)
    with open(fifo_path, "r") as fifo:
        data: dict = json.load(fifo)
    if "stderr" in data:
        print(data["stderr"], file=sys.stderr)
    if "stdout" in data:
        print(data["stdout"])
    exit(data.get("code", 0))


def check_permission():
    if not os.access("/tmp/pen-locker.path", os.W_OK):
        print("Has no permission", sys.stderr)
        exit(100)


def create_send_fifo_add_to_queue() -> str:
    fifo_path = f"/tmp/pen-locker-recv-fifo-{time.time()}"
    os.mkfifo(fifo_path, 0o640)

    pathlib.Path(f"/tmp/pen-locker-queue/pen-locker-{time.time()}-queue").write_text(fifo_path, "utf-8")

    # Trigger systemd oneshot
    pathlib.Path("/tmp/pen-locker.path").touch()

    return fifo_path


def user_open():
    check_permission()

    fifo_recv_path = f"/tmp/pen-locker-user-open-fifo-{time.time()}"

    config = get_user_config()

    data: dict
    if os.path.exists(os.path.expanduser(f"~/.config/pen-locker/key/{config['name']}.bin")):
        data = {
            "cmd": "open_key",
            "key_file": os.path.expanduser(f"~/.config/pen-locker/key/{config['name']}.bin"),
            "fifo": fifo_recv_path,
        } | config
    else:
        process = subprocess.run(["zbarcam", "--raw", "-1"], check=True, capture_output=True)
        data = {
            "cmd": "open_passwd",
            "passwd": process.stdout.decode('utf-8').strip(),
            "fifo": fifo_recv_path,
        } | config

    fifo_send_path = create_send_fifo_add_to_queue()

    with open(fifo_send_path, "w") as fifo:
        json.dump(data, fifo)
        fifo.flush()

    os.remove(fifo_send_path)

    handle_recv_fifo(fifo_recv_path)


commands["open"] = user_open


def user_close():
    check_permission()

    fifo_recv_path = f"/tmp/pen-locker-user-close-fifo-{time.time()}"

    data = {
        "cmd": "close",
        "fifo": fifo_recv_path,
    } | get_user_config()

    fifo_send_path = create_send_fifo_add_to_queue()

    with open(fifo_send_path, "w") as fifo:
        json.dump(data, fifo)
        fifo.flush()

    os.remove(fifo_send_path)

    handle_recv_fifo(fifo_recv_path)


commands["close"] = user_close


def root_success(fifo_path: str):
    with open(fifo_path, "w") as fifo:
        json.dump({
            "code": 0,
            "stdout": "success"
        }, fifo)
        fifo.flush()


def root_fail(fifo_path: str, code: int, msg: str):
    with open(fifo_path, "w") as fifo:
        json.dump({
            "code": code,
            "stderr": msg
        }, fifo)
        fifo.flush()


def root_open(fifo_path: str, name: str, image: str, filesystem: str, mount: str, key: str = "", passwd: str = ""):
    if not valid_name(name):
        raise ValidNameError("Name not valid")
    if key:
        subprocess.run([
            "cryptsetup", "open", "--type", "luks", image, f"pen-locker-{name}", "--key-file", key
        ], check=True, capture_output=True)
    else:
        subprocess.run([
            "cryptsetup", "open", "--type", "luks", image, name
        ], check=True, capture_output=True, input=passwd.encode('utf-8'))
    subprocess.run([
        "mount", "-t", filesystem, f"/dev/mapper/pen-locker-{name}", mount
    ], check=True, capture_output=True)
    root_success(fifo_path)



def root_close(fifo_path: str, name: str, mount: str):
    if not valid_name(name):
        raise ValidNameError("Name not valid")
    subprocess.run([
        "umount", mount
    ], check=True, capture_output=True)
    subprocess.run([
        "cryptsetup", "close", f"pen-locker-{name}"
    ], check=True, capture_output=True)
    root_success(fifo_path)


def process_queue(recv_fifo_path: str):
    if not os.path.exists(recv_fifo_path):
        time.sleep(1)
        return
    path_gid = os.stat(recv_fifo_path).st_gid
    with open(recv_fifo_path, "r") as fifo:
        data = json.load(fifo)
    fifo_path = data["fifo"]
    os.mkfifo(fifo_path, 0o640)
    os.chown(fifo_path, 0, path_gid)
    try:
        match data:
            case {"cmd": "open_key"}:
                root_open(fifo_path, data["name"], data["image"], data["filesystem"], data["mount"], key=data["key_file"])
            case {"cmd": "open_passwd"}:
                root_open(fifo_path, data["name"], data["image"], data["filesystem"], data["mount"], passwd=data["passwd"])
            case {"cmd": "close"}:
                root_close(fifo_path, data["name"], data["mount"])
    except subprocess.CalledProcessError as e:
        root_fail(fifo_path, e.returncode, str(e.stderr))
    except ValidNameError:
        root_fail(fifo_path, 1, "Name not valid")
    except KeyError as e:
        root_fail(fifo_path, 1, e.__str__())
    os.remove(fifo_path)
    time.sleep(1)


def recv():
    if getpass.getuser() != "root":
        print("Must be root to run `recv`", file=sys.stderr)
        exit(1)
    for queue in pathlib.Path("/tmp/pen-locker-queue").glob("pen-locker-*-queue"):
        fifo_path = pathlib.Path(str(queue)).read_text('utf-8').strip()
        os.remove(str(queue))
        process_queue(fifo_path)


commands["recv"] = recv

try:
    commands[flag_command]()
except KeyError:
    print("Could not find command", file=sys.stderr)
