"""Enter a private network namespace, then drop root for Packer and QEMU."""
import argparse
import os
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--uid", type=int, required=True)
parser.add_argument("--gid", type=int, required=True)
parser.add_argument("--groups", required=True)
parser.add_argument("command", nargs=argparse.REMAINDER)
args = parser.parse_args()
if os.geteuid() != 0 or os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
    raise SystemExit("offline runner requires root inside a separate network namespace")
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
if subprocess.check_output(["ip", "route", "show", "default"]):
    raise SystemExit("offline namespace unexpectedly has an external route")
os.setgroups([int(group) for group in args.groups.split(",")])
os.setgid(args.gid)
os.setuid(args.uid)
command = args.command[1:] if args.command[:1] == ["--"] else args.command
os.execvpe(command[0], command, os.environ.copy())
