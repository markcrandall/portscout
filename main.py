"""portscout — cross-platform port/process CLI tool."""

import argparse
import sys

import psutil


def cmd_listen(args):
    """List all listening ports."""
    rows = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != "LISTEN":
            continue
        port = conn.laddr.port
        addr = conn.laddr.ip
        pid = conn.pid or "-"
        name = "-"
        if conn.pid:
            try:
                name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        rows.append((port, pid, name, addr))

    rows.sort(key=lambda r: r[0])
    if not rows:
        print("No listening ports found.")
        return

    print(f"{'PORT':<8} {'PID':<8} {'PROCESS':<25} {'ADDRESS'}")
    print("-" * 65)
    for port, pid, name, addr in rows:
        print(f"{port:<8} {str(pid):<8} {name:<25} {addr}")


def cmd_port(args):
    """Show detail on a specific port."""
    target = args.port
    found = False
    for conn in psutil.net_connections(kind="inet"):
        if conn.laddr.port != target:
            continue
        found = True
        pid = conn.pid
        if not pid:
            print(f"Port {target} — connection with no owning PID (status: {conn.status})")
            continue
        try:
            proc = psutil.Process(pid)
            cmdline = " ".join(proc.cmdline()) or "-"
            print(f"Port:     {target}")
            print(f"PID:      {pid}")
            print(f"Process:  {proc.name()}")
            print(f"Cmdline:  {cmdline}")
            print(f"Status:   {conn.status}")
            print(f"Local:    {conn.laddr.ip}:{conn.laddr.port}")
            if conn.raddr:
                print(f"Remote:   {conn.raddr.ip}:{conn.raddr.port}")
            print()
        except psutil.NoSuchProcess:
            print(f"Port {target} — PID {pid} no longer exists")
        except psutil.AccessDenied:
            print(f"Port {target} — PID {pid} (access denied, try elevated)")

    if not found:
        print(f"Nothing found on port {target}.")
        sys.exit(1)


def cmd_kill(args):
    """Terminate the process on a port."""
    target = args.port
    pids = set()
    for conn in psutil.net_connections(kind="inet"):
        if conn.laddr.port == target and conn.pid:
            pids.add(conn.pid)

    if not pids:
        print(f"No process found on port {target}.")
        sys.exit(1)

    for pid in pids:
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            print(f"Terminating PID {pid} ({name}) on port {target}...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
                print(f"  PID {pid} terminated gracefully.")
            except psutil.TimeoutExpired:
                print(f"  PID {pid} did not exit in 5s, force killing...")
                proc.kill()
                proc.wait(timeout=5)
                print(f"  PID {pid} killed.")
        except psutil.NoSuchProcess:
            print(f"  PID {pid} already gone.")
        except psutil.AccessDenied:
            print(f"  PID {pid} — access denied, try elevated.")
            sys.exit(1)


def cmd_find(args):
    """Find processes by name (case-insensitive partial match)."""
    pattern = args.name.lower()
    rows = []
    for proc in psutil.process_iter(["pid", "name", "cmdline", "memory_info"]):
        try:
            info = proc.info
            pname = info["name"] or ""
            cmdline = " ".join(info["cmdline"] or [])
            if pattern not in pname.lower() and pattern not in cmdline.lower():
                continue
            mem_mb = (info["memory_info"].rss / 1024 / 1024) if info["memory_info"] else 0
            rows.append((info["pid"], f"{mem_mb:.1f}MB", pname, cmdline or "-"))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    rows.sort(key=lambda r: r[0])
    if not rows:
        print(f"No processes matching '{args.name}'.")
        sys.exit(1)

    print(f"{'PID':<8} {'MEMORY':<10} {'PROCESS':<25} {'COMMAND'}")
    print("-" * 80)
    for pid, mem, name, cmd in rows:
        cmd_display = cmd if len(cmd) <= 60 else cmd[:57] + "..."
        print(f"{pid:<8} {mem:<10} {name:<25} {cmd_display}")


def main():
    parser = argparse.ArgumentParser(
        prog="portscout",
        description="Cross-platform port/process CLI tool",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("listen", help="List all listening ports")

    p_port = sub.add_parser("port", help="Detail on a specific port")
    p_port.add_argument("port", type=int, help="Port number")

    p_kill = sub.add_parser("kill", help="Kill process on a port")
    p_kill.add_argument("port", type=int, help="Port number")

    p_find = sub.add_parser("find", help="Find processes by name")
    p_find.add_argument("name", help="Process name (partial, case-insensitive)")

    args = parser.parse_args()

    if args.command is None:
        args.command = "listen"

    commands = {
        "listen": cmd_listen,
        "port": cmd_port,
        "kill": cmd_kill,
        "find": cmd_find,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
