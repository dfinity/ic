#!/usr/bin/env python3
import subprocess
import sys
import time

host = sys.argv[1]
num_boots = sys.argv[2]

command_line = [
    "ssh",
    "-o",
    "ConnectTimeout=1",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "ServerAliveCountMax=3",
    "-o",
    "ServerAliveInterval=1",
    "-o",
    "PasswordAuthentication=false",
    "-tt",
    host,
    "journalctl",
    "--no-tail",
    "-u",
    '"*"',
    "-f",
]

for i in range(int(num_boots)):
    print("--------------------------------------------------")
    time.sleep(5)
    received_logs = False
    while not received_logs:
        proc = subprocess.Popen(command_line, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
        line = b""
        while True:
            # This is somewhat silly -- when not specifying size limit
            # it will block indefinitely filling internal buffers (not helpful).
            # Despite the looks of it, read(1) will still not result in
            # single byte OS level reads (python will buffer internally).
            c = proc.stdout.read(1)
            if c:
                line += c
                if c == b"\n":
                    # Flushing each line makes it easier to follow in interactive
                    # debugging.
                    sys.stdout.buffer.write(line)
                    sys.stdout.flush()
                    line = b""
                received_logs = True
            else:
                break
