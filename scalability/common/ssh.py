import subprocess

from termcolor import colored


def scp_file(source, destination):
    p = subprocess.Popen(
        ["scp", "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=No", "-q", source, destination]
    )
    return p


def get_ssh_args(machine, command, extra_args=[]):
    args = [
        "ssh",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "StrictHostKeyChecking=No",
    ]
    return (
        args
        + extra_args
        + [
            "admin@{}".format(machine),
            command,
        ]
    )


def run_ssh(machine: str, command: str, f_stdout=None, f_stderr=None) -> subprocess.Popen:
    """Run the given command on the given machine."""
    print("{}: Running {}".format(colored(machine, "blue"), command))
    args = get_ssh_args(machine, command)

    if f_stdout is not None and f_stderr is not None:
        p = subprocess.Popen(args, stdout=open(f_stdout, "w"), stderr=open(f_stderr, "w"))
    else:
        p = subprocess.Popen(args)
    return p


def run_ssh_with_t(machine, command, f_stdout, f_stderr):
    """
    Run the given command on the given machine.

    Force pseudo-terminal allocation.
    """
    print("{}: Running in terminal mode {}".format(colored(machine, "blue"), command))
    return subprocess.Popen(
        get_ssh_args(machine, command, ["-tt"]),
        universal_newlines=True,
        stdin=subprocess.DEVNULL,
    )


def scp_in_parallel(sources, destinations):
    assert len(sources) == len(destinations)

    ps = []
    for (source, destination) in zip(sources, destinations):
        print("Starting scp {} to {}".format(source, destination))
        ps.append((source, destination, scp_file(source, destination)))

    rc = []
    for (source, destination, p) in ps:
        print("scp {} to {} done".format(source, destination))
        rc.append(p.wait())

    return rc


def spawn_ssh_in_parallel(machines, command, f_stdout=None, f_stderr=None):
    """Run the given command in parallel on all given machines and return Popen objects for further processing."""
    ps = []
    for machine in machines:
        ps.append(
            (
                machine,
                run_ssh(
                    machine,
                    command,
                    f_stdout.format(machine) if f_stdout is not None else None,
                    f_stderr.format(machine) if f_stderr is not None else None,
                ),
            )
        )
    return ps


def run_ssh_in_parallel(machines, command, f_stdout=None, f_stderr=None):
    ps = spawn_ssh_in_parallel(machines, command, f_stdout, f_stderr)
    rc = []
    for (machine, p) in ps:
        rc.append(p.wait())
        print("Done running {} on {}".format(command, machine))

    return rc


def run_all_ssh_in_parallel(
    machines: [str], commands: [str], f_stdout: str = None, f_stderr: str = None, timeout: int = None
) -> [int]:
    """Run the given command in parallel on all given machines and wait for completion."""
    ps = []  # Array of type: [(str, str, subprocess.Popen)]
    for command, machine in zip(commands, machines):
        this_f_stdout = f_stdout.format(machine) if f_stdout is not None else None
        this_f_stderr = f_stderr.format(machine) if f_stderr is not None else None
        ps.append(
            (
                machine,
                command,
                run_ssh(
                    machine,
                    command,
                    this_f_stdout,
                    this_f_stderr,
                ),
                this_f_stdout,
                this_f_stderr,
            )
        )

    rcs = []
    for (machine, command, p, this_f_stdout, this_f_stderr) in ps:
        try:
            # Note: timeout == None means no timeout (it's the default)
            # Note 2: wait() is actually synchronous, see info here:
            # https://docs.python.org/3/library/subprocess.html#subprocess.Popen.wait
            rc = p.wait(timeout)
            rcs.append(rc)
            status = colored("OK", "green") if rc == 0 else colored(f"rc={rc}", "red")
            print("{}: {} Done running {} on {}".format(colored(machine, "blue"), status, command, machine))
            if rc != 0 and (this_f_stderr is not None or this_f_stdout is not None):
                print(f"SSH failed, output is: err={this_f_stderr} out={this_f_stdout}")
        except subprocess.TimeoutExpired:
            print(
                "{}: {} Timeout running {} on {}".format(
                    colored(machine, "blue"), colored("fail", "red"), command, machine
                )
            )
            # The timeout does not actually mean that the process itself is terminated,
            # we just stop waiting. In order to terminate the subprocess, we explictly
            # need to do so and wait again.
            print("{}: Terminating {} ".format(colored(machine, "blue"), command))
            p.terminate()
            print("{}: Waiting for termination {} ".format(colored(machine, "blue"), command))
            p.wait()

    return rcs
