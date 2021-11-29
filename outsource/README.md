# Outsource

This is "outsource", a script for running commands on our remote builders.

See also:

* [DESIGN.md](./DESIGN.md): The document explaining the design of _outsource_.
* [remote](./remote.py): The command run locally by developers to outsource
  commands to the remote builders.
* [server](./server): The command run on the remote builders to actually
  execute the commands.

## Installation

Make sure
[direnv](https://gitlab.com/dfinity-lab/core/ic/blob/master/CONTRIBUTING.adoc#auto-loading-the-nix-shell)
is installed and add the following to your `rs/.envrc`:

``` bash
# Add the `remote` executable to the PATH
PATH_add ../outsource/bin
```

Make sure `ssh-agent` is enabled, and that your key is loaded:

```shell
$ ssh-add -L
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICkrw58g9XyA6R+MqrVVzkdATxeJ4kwTf1aTTAiEm+kH you@your.email # this is the key you have on GitLab 
```

If you don't have `ssh-agent` enabled, the remote machine will not be
able to use your forwarded key to access GitLab. Follow the
[`ssh-agent` instructions to](nm-outsource-keycheck) set it up for
your system.

For NixOS, enable `programs.ssh.startAgent` (and then log out and log back in):

``` nix
{
  programs.ssh.startAgent = true;
}
```

## Usage

Use `remote <cmd>` where `<cmd>` is the command you would like to run on the
remote builder. The `remote` command automatically syncs your code and changes
the working directory on the remote builder:

``` shell
~/dfinity$ remote echo hello
[outsource]: remote: executing command
hello
~/dfinity$ cd rs/phantom_newtype && remote cargo check
...
    Checking num_enum v0.5.1
    Checking phantom_newtype v0.1.0 (/home/ubuntu/build/rs/phantom_newtype)
    Finished dev [unoptimized + debuginfo] target(s) in 15.90s
~/dfinity/rs/phantom_newtype$
```

You can specify which host to connect to with `--host` and which user to log in
as with `--user`. You can also specify those values through environment variables in your `.envrc`, e.g.:

``` bash
# Set the user through direnv
export OUTSOURCE_USER=johndoe

# Add the `remote` executable to the PATH
PATH_add ../outsource/bin
```


For a full list of options run `remote --help`.

## FAQ

When encountering an issue, first try running `remote` with `--verbose`.

<details><summary>What can I run on the remote builders?</summary>
<p>

You can run anything that you can run inside the nix-shell/sorri environment.
This includes cargo builds, asciidoctor, etc. When running a command, the
network is sandboxed in a way that you can access the internet, but the command
won't interfer with any other command running on the remote builder; i.e. two
commands can bind on the same port.

The `nix` executable is not installed, meaning deployment to testnets with nix
is not possible at the moment.

</p>
</details>

<details><summary>johndoe@zh1-spm24.zh1.dfinity.network: Permission denied (publickey).</summary>
<p>

**Make sure you have an account on the remote builders.** If you don't, please reach out to @doctor-idx on Slack.

Make sure your username on the remote builder is the same as `$USER`, or use
`remote --user my_user ...` to specify the username on the remote builder.

</p>
</details>

<details><summary>stuck on "syncing files with johndoe@zh1-spm23.zh1.dfinity.network" or getting "connect to host zh1-spm23.zh1.dfinity.network port 22: Operation timed out"</summary>
<p>

**Make sure you are connected to the VPN and that the host is reachable.**

If you are connected to the VPN but the host is unreachable, please reach out to @doctor-idx on Slack.

</p>
</details>

<details><summary>Where is the target directory?</summary>
<p>

**/cargo-target/target** but subject to change.


```shell
~/dfinity$ remote printenv CARGO_TARGET_DIR
/persisted/cargo-target
```

</p>
</details>
