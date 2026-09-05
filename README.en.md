# mac-smb-repair

**[中文主文档 / Main Chinese README](./README.md)**

A conservative macOS utility for detecting and locally recovering from one specific kind of stuck SMB connection: `NetAuthSysAgent` retains an unfinished SMB mount request and Finder remains on “Connecting”.

The main documentation is maintained in Chinese. It covers the intended use cases, commands, one-click repair script, background, privacy model, compatibility, and limitations:

→ **[Read the main Chinese documentation](./README.md)**

## Quick start

1. Open [Releases](../../releases/latest).
2. Download `NetAuthSMBRepair.zip`.
3. Extract it and double-click `NetAuthSMBRepair.command` in Finder.

The ZIP release preserves the script’s executable permission. If macOS blocks the first launch, Control-click the script in Finder and choose **Open**.

## What it does

The script samples the current user’s `NetAuthSysAgent` twice. It sends a normal `TERM` signal only when both samples show the targeted persistent-blocking signature:

- the main thread is continuously waiting for an internal lock; and
- an SMB mount path is continuously waiting for an account-SID RPC query.

If the signature is absent, the process changes during checking, or the result cannot be interpreted reliably, the script reports that outcome and makes no change. It does not restart Finder or access a server.

## Privacy and compatibility

The project contains no server address, device name, username, password, or mount path. The script does not use the network, read the keychain, or retain sampling output.

It is for macOS systems that provide the built-in `/usr/bin/sample` utility and uses only system tools: `zsh`, `awk`, `ps`, `pgrep`, `mktemp`, and `kill`.

The tool is not a general SMB troubleshooter. Server availability, SMB service settings, credentials, permissions, and name resolution must be investigated separately.
