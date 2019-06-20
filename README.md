# rustbuster [![CircleCI](https://circleci.com/gh/phra/rustbuster.svg?style=svg)](https://circleci.com/gh/phra/rustbuster)

DirBuster for Rust

[![asciicast](https://asciinema.org/a/ymyCFj4NBRukQIEcjjzK9JYEU.svg)](https://asciinema.org/a/ymyCFj4NBRukQIEcjjzK9JYEU)

## Download

You can download prebuilt binaries from [here](https://github.com/phra/rustbuster/releases).

## Usage

```shell
rustbuster 2.1.0
DirBuster for rust

USAGE:
    rustbuster [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    dir      Directories and files enumeration mode
    dns      A/AAAA entries enumeration mode
    fuzz     Custom fuzzing enumeration mode
    help     Prints this message or the help of the given subcommand(s)
    vhost    Virtual hosts enumeration mode

EXAMPLES:
    1. Dir mode:
        rustbuster dir -u http://localhost:3000/ -w examples/wordlist -e php
    2. Dns mode:
        rustbuster dns -u google.com -w examples/wordlist
    3. Vhost mode:
        rustbuster vhost -u http://localhost:3000/ -w examples/wordlist -d test.local -x "Hello"
    4. Fuzz mode:
        rustbuster fuzz -u http://localhost:3000/login \
            -X POST \
            -H "Content-Type: application/json" \
            -b '{"user":"FUZZ","password":"FUZZ","csrf":"CSRFCSRF"}' \
            -w examples/wordlist \
            -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt \
            -s 200 \
            --csrf-url "http://localhost:3000/csrf" \
            --csrf-regex '\{"csrf":"(\w+)"\}'

```

### `dir` usage

```shell
```

### `dns` usage

```shell
```

### `vhost` usage

```shell
```

#### `fuzz` usage

```shell
```
