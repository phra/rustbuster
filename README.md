# rustbuster [![CircleCI](https://circleci.com/gh/phra/rustbuster.svg?style=svg)](https://circleci.com/gh/phra/rustbuster)

DirBuster for Rust

[![asciicast](https://asciinema.org/a/ymyCFj4NBRukQIEcjjzK9JYEU.svg)](https://asciinema.org/a/ymyCFj4NBRukQIEcjjzK9JYEU)

## Download

You can download prebuilt binaries from [here](https://github.com/phra/rustbuster/releases).

## Usage

```text
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
    tilde    IIS 8.3 shortname enumeration mode

EXAMPLES:
    1. Dir mode:
        rustbuster dir -u http://localhost:3000/ -w examples/wordlist -e php
    2. Dns mode:
        rustbuster dns -d google.com -w examples/wordlist
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
    5. Tilde mode:
        rustbuster tilde -u http://localhost:3000/ -e aspx -X OPTIONS
```

### `dir` usage

```text
rustbuster-dir
Directories and files enumeration mode

USAGE:
    rustbuster dir [FLAGS] [OPTIONS] --url <url> --wordlist <wordlist>...

FLAGS:
    -f, --append-slash          Tries to also append / to the base request
    -K, --exit-on-error         Exits on connection errors
    -h, --help                  Prints help information
    -k, --ignore-certificate    Disables TLS certificate validation
        --no-banner             Skips initial banner
        --no-progress-bar       Disables the progress bar
    -V, --version               Prints version information
    -v, --verbose               Sets the level of verbosity

OPTIONS:
    -e, --extensions <extensions>                        Sets the extensions [default: ]
    -b, --http-body <http-body>                          Uses the specified HTTP method [default: ]
    -H, --http-header <http-header>...                   Appends the specified HTTP header
    -X, --http-method <http-method>                      Uses the specified HTTP method [default: GET]
    -S, --ignore-status-codes <ignore-status-codes>      Sets the list of status codes to ignore [default: 404]
    -s, --include-status-codes <include-status-codes>    Sets the list of status codes to include [default: ]
    -o, --output <output>                                Saves the results in the specified file [default: ]
    -t, --threads <threads>                              Sets the amount of concurrent requests [default: 10]
    -u, --url <url>                                      Sets the target URL
    -a, --user-agent <user-agent>                        Uses the specified User-Agent [default: rustbuster]
    -w, --wordlist <wordlist>...                         Sets the wordlist

EXAMPLE:
    rustbuster dir -u http://localhost:3000/ -w examples/wordlist -e php
```

### `dns` usage

```text
rustbuster-dns
A/AAAA entries enumeration mode

USAGE:
    rustbuster dns [FLAGS] [OPTIONS] --domain <domain> --wordlist <wordlist>...

FLAGS:
    -K, --exit-on-error      Exits on connection errors
    -h, --help               Prints help information
        --no-banner          Skips initial banner
        --no-progress-bar    Disables the progress bar
    -V, --version            Prints version information
    -v, --verbose            Sets the level of verbosity

OPTIONS:
    -d, --domain <domain>           Uses the specified domain
    -o, --output <output>           Saves the results in the specified file [default: ]
    -t, --threads <threads>         Sets the amount of concurrent requests [default: 10]
    -w, --wordlist <wordlist>...    Sets the wordlist

EXAMPLE:
    rustbuster dns -d google.com -w examples/wordlist
```

### `vhost` usage

```text
rustbuster-vhost 
Virtual hosts enumeration mode

USAGE:
    rustbuster vhost [FLAGS] [OPTIONS] --domain <domain> --ignore-string <ignore-string>... --url <url> --wordlist <wordlist>...

FLAGS:
    -K, --exit-on-error         Exits on connection errors
    -h, --help                  Prints help information
    -k, --ignore-certificate    Disables TLS certificate validation
        --no-banner             Skips initial banner
        --no-progress-bar       Disables the progress bar
    -V, --version               Prints version information
    -v, --verbose               Sets the level of verbosity

OPTIONS:
    -d, --domain <domain>                                Uses the specified domain to bruteforce
    -b, --http-body <http-body>                          Uses the specified HTTP body [default: ]
    -H, --http-header <http-header>...                   Appends the specified HTTP header
    -X, --http-method <http-method>                      Uses the specified HTTP method [default: GET]
    -S, --ignore-status-codes <ignore-status-codes>      Sets the list of status codes to ignore [default: 404]
    -x, --ignore-string <ignore-string>...               Ignores results with specified string in the HTTP body
    -s, --include-status-codes <include-status-codes>    Sets the list of status codes to include [default: ]
    -o, --output <output>                                Saves the results in the specified file [default: ]
    -t, --threads <threads>                              Sets the amount of concurrent requests [default: 10]
    -u, --url <url>                                      Sets the target URL
    -a, --user-agent <user-agent>                        Uses the specified User-Agent [default: rustbuster]
    -w, --wordlist <wordlist>...                         Sets the wordlist

EXAMPLE:
    rustbuster vhost -u http://localhost:3000/ -w examples/wordlist -d test.local -x "Hello"
```

### `fuzz` usage

```text
rustbuster-fuzz
Custom fuzzing enumeration mode

USAGE:
    rustbuster fuzz [FLAGS] [OPTIONS] --url <url> --wordlist <wordlist>...

FLAGS:
    -K, --exit-on-error         Exits on connection errors
    -h, --help                  Prints help information
    -k, --ignore-certificate    Disables TLS certificate validation
        --no-banner             Skips initial banner
        --no-progress-bar       Disables the progress bar
    -V, --version               Prints version information
    -v, --verbose               Sets the level of verbosity

OPTIONS:
        --csrf-header <csrf-header>...                   Adds the specified headers to CSRF GET request
        --csrf-regex <csrf-regex>                        Grabs the CSRF token applying the specified RegEx
        --csrf-url <csrf-url>                            Grabs the CSRF token via GET to csrf-url
    -b, --http-body <http-body>                          Uses the specified HTTP method [default: ]
    -H, --http-header <http-header>...                   Appends the specified HTTP header
    -X, --http-method <http-method>                      Uses the specified HTTP method [default: GET]
    -S, --ignore-status-codes <ignore-status-codes>      Sets the list of status codes to ignore [default: 404]
    -x, --ignore-string <ignore-string>...               Ignores results with specified string in the HTTP Body
    -s, --include-status-codes <include-status-codes>    Sets the list of status codes to include [default: ]
    -i, --include-string <include-string>...             Includes results with specified string in the HTTP body
    -o, --output <output>                                Saves the results in the specified file [default: ]
    -t, --threads <threads>                              Sets the amount of concurrent requests [default: 10]
    -u, --url <url>                                      Sets the target URL
    -a, --user-agent <user-agent>                        Uses the specified User-Agent [default: rustbuster]
    -w, --wordlist <wordlist>...                         Sets the wordlist

EXAMPLE:
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

### `tilde` usage

```text
rustbuster-tilde
IIS 8.3 shortname enumeration mode

USAGE:
    rustbuster tilde [FLAGS] [OPTIONS] --url <url>

FLAGS:
    -K, --exit-on-error         Exits on connection errors
    -h, --help                  Prints help information
    -k, --ignore-certificate    Disables TLS certificate validation
        --no-banner             Skips initial banner
        --no-progress-bar       Disables the progress bar
    -V, --version               Prints version information
    -v, --verbose               Sets the level of verbosity

OPTIONS:
    -e, --extension <extension>                          Sets the redirect extension
    -b, --http-body <http-body>                          Uses the specified HTTP body [default: ]
    -H, --http-header <http-header>...                   Appends the specified HTTP header
    -X, --http-method <http-method>                      Uses the specified HTTP method [default: GET]
    -S, --ignore-status-codes <ignore-status-codes>      Sets the list of status codes to ignore [default: 404]
    -s, --include-status-codes <include-status-codes>    Sets the list of status codes to include [default: ]
    -o, --output <output>                                Saves the results in the specified file [default: ]
    -t, --threads <threads>                              Sets the amount of concurrent requests [default: 10]
    -u, --url <url>                                      Sets the target URL
    -a, --user-agent <user-agent>                        Uses the specified User-Agent [default: rustbuster]

EXAMPLE:
    rustbuster tilde -u http://localhost:3000/ -e aspx -X OPTIONS
```
