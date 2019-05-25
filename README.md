# rustbuster

DirBuster for Rust

[![asciicast](https://asciinema.org/a/ymyCFj4NBRukQIEcjjzK9JYEU.svg)](https://asciinema.org/a/ymyCFj4NBRukQIEcjjzK9JYEU)

## Usage

There are three modules currently implemented:

1. Dirbuster (default)  
`rustbuster -m dir -u http://localhost:3000/ -w examples/wordlist -e php`

1. Dnsbuster  
`rustbuster -m dns -u google.com -w examples/wordlist`

1. Vhostbuster  
`rustbuster -m vhost -u http://localhost:3000/ -w examples/wordlist -d test.local -x "Hello"`

```shell

         _     _                 _         _           _        _                 _         _           _           _     
        /\ \  /\_\              / /\      /\ \        / /\     /\_\              / /\      /\ \        /\ \        /\ \   
       /  \ \/ / /         _   / /  \     \_\ \      / /  \   / / /         _   / /  \     \_\ \      /  \ \      /  \ \  
      / /\ \ \ \ \__      /\_\/ / /\ \__  /\__ \    / / /\ \  \ \ \__      /\_\/ / /\ \__  /\__ \    / /\ \ \    / /\ \ \ 
     / / /\ \_\ \___\    / / / / /\ \___\/ /_ \ \  / / /\ \ \  \ \___\    / / / / /\ \___\/ /_ \ \  / / /\ \_\  / / /\ \_\
    / / /_/ / /\__  /   / / /\ \ \ \/___/ / /\ \ \/ / /\ \_\ \  \__  /   / / /\ \ \ \/___/ / /\ \ \/ /_/_ \/_/ / / /_/ / /
   / / /__\/ / / / /   / / /  \ \ \    / / /  \/_/ / /\ \ \___\ / / /   / / /  \ \ \    / / /  \/_/ /____/\   / / /__\/ / 
  / / /_____/ / / /   / / _    \ \ \  / / /     / / /  \ \ \__// / /   / / _    \ \ \  / / /     / /\____\/  / / /_____/  
 / / /\ \ \  / / /___/ / /_/\__/ / / / / /     / / /____\_\ \ / / /___/ / /_/\__/ / / / / /     / / /______ / / /\ \ \    
/ / /  \ \ \/ / /____\/ /\ \/___/ / /_/ /     / / /__________/ / /____\/ /\ \/___/ / /_/ /     / / /_______/ / /  \ \ \   
\/_/    \_\/\/_________/  \_____\/  \_\/      \/_____________\/_________/  \_____\/  \_\/      \/__________\/_/    \_\/   

~ rustbuster v. 1.2.0 ~ by phra & ps1dr3x ~

USAGE:
    rustbuster [FLAGS] [OPTIONS] --url <url> --wordlist <wordlist>

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
    -d, --domain <domain>                                Uses the specified domain
    -e, --extensions <extensions>                        Sets the extensions [default: ]
    -b, --http-body <http-body>                          Uses the specified HTTP method [default: ]
    -H, --http-header <http-header>...                   Appends the specified HTTP header
    -X, --http-method <http-method>                      Uses the specified HTTP method [default: GET]
    -S, --ignore-status-codes <ignore-status-codes>      Sets the list of status codes to ignore [default: 404]
    -x, --ignore-string <ignore-string>...               Ignores results with specified string in vhost mode
    -s, --include-status-codes <include-status-codes>    Sets the list of status codes to include [default: ]
    -m, --mode <mode>                                    Sets the mode of operation (dir, dns, fuzz) [default: dir]
    -o, --output <output>                                Saves the results in the specified file [default: ]
    -t, --threads <threads>                              Sets the amount of concurrent requests [default: 10]
    -u, --url <url>                                      Sets the target URL
    -a, --user-agent <user-agent>                        Uses the specified User-Agent [default: rustbuster]
    -w, --wordlist <wordlist>                            Sets the wordlist

```
