# rustbuster

[WIP] DirBuster for Rust

## Usage

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

USAGE:
    rustbuster [FLAGS] [OPTIONS] --url <url> --wordlist <wordlist>

FLAGS:
    -K, --exit-on-error         Exits on connection errors
    -h, --help                  Prints help information
    -k, --ignore-certificate    Disables TLS certificate validation
        --no-banner             Skips initial banner
    -V, --version               Prints version information
    -v, --verbose               Sets the level of verbosity

OPTIONS:
    -e, --extensions <extensions>                        Sets the extensions [default: ]
    -S, --ignore-status-codes <ignore-status-codes>
            Sets the list of status codes (comma-separated) to ignore from the results (default: 404) [default: 404]

    -s, --include-status-codes <include-status-codes>
            Sets the list of status codes (comma-separated) to include in the results (default: all but the ignored
            ones) [default: ]
    -m, --mode <mode>                                    Sets the mode of operation (dir, dns, fuzz) [default: dir]
    -o, --output <output>                                Save the results in the specified file [default: ]
    -t, --threads <threads>                              Sets the amount of concurrent requests [default: 10]
    -u, --url <url>                                      Sets the target URL
    -w, --wordlist <wordlist>                            Sets the wordlist

```
