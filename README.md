# bm-eke

This repo is a demo implementation of the Bellovin-Merritt key exchange protocol,
which is one of the labs in Tsinghua University's "Cybersecurity Fundamentals" course.

## build

``` bash
# for server
cargo build --bin server --release
# for client
cargo build --bin client --release
```

## usage

```
Usage: server [OPTIONS] --pw <PW>

Options:
  -a, --addr <ADDR>  [default: 127.0.0.1]
  -p, --port <PORT>  [default: 7878]
      --pw <PW>
  -h, --help         Print help
  -V, --version      Print version
```

```
Usage: client [OPTIONS] --pw <PW>

Options:
  -a, --addr <ADDR>  [default: 127.0.0.1]
  -p, --port <PORT>  [default: 7878]
      --pw <PW>
  -h, --help         Print help
  -V, --version      Print version
```

`--pw` is the pre-shared password. Server and client must use the same password.

Run the server first, then run the client.
