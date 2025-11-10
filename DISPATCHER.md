# Dispatcher Test

## 1. Build shredcaster and dummy-xdp-loader

```bash
cargo build --release dummy-xdp-loader && cargo build --release shredcaster
```

## 2. Start shredcaster (See README.md)

## 3. Start dummy-xdp-loder

You can also load dummy-xdp-loader before shredcaster

```bash
./target/release/dummy-xdp-loader --iface <same as shredcaster>
```

## 4. Spam UDP packets from an external machine

or you can also use the `lo` interface and spam the packets over `127.0.0.1:<tvu_port>`

```bash
cargo run --release -p udp-spammer -- --target <ip of machine running shredcaster>:<tvu_port>
```
