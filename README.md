# Shredcast

Shredcast is a utility to forward Turbine (TVU) packets from a Solana Node to arbitrary UDP listeners. It aims to be minimaly invasive.

## Proposed Architecture

```mermaid
sequenceDiagram
    actor RL as Remote Listener
    participant NIC

    box rgba(255, 0, 0, 0.2) User Space
    participant V as Validator
    participant TF as turbine-forwarder
    end
    box rgba(0, 0, 255, 0.2) Kernel Space
    participant XP as XDP Probe
    participant TC as Traffic Control Probe
    participant KN as Kernel Netstack
    end

    NIC -) XP: Incoming Packet
    Note over TF,XP: Packet is a shred if:<br>1. is a UDP Packet<br>2. Matches Turbine Port<br>3. Payload Length <= 1232
    alt If packet is a shred
        rect rgba(0, 255, 0, 0.2)
        XP -) TF: Copied Packet
        Note over XP,TF: Shared Memory(UMEM) Ring Buffer
        end
        XP ->> KN: Packet
        Note over XP,KN: XDP_PASS
        KN ->> V: Packet
    else Normal Packet Flow
        XP ->> KN: Packet
        Note over XP,KN: XDP_PASS
    end

    V -) KN: Egress Packet
    KN ->> TC: Egress Packet
    alt If packet is a shred
        rect rgba(0, 255, 0, 0.2)
        TC -) TF: Copied Packet
        Note Over TC,TF: Shared Memory (UMEM) Ring Buffer
        end
    end
    TC -->> KN: Egress Packet
    KN ->> NIC: Egress Packet

    loop For each listener
        rect rgba(0, 255, 0, 0.2)
        TF -) NIC: Modified Packet
        Note over TF, NIC: turbine-forwarder modifies Ethernet, IPv4, UDP header<br> Sent via AF_XDP
        end
        NIC -) RL: Modified Packet
    end
```


## Compilation

[bpf-linker](https://github.com/aya-rs/bpf-linker) is required to compile the BPF probe which monitors TVU traffic.

```bash
cargo build --release -p turbine-forwarder
```

## Running

Elevated privileges are required to run `turbine-forwarder`

To view the help menu:
```bash
sudo ./target/release/turbine-forwarder --help
```


Example:

```
sudo ./target/release/turbine-forwarder --tvu-ports 9000 --iface eth0 --listeners 127.0.0.1:5000
```

This will monitor incoming turbine packets on UDP port 9000 and interface `eth0`, and forward this traffic to a UDP socket running on `127.0.0.1:5000`

Multiple listeners are supported
```
--listeners 127.0.0.1:5000 --listeners 127.0.0.1:5001
```

Listener can also be a remote address.

Multiple TVU ports are also supported


### Egress

Watching TVU broadcast is currently work in progress. It can be enabled with the `--watch-egress` flag