# Shredcaster

Shredcaster is a lightweight utility that lets any Solana full node (validator, RPC, or Mithril verifying node) forward Turbine (TVU) packets to arbitrary UDP listeners.
Key benefits of using shredcaster include:
1. Standalone tool which requires minimal or zero modification of the codebase
   * Modification is needed if the broadcast has XDP turned on. This is for forwarding shreds produced by a leader
2. Doesn't require validator restart or reconfiguration
3. Uses XDP to have zero impact on validator performance
4. Can forward shreds to multiple recipients

## Proposed Architecture

```mermaid
sequenceDiagram
    actor RL as Remote Listener
    participant NIC

    box rgba(255, 0, 0, 0.2) User Space
    participant V as Validator
    participant SC as shredcaster
    end
    box rgba(0, 0, 255, 0.2) Kernel Space
    participant XP as XDP Probe
    participant TC as Traffic Control Probe
    participant KN as Kernel Netstack
    end

    NIC -) XP: Incoming Packet
    Note over SC,XP: Packet is a shred if:<br>1. is a UDP Packet<br>2. Matches Turbine Port<br>3. Payload Length <= 1232
    alt If packet is a shred
        rect rgba(0, 255, 0, 0.2)
        XP -) SC: Copied Packet
        Note over XP,SC: Shared Memory(UMEM) Ring Buffer
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
        TC -) SC: Copied Packet
        Note Over TC,SC: Shared Memory (UMEM) Ring Buffer
        end
    end
    TC -->> KN: Egress Packet
    KN ->> NIC: Egress Packet

    loop For each listener
        rect rgba(0, 255, 0, 0.2)
        SC -) NIC: Modified Packet
        Note over SC, NIC: shredcaster modifies Ethernet, IPv4, UDP header<br> Sent via AF_XDP
        end
        NIC -) RL: Modified Packet
    end
```


## Compilation

[bpf-linker](https://github.com/aya-rs/bpf-linker) is required to compile the BPF probe which monitors TVU traffic.

```bash
cargo build --release -p shredcaster
```

## Running

Elevated privileges are required to run `shredcaster`

To view the help menu:
```bash
sudo ./target/release/shredcaster --help
```


Example:

```
sudo ./target/release/shredcaster --tvu-ports 9000 --iface eth0 --listeners 127.0.0.1:5000
```

This will monitor incoming turbine packets on UDP port 9000 and interface `eth0`, and forward this traffic to a UDP socket running on `127.0.0.1:5000`

Multiple listeners are supported
```
--listeners 127.0.0.1:5000 --listeners 127.0.0.1:5001
```

Listener can also be a remote address.

Multiple TVU ports are also supported


## Monitoring

Watching TVU broadcast is currently work in progress. It can be enabled with the `--watch-egress` flag
