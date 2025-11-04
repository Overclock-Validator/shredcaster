# Shredcaster

Shredcaster is a lightweight standalone utility that allows any Solana full node, including a validator, RPC node, or Mithril verifying node, to forward Turbine (TVU) shred packets to external UDP listeners.

Key benefits:

1) Standalone design – Requires little or no modification to the Solana client codebase.
Note: If XDP-based broadcast is enabled, a small change is required to forward leader-produced shreds.

2) No validator disruption – Works without restarting or reconfiguring the node.

3) Minimal performance overhead – Uses eXpress Data Path (XDP) for efficient zero-copy packet forwarding.

4) Multi-recipient forwarding – Supports sending shreds to multiple UDP listeners simultaneously.

## Architecture

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


## Running Shredcaster

### Building

[bpf-linker](https://github.com/aya-rs/bpf-linker) is required to compile the BPF probe which monitors TVU traffic.

```bash
cargo build --release -p shredcaster
```

### Running

Elevated privileges are required to run `shredcaster`

To view the help menu:
```bash
sudo ./target/release/shredcaster --help
```


Example:

```
sudo ./target/release/shredcaster --tvu-ports 9000 --iface eth0 --listeners 127.0.0.1:5000
```

This monitors incoming Turbine shreds on UDP port 9000 and interface `eth0`, forwarding this traffic to a UDP socket running on `127.0.0.1:5000`

Multiple listeners are supported
```
--listeners 127.0.0.1:5000 --listeners 127.0.0.1:5001
```

Listeners can also be remote addresses, with multiple TVU ports supported.


### Monitoring

Watching TVU broadcast is currently a work in progress. It can be enabled with the `--watch-egress` flag
