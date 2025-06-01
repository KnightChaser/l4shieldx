# l4shieldx

> A lean, mean **in-kernel eBPF/XDP TCP Firewall** for simple DoS prevention.  Logs per-second packet counts, auto-blocks offenders, and ships a TUI for real-time control.

## Introduction
This project demonstrates how to harness Linux’s eBPF/XDP stack to drop bad actors at line rate. It isn’t production-grade, but it works(!), it's (technically) fast, and it simply shows how modern firewalls (Cloudflare, Facebook) run in the kernel.

![image](https://github.com/user-attachments/assets/8d2bb5d8-4f16-4cb4-a0d6-57915b54b107)


## Technology Stack
- **Kernel side**: C / libbpf + eBPF CO-RE, XDP hook  
- **User space**: Go / Cilium ebpf + tview/tcell for Terminal UI  
- **Maps & ringbuf**: per-IP counters, IP blocklist, protected-ports, threshold & events ring buffer  

## Architecture
1. **XDP eBPF program**  
   - Attach at the NIC driver level  
   - If `dst_port ∉ protected`, return `XDP_PASS`  
   - Else increment per-IP counter; if > threshold, add to blocklist + `XDP_DROP`, else emit event + `XDP_PASS`  
2. **Go controller & TUI**  
   - Loads & attaches the BPF object  
   - Reads the ring buffer for packet events  
   - Flushes & resets counters every second  
   - Offers commands to block/unblock IPs or protect/unprotect PIDs

## Quick Start
```sh
# 1. Build & install
make
sudo ./l4shieldx -i eth0

# 2. In the TUI:
protect 1234        # protect PID 1234’s listening ports
unprotect 1234      # remove that protection
deny 203.0.113.5    # manual block
allow 203.0.113.5   # manual unblock
setThreshold 50     # change pkts/sec limit
showProtected       # list current protections
exit                # quit and detach XDP (or hit Ctrl+C)
```

## Explanation by diagrams

1. **Project Architecture**: Kernel (XDP eBPF, maps, ring buffer) vs. User Space (Go controller, Cilium ebpf, TUI)
```mermaid
flowchart LR
  subgraph Kernel_Space
    XDP_Prog[XDP eBPF Program]
    Maps[Maps: counters, blocklist, protected_ports, threshold]
    Ringbuf[Ring Buffer → User Space]
    XDP_Prog --> Maps
    XDP_Prog --> Ringbuf
  end

  subgraph User_Space
    Go_Controller[Go Controller & TUI]
    Cilium_Lib[Cilium ebpf + libbpf]
    TUI[TUI: tview/tcell]
  end

  NIC[Network Interface] -->|packets| XDP_Prog
  Go_Controller -- loads/attaches --> XDP_Prog
  Go_Controller -- updates maps --> Maps
  Ringbuf --> Go_Controller
  Go_Controller --> TUI
```

2. **XDP Packet Path**: How XDP hooks incoming packets, verifies IPv4/TCP, and proceeds
```mermaid
flowchart TD
  NIC[Incoming Packet at NIC] --> XDP_Hook[XDP Hook]
  XDP_Hook -->|attach eBPF prog| eBPF[Run eBPF Program]
  eBPF --> Check_Version{Is IPv4?}
  Check_Version -- No --> PASS1[XDP_PASS]
  Check_Version -- Yes --> Parse_TCP{Is TCP?}
  Parse_TCP -- No --> PASS2[XDP_PASS]
  Parse_TCP -- Yes --> Continue[Proceed to maps logic]
```

3. **Firewall Logic Flowchart**: Step-by-step packet filtering (protected ports, blocklist, rate‐limit)
```mermaid
flowchart TD
  subgraph XDP_Prog
    A[Receive Packet]
    B{Is dst_port ∈ protected_ports?}
    C{IP ∈ blocklist?}
    D[Drop Packet 'XDP_DROP']
    E[Lookup/Increment ip_count_map]
    F{Count > threshold?}
    G[Add IP to blocklist]
    H[Emit event via ringbuf]
    I[XDP_PASS → Let kernel handle]
  end

  A --> B
  B -- No --> I
  B -- Yes --> C
  C -- Yes --> D
  C -- No --> E
  E --> F
  F -- Yes --> G
  G --> D
  F -- No --> H
  H --> I
```

4. **Sequence Diagram**: Detailed interaction from NIC to XDP to maps to user-space ring buffer and UI updates
```mermaid
sequenceDiagram
  participant NIC as Network Interface
  participant XDP as XDP eBPF
  participant Maps as BPF Maps
  participant RB as Ring Buffer
  participant Go as Go Controller

  NIC->>XDP: Packet Arrival
  XDP->>Maps: Check blocked_ips
  alt blocked
    Maps-->>XDP: IP found
    XDP-->>NIC: XDP_DROP
  else not blocked
    XDP->>Maps: Check protected_ports (dst_port)
    alt not protected
      XDP-->>NIC: XDP_PASS
    else protected
      XDP->>Maps: Increment ip_count_map[src_IP]
      XDP->>Maps: Check threshold
      alt exceeds
        XDP->>Maps: Update blocked_ips
        XDP-->>NIC: XDP_DROP
      else within limit
        XDP->>RB: Emit event (src_IP, dst_port, timestamp)
        XDP-->>NIC: XDP_PASS
      end
    end
  end
  RB-->>Go: Deliver event
  Go-->>Maps: (every 1s) Reset ip_count_map entries
  Go-->>Maps: (commands) block/unblock or protect/unprotect
  Go-->>TUI: Update display
```

5. **Runbook Flow**: How a user protecting a process leads to map updates and TUI confirmation
```mermaid
flowchart TD
  subgraph Runbook: Protect a Service
    Start[User runs firewall to a specific NIC] --> Load_BPF[Go loads & attaches XDP eBPF prog]
    Load_BPF --> TUI_Launch[TUI appears]
    TUI_Launch --> User_Commands{User issues command}
    User_Commands -- "protect <PID>" --> Find_Ports[Go finds listening ports for PID]
    Find_Ports --> Update_Map[Go updates protected_ports map]
    Update_Map --> Confirm[Show confirmation in TUI]
    Confirm --> Continue[Return to monitoring]
  end
```
