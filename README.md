# eBPF Verifier Exploit Research — s344024 Romano Simone

Research project for the Security Verification and Testing (SVT) course —
analysis and exploit development for eBPF verifier vulnerabilities in the Linux kernel.

The primary focus is identifying unpatched or unexploited CVEs in `kernel/bpf/verifier.c`,
writing proofs of concept, and developing memory read/write primitives suitable for
Local Privilege Escalation (LPE).

---

## Project Structure

```
s344024_Romano_Simone/
│
├── test/                               ← Buildroot-based build & test environment
│   ├── build.sh                        ← Interactive build script (CVE + kernel selection)
│   ├── buildroot/                      ← Buildroot source tree
│   ├── configs/                        ← Shared/base buildroot configs
│   ├── patches/                        ← Per-kernel patch sets (linux-4.x ... 5.9.x)
│   ├── linux-6.8/kernel/bpf/           ← Reference verifier source for diff/analysis
│   └── CVEs/                           ← One folder per CVE under test
│       ├── CVE-2023-39191/
│       │   ├── configs/                ← Per-kernel buildroot + kernel configs
│       │   │   ├── v6.0/
│       │   │   └── v6.1/
│       │   ├── exploit_overlay/
│       │   └── src/
│       ├── CVE-2024-42072/
│       │   ├── configs/
│       │   ├── exploit_overlay/
│       │   └── src/
│       ├── CVE-2024-43838/
│       │   ├── configs/
│       │   ├── exploit_overlay/
│       │   └── src/
│       ├── CVE-2024-45020/
│       │   ├── configs/
│       │   ├── exploit_overlay/
│       │   └── src/
│       └── CVE-2024-58100/
│           ├── configs/
│           ├── exploit_overlay/
│           └── src/
│
├── exploits/                           ← Standalone exploit sources (outside Buildroot flow)
│   ├── CVE-2023-39191/src/             ← poc.c, exploit.c 
│   ├── CVE-2024-42072/src/
│   ├── CVE-2024-45020/src/
│   └── CVE-2024-58100/src/             
│
├── report/                             ← LaTeX report
│   ├── main.tex
│   ├── compile.sh
│   ├── src/                            ← Per-CVE chapter sources
│   │   ├── CVE-2023-39191.tex
│   │   ├── CVE-2024-42072.tex
│   │   ├── CVE-2024-45020.tex
│   │   └── CVE-2024-58100.tex
│   ├── img/
│   ├── out/                            ← Build artifacts (aux, log, ...)
│   └── SVT_report.pdf                  ← Compiled PDF
│
└── presentation/                       ← LaTeX slides
    ├── main.tex
    ├── compile.sh
    ├── img/
    ├── out/
    └── SVT_presentation.pdf            ← Compiled PDF
```

---

## CVEs

| CVE | Kernel Range | Bug Class | Memory Primitive | LPE Status |
|-----|-------------|-----------|-----------------|------------|
| CVE-2023-39191 | ≤ 6.1.19 / ≤ 6.2.6 | Dynptr type confusion (OOB via overlapping dynptrs on BPF stack) | Arbitrary OOB R/W via corrupted dynptr size | Full LPE (adaptive calibration + cred spray) |
| CVE-2024-42072 | < 6.10.2 | Verifier register state leak across subprog calls | OOB read primitive | Primitive confirmed, LPE in progress |
| CVE-2024-45020 | < 6.11 | Incorrect bounds check on stack-allocated dynptr | OOB R/W potential | PoC confirmed, exploitation analysis ongoing |
| CVE-2024-58100 | 5.6 – 6.6.89 / 6.7 – 6.12.24 | Verifier omits `changes_pkt_data` propagation through GLOBAL subprog → stale `PTR_TO_PACKET` after `bpf_skb_change_head` | UAF R/W on freed `kmalloc-1024` slab | UAF R/W confirmed, full LPE(modprobe_path tampered) |

---

## Testing Environment

The project uses a Buildroot-based QEMU environment. `test/build.sh` handles kernel
selection, config preparation, legacy option stripping, and build orchestration.

```bash
cd test/
./build.sh        # Interactively select CVE + kernel, then build
```

After the build completes, boot QEMU with:

```bash
cd buildroot/
output/images/start-qemu.sh  --serial-only -- -m 9216
```

> **Note:** `-m 9216` (9 GiB RAM) is **required** for CVE-2023-39191.
> The exploit's OOB target lands at ~8.2 GiB physical; less RAM makes it unreachable.

| VM Detail | Value |
|-----------|-------|
| Rootfs | Buildroot minimal image |
| Kernel | Per-CVE, selectable in build script |
| Virtualization | QEMU (no KVM required) |
| Login | `root` (no password) |
| BPF | Enabled, unprivileged BPF allowed |
| KASLR / RANDOMIZE_MEMORY | Disabled (for exploit reproducibility) |
| Binary delivery | Via Buildroot overlay → `/root/` in VM |

---

## Building & Running

### CVE-2023-39191 — Dynptr Type Confusion LPE

```bash
# Build Buildroot image for kernel 5.19 (vulnerable)
cd test/
./build.sh   # select CVE-2023-39191, kernel v5.19

# Boot VM with 9 GB RAM
cd buildroot/
output/images/start-qemu.sh  --serial-only -- -m 9216

# Inside VM:
/root/poc      # Verify OOB R/W primitive
/home/user/exploit  # Full LPE → creates /tmp/rootsh
/tmp/rootsh    # Spawn root shell
```

### CVE-2024-42072

```bash
cd test/
./build.sh   # select CVE-2024-42072

cd buildroot/
output/images/start-qemu.sh  --serial-only

# Inside VM:
/root/poc      # OOB read primitive demo
/root/exploit  # Exploitation attempt
```

### CVE-2024-45020

```bash
cd test/
./build.sh   # select CVE-2024-45020

cd buildroot/
output/images/start-qemu.sh  --serial-only

# Inside VM:
/root/poc      # Dynptr OOB trigger
/root/exploit  # Exploitation attempt
```

### CVE-2024-58100 — Stale PTR_TO_PACKET UAF

```bash
cd test/
./build.sh   # select CVE-2024-58100, kernel v6.12.24

cd buildroot/
output/images/start-qemu.sh -- -smp 4

# Inside VM (login as user, uid=1000):
/home/user/poc        # Verifier-accept demo (stale PTR_TO_PACKET load)
/home/user/exploit    # UAF R/W primitive + PE attempt via pipe_buffer.ops
```

> **Capabilities:** the init script (`exploit_overlay/etc/init.d/S99exploit`) grants
> `cap_bpf,cap_net_admin,cap_perfmon,cap_syslog+ep` to the exploit binary and sets
> `kptr_restrict=0`, `unprivileged_bpf_disabled=0`, `perf_event_paranoid=0`. This
> simulates a context where a service with BPF policy is compromised — CVE-2024-58100
> is **not** exploitable by a fully unprivileged user on modern kernels.

---

## Report

The full technical report (LaTeX + PDF) is in `report/`. It covers:
- Methodology for CVE selection from the eBPF verifier bug class
- Technical analysis of each CVE (patch diff, root cause, exploitation path)
- Exploit design decisions and failed approaches
- Results and conclusions

Politecnico di Torino — Cybersecurity (SVT) — A.Y. 2025/2026
