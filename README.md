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
│   └── CVEs/                           ← One folder per CVE under test
│       ├── CVE-2023-39191/
│       │   ├── configs/                ← Per-kernel buildroot + kernel configs
│       │   │   ├── v6.0/
│       │   │   └── v6.1/
│       │   ├── exploit_overlay/        ← Root overlay: binaries deployed to VM at /root/
│       │   └── src/                    ← Exploit source (poc.c, exploit.c)
│       ├── CVE-2024-42072/
│       │   ├── configs/
│       │   ├── exploit_overlay/
│       │   └── src/
│       └── CVE-2024-45020/
│           ├── configs/
│           ├── exploit_overlay/
│           └── src/
│
├── exploits/                           ← Standalone exploit sources (outside Buildroot flow)
│   └── CVE-2023-39191/
│       └── src/
│           ├── poc.c                   ← Proof of concept (OOB R/W primitive)
│           └── exploit.c              ← Full LPE exploit (adaptive calibration + cred spray)
│
├── CVE/                                ← CVE list analysis scripts and data
│   ├── eBPF_CVEs_new_exploits.csv
│   ├── list_verifier_cve.py
│   ├── list_verifier_only_cve.py
│   ├── verifier_cve_list.txt
│   └── verifier_only_cve_list.txt
│
└── report/                             ← LaTeX report and compiled PDF
    ├── exploits/
    │   ├── CVE-2023-39191.tex
    │   ├── CVE-2024-42072.tex
    │   └── CVE-2024-45020.tex
    ├── img/
    ├── main.tex
    └── main.pdf
```

---

## CVEs

| CVE | Kernel Range | Bug Class | Memory Primitive | LPE Status |
|-----|-------------|-----------|-----------------|------------|
| CVE-2023-39191 | ≤ 6.1.19 / ≤ 6.2.6 | Dynptr type confusion (OOB via overlapping dynptrs on BPF stack) | Arbitrary OOB R/W via corrupted dynptr size | ✅ Full LPE (adaptive calibration + cred spray) |
| CVE-2024-42072 | < 6.10.2 | Verifier register state leak across subprog calls | OOB read primitive | 🔬 Primitive confirmed, LPE in progress |
| CVE-2024-45020 | < 6.11 | Incorrect bounds check on stack-allocated dynptr | OOB R/W potential | 🔬 PoC confirmed, exploitation analysis ongoing |

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
./start-qemu.sh --serial-only -- -m 9216
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
./start-qemu.sh --serial-only -- -m 9216

# Inside VM:
/root/poc      # Verify OOB R/W primitive
/root/exploit  # Full LPE → creates /tmp/rootsh
/tmp/rootsh    # Spawn root shell
```

### CVE-2024-42072

```bash
cd test/
./build.sh   # select CVE-2024-42072

cd buildroot/
./start-qemu.sh --serial-only

# Inside VM:
/root/poc      # OOB read primitive demo
/root/exploit  # Exploitation attempt
```

### CVE-2024-45020

```bash
cd test/
./build.sh   # select CVE-2024-45020

cd buildroot/
./start-qemu.sh --serial-only

# Inside VM:
/root/poc      # Dynptr OOB trigger
/root/exploit  # Exploitation attempt
```

---

## How CVE-2023-39191 Works (Summary)

The BPF verifier fails to detect that two dynptrs placed at `fp-32` and `fp-24`
overlap on the BPF stack. When `bpf_ringbuf_reserve_dynptr` writes its vmalloc
pointer to `fp-24`, it overwrites the `size` field of the first dynptr with the
upper 32 bits of the vmalloc address (`≈ 0xFFFFC900` ≈ 4 GiB). The verifier
already approved the program; at runtime the dynptr believes it has a 4 GiB window,
enabling arbitrary kernel memory R/W at a fixed physical offset (~8.2 GiB).

The exploit proceeds in 7 phases:
1. Allocate BPF data map early (anchors the OOB target address)
2. Spray ringbuf allocations to align the vmalloc pointer correctly
3. Adaptive pressure calibration (detects when mmap reaches the OOB window)
4. Fork 5000 children → cred structs land in pages just past the mmap boundary
5. Scan OOB window for `uid_sig = (uid << 32) | uid` pattern
6. Overwrite the matched `struct cred` fields with zero (uid/gid → root)
7. The child with zeroed creds copies the exploit binary as SUID root → `/tmp/rootsh`

---

## Report

The full technical report (LaTeX + PDF) is in `report/`. It covers:
- Methodology for CVE selection from the eBPF verifier bug class
- Technical analysis of each CVE (patch diff, root cause, exploitation path)
- Exploit design decisions and failed approaches
- Results and conclusions

Politecnico di Torino — Cybersecurity (SVT) — A.Y. 2025/2026
