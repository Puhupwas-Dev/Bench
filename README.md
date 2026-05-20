# Bench – Internal Legacy Code Reference

Personal reference for evaluating AI agents on legacy software engineering tasks (COBOL, Fortran, Java 7, Assembly, C89, BASIC).  
Cloned from a public source and adapted for personal evaluation workflows.

> *Includes ten representative sample tasks. The full benchmark contains hundreds of tasks.*

---

## Overview

Tasks span six legacy language families and real enterprise domains.

| Language | % of Sample | Domains |
| --- | --- | --- |
| **COBOL** | 46% | Financial settlement, payroll, insurance, telecom billing, VSAM |
| **Java 7** | 32% | Enterprise middleware, CDR processing, warehouse logistics, binary parsing |
| **BASIC** | 6% | Business applications, accounting |
| **C89** | 5% | Systems programming, low‑level debugging |
| **Fortran** | 5% | Scientific computing, numerical methods |
| **Assembly** | 5% | x86 firmware, protocol decoding |

---

## Sample Tasks (Local Only)

| Task | Language | Type | Description |
| --- | --- | --- | --- |
| `1907c2` | C | fix/debug | Legacy buddy allocator fix |
| `16b04d` | COBOL | migration | Railroad retirement migration |
| `2831b5` | Java 7 | fix/debug | Rating engine repair |
| `3af1fe` | COBOL | fix/debug | Bond settlement reconciliation |
| `505812` | Java 7 | fix/debug | Inventory cost fix |
| `6fe1ab` | Java 7 | fix/debug | MTOM attachment corruption fix |
| `8e8098` | COBOL | fix/debug | Railcar settlement fix |
| `d1ddc1` | Fortran | migration | Lattice QCD migration to C++ |
| `ecf5e7` | x86-64 ASM | fix/debug | MZ/NE header parser fix |
| `fac397` | COBOL | migration | Batch interest migration |

---

## Task Structure (Harbor format)

Each task directory contains:
tasks/<task-id>/
instruction.md # What the agent must do
task.toml # Configuration (timeout, resources)
environment/ # Legacy codebase + Dockerfile
solution/ # Reference solution (oracle)
tests/ # Verifier scripts

text

---

## Getting Started (Local)

### Prerequisites

- Docker
- [Harbor](https://github.com/laude-institute/harbor) (for automated evaluation)

### Install Harbor

```shell
pip install harbor
Run the Oracle Solutions (Verify setup)
shell
harbor run --dataset bench \
  --agent oracle \
  --n-concurrent 4
Run an Agent (example with Anthropic)
shell
export ANTHROPIC_API_KEY=<YOUR-KEY>
harbor run --dataset bench \
  --agent claude-code \
  --model anthropic/claude-opus-4-6 \
  --n-concurrent 4
Run a Single Task Manually
shell
cd tasks/1907c2-c-debug-legacy-buddy-fix

docker build -t bench-1907c2 -f environment/Dockerfile environment/
docker run -it bench-1907c2 /bin/bash

# After changes inside container:
pytest tests/test_outputs.py
Refer to task.toml for task‑specific settings.
