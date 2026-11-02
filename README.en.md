<div align="center">

# agent安全笔记 · AI Agent Security Notes

<img alt="tests" src="https://img.shields.io/badge/tests-42%20passing-brightgreen"> <img alt="python" src="https://img.shields.io/badge/python-3.12-blue"> <img alt="langgraph" src="https://img.shields.io/badge/LangGraph-1.2.11-purple"> <img alt="license" src="https://img.shields.io/badge/license-MIT-green">

</div>

<p align="center">
🇨🇳 <a href="./README.md">简体中文</a> | 🇺🇸 <a href="./README.en.md">English</a>
</p>

An AI Agent security knowledge base: 10 ASI principle documents, 50 categorized knowledge documents, and 3 learning paths. It covers per-item principles, attack steps, detection, and defenses for the OWASP Agentic AI Top 10.

## Table of Contents

- [Overview](#overview)
- [Knowledge System](#knowledge-system)
- [Quick Start](#quick-start)
- [Pages and Usage](#pages-and-usage)
- [Learning Paths](#learning-paths)
- [Document Conventions](#document-conventions)
- [Directory Structure](#directory-structure)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [References](#references)

## Overview

The project splits AI Agent security into two readable, searchable, reproducible layers:

| Layer | Content | Location |
| --- | --- | --- |
| Principles | OWASP Agentic AI Top 10 (ASI01–ASI10), item by item: principles, source code, defenses | `docs/asi01-principle.md` … `docs/asi10-principle.md` |
| Knowledge | 11 categories, 50 attack/defense documents, unified paper-style structure | `docs/kb/` |

> [!NOTE]
> The content is intended for authorized security testing and defense engineering only.

## Knowledge System

### ASI Topics (10 documents)

| ID | Topic | Principle document |
| --- | --- | --- |
| ASI01 | Agent Goal Hijacking | `docs/asi01-principle.md` |
| ASI02 | Tool Misuse & Exploitation | `docs/asi02-principle.md` |
| ASI03 | Identity & Privilege Abuse | `docs/asi03-principle.md` |
| ASI04 | Agentic Supply Chain | `docs/asi04-principle.md` |
| ASI05 | Unexpected Code Execution | `docs/asi05-principle.md` |
| ASI06 | Memory & Context Poisoning | `docs/asi06-principle.md` |
| ASI07 | Insecure Inter-Agent Communication | `docs/asi07-principle.md` |
| ASI08 | Cascading Agent Failures | `docs/asi08-principle.md` |
| ASI09 | Human-Agent Trust Exploitation | `docs/asi09-principle.md` |
| ASI10 | Rogue Agents | `docs/asi10-principle.md` |

### Categorized Knowledge Base (11 groups / 50 documents)

| Group | Docs | Coverage |
| --- | --- | --- |
| Foundations & Threat Modeling | 5 | OWASP lists, MITRE ATLAS, STRIDE, asset surface, five-stage supply chain |
| Prompt Injection | 8 | Direct/indirect/split/structured injection, fake traces, deferred triggers, tool exfiltration, output handling |
| Obfuscation & Perturbation | 4 | Noise tiers, Unicode characters, token splitting, mother sentences |
| Jailbreak & Persuasion | 4 | Roleplay, emotional appeal, multi-turn crescendo, PAIR/TAP/GCG |
| Model & Data Attacks | 5 | Model extraction, inversion, membership inference, poisoning, embedding weaknesses |
| Context & Memory Attacks | 3 | Context overflow, system prompt leakage, memory poisoning |
| Agentic & Trust | 3 | Excessive agency, multi-agent communication and cascades, human-agent trust |
| AI Protocols & Runtime | 5 | MCP tool poisoning, A2A card spoofing, model file deserialization, multimodal channels, encoding bypass |
| AI Infrastructure & Supply Chain | 6 | Inference fingerprinting, MLOps enumeration, vector databases, recon methodology, CVEs, detection and hardening |
| Defense & Evaluation | 3 | Input-side defenses, architectural hard constraints, red-team evaluation and go-live checklist |
| Agent Attack Surface in Practice | 4 | Prompt assembly surface, sandbox read/write boundary, privilege surface recon, six-stage attack chain |

## Quick Start

```bash
# 1. Create a virtual environment
python -m venv .venv

# 2. Activate it (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the local site
python run_web.py
```

Open `http://127.0.0.1:5000`. The server binds to the loopback address only.

## Pages and Usage

| Route | Description |
| --- | --- |
| `/` | Dashboard: learning path entry + ASI topic matrix |
| `/learn` | Learning path list (3 paths) |
| `/learn/<pid>` | Path detail: ordered reading units |
| `/topic/<asi>` | ASI topic page: full principle text + auto TOC + related knowledge |
| `/principle/<asi>` | Direct principle document page |
| `/kb` | Knowledge base overview (11 groups) |
| `/kb/g/<gid>` | Group page |
| `/kb/<slug>` | Single document (auto TOC) |

## Learning Paths

| Path | Units | Flow |
| --- | --- | --- |
| P1 LLM Security Foundations | 3 | Official numbering → context overflow → memory poisoning |
| P2 Injection & Evasion in Practice | 6 | Indirect/split/structured injection → Unicode flaws → multi-turn jailbreak → limits of sanitization |
| P3 AI Infrastructure & Defense in Depth | 5 | Five-stage supply chain → inference fingerprinting → MLOps enumeration → detection signatures → architectural defenses |

## Document Conventions

Every knowledge document follows the same structure for side-by-side comparison:

```text
1. Problem & Threat Model     roles / capabilities / preconditions + core thesis
2. Principle Derivation       mechanism breakdown and derivable conclusions
3. Attack Surface             entry points / preconditions / observables / impact
4. Practical Steps            numbered steps + payloads + expectations + failure handling
5. Variant Catalog            ID + payload traits + decision markers
6. Detection & Evidence       observable signals + evidence checklist
7. Defense & Verification     each defense paired with a verification method
8. References                 primary sources
```

## Directory Structure

```text
.
├── run_web.py            # Local site entry point
├── requirements.txt
├── test_web.py           # Page reachability and content contracts (42 checks)
├── lab/                  # Reference implementations quoted by the docs
│   ├── asi_map.py        # ASI names and component mapping
│   ├── kb_map.py         # Knowledge base group registry
│   ├── learn.py          # Learning path registry
│   ├── graph.py          # Single-agent scenario and HITL
│   ├── multi_agent.py    # Multi-agent and cascades
│   ├── mock_llm.py       # Deterministic scenario queues
│   ├── tools.py          # Tool set (with safe variants)
│   ├── memory.py         # Vector memory (with session isolation)
│   └── runner.py         # Scenario runner wrapper
├── docs/
│   ├── asi01-principle.md … asi10-principle.md
│   └── kb/               # 50 categorized knowledge documents
├── seed/                 # Example payload documents
└── web/                  # Flask site (routes / templates / static assets)
```

## Testing

```bash
python test_web.py       # 42 checks: page reachability, content contracts, no leftovers
```

## Contributing

- Technical content must follow official documentation and public research; cited CVEs and IDs must be traceable.
- Run `test_web.py` before submitting changes.
- Keep the paper-style structure; avoid filler transitions.

## License

This project is open-sourced under the [MIT License](LICENSE).

## References

- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
