# EIP — Execution Intelligence Project

**Task-authorized, provenance-aware enforcement for tool-using agents.** EIP evaluates proposed tool effects against the user's task, selected source records, established objects and destinations, and relevant provider state before native dispatch. An external document can supply evidence without gaining authority to issue new instructions.

## Evaluation results

All figures below are **paired historical cases with an injected attack present**. Utility is the percentage of legitimate user tasks completed *under attack*; it was measured directly, alongside targeted attack success rate (ASR).

| Benchmark | Defense | Legitimate-task utility under attack | Targeted ASR |
|---|---|---:|---:|
| **AgentDyn v1.2.2** · 560 pairs | **EIP** | **212/560 (37.9%)** | **12/560 (2.1%)** |
| | Native | 198/560 (35.4%) | 286/560 (51.1%) |
| | DRIFT | 107/560 (19.1%) | 20/560 (3.6%) |
| **AgentDojo v1.2** · 629 pairs | **EIP** | 304/629 (48.3%) | **0/629 (0.0%)** |
| | Native | 314/629 (49.9%) | 171/629 (27.2%) |
| | DRIFT | 334/629 (53.1%) | 12/629 (1.9%) |

In the matched AgentDyn cases, EIP reduced observed targeted ASR by **95.8% relative to Native** while completing 14 more legitimate tasks (212 versus 198). It completed **1.98× as many** legitimate attacked tasks as DRIFT (212 versus 107). In AgentDojo, EIP recorded **no targeted successes in 629 cases**, versus 171 for Native and 12 for DRIFT, at a lower attacked-task utility than both comparators.

These are **different evaluated configurations**, not a single combined experiment: AgentDyn used P09 intent compilation; AgentDojo used P09 plus read-result isolation. The AgentDojo subset is 629 matched cases, not the full 949-case DRIFT grid. The supplied records do not include a separate EIP no-attack utility arm or matched runtime-cost study. The current reference code contains subsequent changes and is not claimed to be byte-identical to the original evaluated implementation.

See **[Technical paper, evaluation details and reproduction](docs/TECHNICAL.md)** for mechanism-to-code mapping, suite-level comparisons, methods, scope, statistical qualifications and verification.

## How it works

EIP combines eight related controls:

1. **Trusted task intent (P09):** bounded effect families, destinations and task-delegated sources derived from the principal's request.
2. **Selected-record provenance:** reconstruct the relevant earlier observations; extract structured facts without accepting embedded commands.
3. **Effect, object and destination alignment:** check the proposed native operation against the authorized target and recipient.
4. **Provider-backed facts:** consult simulator contact and membership state in the measured harnesses when the task requires it.
5. **Correlated verification:** bind verification steps to the specific pending consequential effect.
6. **Pre-dispatch enforcement:** hold unsupported consequential calls before the native executor; permit supported calls through its normal path.
7. **Optional read-result isolation:** isolate untrusted observations before subsequent model reasoning in the AgentDojo evaluated configuration.
8. **Decision context and audit contract:** record scope, authority, evidence, decision reasons and obligations. Risk-budget fields are interface definitions, not measured budget enforcement.

The reference implementation is under `src/eip_execution/`; the AgentDyn and AgentDojo evaluations, audit data, source metadata and strict scorers are under `benchmarks/`.

## Verify the archived results

The original 4,446 evidence JSON records (2,004 AgentDyn and 2,442 AgentDojo) are **separate release assets**, not repository source files. The checked-in manifest is `docs/EVIDENCE_SHA256_MANIFEST.json`.

From the repository root after obtaining the original ZIP assets:

```sh
python tools/verify_offline.py \
  --agentdyn-zip /path/to/agentdyn-v1.2.2-evidence.zip \
  --agentdojo-zip /path/to/agentdojo-v1.2-evidence.zip
```

This checks the SHA-256 of every record, then recomputes both strict aggregate summaries. It requires no API key, network access or model calls. It verifies preserved evidence and scoring arithmetic, **not** the original model service activity or a cryptographically attested source-to-run chain.

For the reference implementation tests with Python 3.11 and AgentDojo installed:

```sh
python -m pip install -e '.[test]'
python -m pip install 'agentdojo==0.1.35'
python -m pytest
```

Local upstream-source validation reported **97 passing no-model tests per harness** on Python 3.11.18 on 12 November 2026, including installed-wheel verification. The corresponding upstream PR revisions have not been subjected to another paid-model benchmark run; that result cannot be inferred from the installation tests.

## Scope and license

The gate covers instrumented native calls and a declared set of consequential effect types; some native operations remain outside full policy classification. The technical paper lists those operations and the relevant test coverage. No general guarantee of prompt-injection immunity, unseen-tool enforcement, or superiority to unevaluated defenses is claimed.

EIP-authored reference source, tests, scorers and documentation are MIT-licensed (`LICENSE`). **Third-party benchmark fixtures and recorded model trajectories are not automatically covered by that grant**; see [`LICENSE_SCOPE.md`](LICENSE_SCOPE.md). Contributions should include focused allow/hold tests and must identify any effect on evaluation comparability. For benchmark claims, include exact suite/version, model, arm settings, paired-case denominators and trace provenance.
