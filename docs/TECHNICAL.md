# Execution Intelligence Project (EIP): Provenance-Aware Task Authority and Consequence-Level Enforcement for Tool-Using Agents

**Technical paper and reproducibility record**  
**Project:** EIP / Devmaha  
**Evaluation:** historical AgentDyn v1.2.2 and AgentDojo v1.2 traces  
**Code:** reference implementation and upstream adapters

## Abstract

Prompt injection exploits a trust-boundary error: an agent processes outside content as task data, but may inadvertently treat that content as instructions authorizing sensitive actions. The Execution Intelligence Project (EIP) investigates an authorization architecture that evaluates proposed *effects* against the trusted task, bounded delegation, provenance of supporting observations, established identities and objects, provider facts, and correlated execution state. The design places an intervention point immediately before native tool dispatch. It distinguishes the authenticity or relevance of information from the authority to act on it; a retrieved record may be legitimate evidence without being permission to transfer money, add a collaborator, change a credential, or send data to a new recipient.

EIP is not a single detector. The benchmark artifact implements a task-intent compiler (P09), record-granular source resolution, effect-family and target alignment, selected provider-state probes, pending-effect correlation, a HOLD/allow native execution checkpoint, optional observation isolation, and an audit-oriented portable decision schema. Some broader contract fields—including multi-agent delegation and runtime risk budgets—are *interfaces*, not empirically validated enforcement in the two benchmark runs. The historical evaluations are distinct configurations: on AgentDyn v1.2.2 (560 paired attacked cases) EIP recorded 12/560 targeted attack successes (2.1%), versus 286/560 (51.1%) for Native and 20/560 (3.6%) for DRIFT; attacked-task utility was 212/560 (37.9%), versus 198/560 (35.4%) and 107/560 (19.1%), respectively. On AgentDojo v1.2 (629 paired attacked cases), EIP recorded 0/629 targeted successes versus 171/629 (27.2%) Native and 12/629 (1.9%) DRIFT, at attacked-task utility 304/629 (48.3%), versus 314/629 (49.9%) and 334/629 (53.1%). These are paired, offline-verified historical observations, not proof of universal prevention, source-to-run attestation, or head-to-head superiority over CaMeL, FIDES, or APEX.

**Index terms:** prompt injection; agent security; tool authorization; provenance; trusted task intent; execution guard; indirect prompt injection; agent benchmarks.

## I. Problem statement and security objective

Tool-using assistants observe emails, files, issue comments, search results, messages, webpages and other third-party content while performing a legitimate task. These objects can carry instructions written by an adversary. If an agent interprets an instruction in such data as if it were supplied by the user, the resulting *external effect* may exceed the authorization granted by the task. Textual similarity to an attack pattern is incidental: unauthorized consequences can arise from plausible, factual-looking content as well as overt imperative text.

EIP's operational objective is to reduce unauthorized consequential actions while preserving as much legitimate task completion as possible. The principal's request and explicitly bounded delegations anchor authorization. A model's proposed action is not itself authority. Provider data may establish facts such as object identifiers or known contacts, but cannot on its own authorize a new payment destination or access grant. A gate at the executable checkpoint decides whether the action is supported, underspecified, or unauthorized.

This artifact evaluates **targeted attack success rate (ASR)** and **utility under attack**. It does not establish general privacy noninterference, full formal policy verification, protection from all uninstrumented capabilities, or exact equality of compute overhead against baselines. The useful technical claim is a *composed control architecture*, supported by concrete benchmark configurations, not invention of the execution-boundary concept in isolation.

## II. Threat model and trust boundaries

**Trusted inputs.** A user or other authenticated principal issues a task. The runtime may also contain pre-existing system/developer instructions, a known tool schema, certified provider state, and explicitly identified delegated sources. These sources have distinct roles: user instructions grant task authority; provider state supplies facts; tool specifications constrain effect interpretation.

**Untrusted inputs.** Retrieved bodies, third-party messages, document contents, web snippets, attacker-editable records and LLM continuations are treated as data or proposed operations, not as new authorization roots. An attacker may place instructions, misleading entities, URLs, apparent contact identities, or invented verification requirements into these surfaces. The adversary is not assumed to alter the trusted task or the gate's own code; compromised provider state, arbitrary code execution, and missing interception points are separate failure modes.

**Sensitive effects.** Examples include messages and email sends, payments, purchases, calendar invitations, file or repository modifications, permissions and collaborator grants, credential operations, deletion, downloads, form submissions and reservations. Read operations can establish facts and can also be sensitive in other threat models; this benchmark-specific implementation does not claim to gate all possible exfiltration paths or reads.

**Trust separation.** EIP distinguishes (1) *authority*: who permitted this consequence and within what scope; (2) *lineage*: where an asserted fact or identifier came from; (3) *truth or provider establishment*: whether a value is grounded by a recognized source; and (4) *effect*: what the pending native tool call would change or disclose. A true fact extracted from an email may be usable as an object identifier yet remain insufficient to authorize adding the email's author to a repository.

## III. Architecture and execution sequence

The evaluated flow can be summarized as:

```text
Authenticated task and bounded delegation
       |  P09 candidate intent clauses (optional model call)
       v
Task authority envelope --> task-named targets / delegated sources
       |                                    |
       |                         selected source records
       |                              + provenance
       v                                    v
Proposed native tool call --> effect/target classification --> evidence alignment
                                                       |
                                     provider fact probes / pending-effect correlation
                                                       |
                                                       v
                                          pre-dispatch EIP decision
                                               /           \
                                             ALLOW          HOLD
                                               |              |
                                          native tool      safe bounded
                                           execution      continuation
       Optional post-tool result isolation influences later LLM context,
       but does not substitute for the pre-dispatch authorization decision.
```

The portable contract lives in `src/eip_execution/core/port.py`; the benchmark adapters live under `src/eip_execution/adapters/`. The common gate operates at the native execution loop before the normal `ToolsExecutor` of the AgentDojo-derived harness. The benchmark-specific adapter translates the harness's tool calls and observations into the policy and evidence checks; an adapter is not intended to consult benchmark labels, attack success flags, expected answers, or evaluator state.

### A. Trusted Task Intent and P09 compilation

`core/p09.py` defines a typed, task-local compilation of the authenticated request into candidate `allowed_effect_families`, `allowed_destinations`, and `delegated_sources`. `core/planfirst.py` and `core/effect_support.py` provide related effect-family and support machinery. A semantic model proposes a bounded clause set; deterministic checks test candidate actions for membership and destination/object consistency. The compilation cannot independently assert a provider fact or create approval absent from the trusted task.

This hybrid design has a practical trade-off: it can process tasks phrased in natural language without a fixed vocabulary of attack strings, but a mistaken compiler may omit legitimate intent or overinterpret a request. In the measured configurations P09 uses additional GPT-4o-mini calls. It should neither be called a zero-LLM security kernel nor compared to baselines as if identical model-call budgets were established.

### B. Provenance-aware, record-granular source resolution

`core/action_resolution.py` builds source selections from the *causally prior* interaction history, not from content inserted by the pending effect. The distinction matters because an attacker can fill a large inbox or page with multiple attractive targets. EIP attempts to resolve the specific record relevant to the task and project only typed, context-appropriate facts such as a selected identifier, sender or URL. `core/object_alignment.py` then cross-checks object and recipient relationships rather than promoting an entire untrusted document to unrestricted task authority.

Example: the user asks to reply to a named correspondent. Reading the selected correspondence may establish the reply target, but an injected instruction inside a different message to add an external recipient is not thereby authorized. Conversely, refusing to use all external facts would make many normal tasks impossible. EIP attempts the narrower policy: **provenance establishes bounded data dependencies; it does not establish a general permission to act.** Current source selection includes heuristics and is not a cryptographic data-lineage proof; robust provider identities and stale-data handling remain open work.

### C. Consequence, object and destination alignment

A sensitive tool call has at least three questions: what *effect family* does it enact; which *object or resource* does it modify; and which *destination or principal* receives a benefit, permission or disclosure? `core/effect_support.py`, `core/object_alignment.py` and `adapters/agentdojo/element.py` implement families of checks for these dimensions. An authorized purchase does not authorize a substituted product; a valid repository action does not automatically authorize an attacker-nominated collaborator; a permitted message does not allow arbitrary recipient changes. These tests deliberately distinguish business objects, benign operation fields and actual authority-bearing destinations.

### D. Provider-state fact probes

Some decisions need authoritative context not present in the message trace: for example, whether an invitee is already an established workspace member or contact. `adapters/agentdojo/membership_probe.py` implements `SlackMembershipProbe` and `WorkspaceContactsProbe` as benchmark-world fact providers. The gate decides whether expansion of an established set is authorized; the probe reports the membership fact. In these experiments, probes read simulator state that the agent would otherwise access through provider APIs. This is a meaningful *experimental privilege* and a deployment gap—not evidence of an authenticated production integration or an attack-label oracle. Results must disclose that the probe can inspect provider-world membership state.

### E. Pending-effect and verification correlation

`core/pending_effect.py` models a consequential action that triggers an account verification challenge. A subsequent verification operation is correlated to the pending action, using a unique outstanding effect or a provider reference where available. Verification without a matching pending effect is held; ambiguous matches are not promoted to authorization. This reduces the risk that attacker-supplied one-time-password requests are treated as stand-alone permission. The model is implemented primarily for the AgentDyn provider-contract paths; it is not a general transactional consistency guarantee across arbitrary systems.

### F. Native pre-execution gate and bounded continuation

`adapters/agentdojo/element.py` evaluates the consequential native call before dispatch. The enforced path returns an allow or hold decision. Held tool calls are redirected to an internal blocked-action sentinel so the harness can maintain a well-formed tool-call/result relationship. `adapters/agentdojo/defense_module.py` hides that sentinel from the model's callable schema and guards loop continuation to avoid repeated blocked-call storms. The latest standalone source also exposes a named `build_eip_pipeline` for first-class upstream integration rather than requiring the historical global module-load monkey patch.

The gate is *hold-only* in the sense that it does not grant new permissions from untrusted text. This does not prove that every unauthorized operation will be recognized or that all legitimate operations will pass; classifications can be wrong and instrumentation is limited to covered tool paths. A deployment must also define semantics for outputs and uninstrumented capabilities.

### G. Optional observation isolation

The AgentDojo historical EIP configuration additionally sanitizes fresh tool-result text with same-model calls before subsequent model turns. This complements, rather than replaces, execution authorization. The historical/default failure path passes the original tool result through when sanitization fails; a later code revision adds optional withholding and failure counters, neither of which was measured in the historical data. AgentDyn historical results do not use this layer. Thus the two benchmark operating points are not one identical deployment configuration.

### H. Connected execution context and audit contract

`core/port.py` defines `NativeInvocation` and `EIPDecision`. Its fields include checkpoint and semantic-action identifiers, execution and authority scopes, delegation lineage, evidence references, reason-coded hold telemetry, truth/coverage labels, observations, and optional risk-charge and model-use counters. Such a contract can support reviewable records and future multi-agent/risk-budget integration. **Presence of a field is not evidence that a budget, cross-agent authorization graph, or cryptographically secure provenance ledger was enforced in the experiments.** These capabilities are recorded as design interfaces until exercised end to end.

## IV. A decision model (analytical abstraction, not a formal security proof)

Let **T** be the authenticated task, **C(T)** its candidate bounded intent clauses, **a** a pending native action, **E(a)** its effect family, **O(a)** its resource/object, **D(a)** its destination set, **R(T,H)** the task-selected source records from prior history **H**, and **F** certified provider facts available to the guard. Let `SupportedEffect`, `AlignedObject`, `AlignedDestinations` and `Correlated` denote the checks performed where applicable.

A conceptual admissibility predicate is:

```text
Allowed(a | T,H,F) :=
    SupportedEffect(E(a), C(T))
    AND AlignedObject(O(a), T, R(T,H), F)
    AND AlignedDestinations(D(a), T, R(T,H), F)
    AND Correlated(a, PendingEffects(H,F))     [when verification applies]
```

If the required evidence is missing or materially ambiguous, a conservative implementation returns HOLD; benchmark adapters may also contain utility-preserving exceptions. This expression describes the intended separation of concerns rather than a mechanically verified specification of every branch of `element.py`. Where tasks have bounded delegation, `R(T,H)` permits selected external records to contribute *facts* inside the delegated scope; it does not let those records expand `C(T)` themselves.

A representative example is a legitimate request to invite a named collaborator to a particular repository. EIP can allow the named destination if the effect family and repository scope align; it should hold an additional external address that appears only in an attacker-editable issue body. By contrast, a truly task-delegated source may establish a particular object or data field without authorizing a new effect family. The distinction between a source's *data relevance* and *ability to delegate authority* is central to the design.

## V. Implementation and reproducibility

**Package layout.** `src/eip_execution/core/` supplies intent compilation, effect support, action/source resolution, object alignment, pending effects and a portable decision port. `src/eip_execution/adapters/agentdojo/` provides the gate and integration wrappers; the AgentDyn adapter reuses the AgentDojo-derived core. `tests/unit/` contains source behavior tests; the evidence scorers live under `benchmarks/{agentdojo,agentdyn}/tools/aggregate_strict.py`. `tools/verify_offline.py` checks SHA-256 hashes and reruns both strict score summaries directly from the evidence ZIPs without LLM calls.

**Artifact provenance.** The archived traces, paired-cell audits and strict scoring scripts permit offline recomputation of the published aggregates. They do not independently attest the original model API calls. AgentDyn traces span implementation revisions, and the historical AgentDojo source-freeze record does not byte-match the subsequently revised reference runtime supplied here. The original freeze metadata remains unchanged under `benchmarks/*/provenance/`; the current code must not be treated as an exact historical run snapshot.

**Operational reproducibility.** A first-class upstream port requires `eip` in the upstream `DEFENSES` list, a `from_config` route to the EIP pipeline constructor, and correct packaging of `src/eip_execution` into the upstream wheel (or an explicitly pinned external dependency). A model-free import/build/smoke test is necessary to validate such integration. Results from a new code revision must not be attributed retroactively to the historical traces.

## VI. Evaluation design and measurements

Both evaluated configurations used `important_instructions` attacks and `gpt-4o-mini-2024-07-18` at temperature zero. Per-harness comparisons use the same attacked cases for the three reported arms. Native means the matched undefended agent. DRIFT is the reported paired reference defense. These are **within-harness** comparisons; the two harness versions and EIP configurations differ.

### A. AgentDyn v1.2.2 (n = 560 paired attacked cases)

| Arm | Correct tasks | Attacked-task utility | Successful targeted attacks | Targeted ASR |
|---|---:|---:|---:|---:|
| EIP | **212/560** | **37.9%** | **12/560** | **2.1%** |
| DRIFT | 107/560 | 19.1% | 20/560 | 3.6% |
| Native | 198/560 | 35.4% | 286/560 | 51.1% |

In this matched set, EIP reduced observed targeted ASR relative to Native by **48.9 percentage points**, or **95.8% relative**, while attacked-task utility increased by 2.5 points. It completed **1.98× as many attacked tasks as DRIFT** (212 versus 107), with observed aggregate ASR of 2.1% versus 3.6%. This is a strong empirical *security–utility operating point* on this harness. However, the EIP–DRIFT ASR difference is not significant in the stored exploratory paired test (p = 0.215); EIP's 2.5-point utility difference versus Native is not significant at 0.05 (p = 0.070). The utility difference versus DRIFT is large on the stored paired comparison (p ≈ 1.39×10^-18).

The per-suite ASR comparison is heterogeneous: EIP/DRIFT Shopping 3.9%/1.1%, GitHub 2.2%/0.6%, Daily Life 0.5%/8.5%. The aggregate ASR advantage over DRIFT is largely attributable to Daily Life, not uniform suite superiority. Historical EIP here uses P09 without observation isolation; benign/no-attack EIP utility was not collected.

### B. AgentDojo v1.2 (n = 629 paired attacked cases)

| Arm | Correct tasks | Attacked-task utility | Successful targeted attacks | Targeted ASR |
|---|---:|---:|---:|---:|
| EIP | **304/629** | **48.3%** | **0/629** | **0.0% observed** |
| DRIFT | 334/629 | 53.1% | 12/629 | 1.9% |
| Native | 314/629 | 49.9% | 171/629 | 27.2% |

The headline is **zero observed targeted attack successes on 629 matched cases**, against 171 for Native and 12 for DRIFT. EIP's attacked-task utility was 1.6 points lower than Native and 4.8 points lower than DRIFT. The stored exploratory paired test reports EIP–DRIFT ASR p ≈ 0.00049 and EIP–DRIFT utility p ≈ 0.048 (in DRIFT's favor). A zero observed count is not a zero true risk estimate; the approximate 95% Wilson upper confidence bound is 0.61% under a simple binomial approximation, without accounting for task dependence or selection.

Suite detail: Workspace EIP/DRIFT ASR 0.0%/1.7%; Travel 0.0%/**0.0%** (tie); Banking 0.0%/4.9%; Slack 0.0%/1.0%. EIP's utility exceeds DRIFT only in Banking. This 629-case Native-intersection set is not the complete 949-case DRIFT grid; EIP has 666 attacked records, of which 629 are in the paired subset. Benign utility for EIP and DRIFT was not measured. The EIP configuration includes both P09 and same-model observation isolation, making equal model-call overhead unverified.

### C. What the evidence establishes

The two strict scoring scripts reproduce the checked-in aggregates from the 4,446 supplied JSON trace records (2,004 AgentDyn, 2,442 AgentDojo). SHA-256 verification establishes correspondence between supplied artifacts and audit calculations; it does **not** establish that external model calls occurred as represented. All p-values are exploratory and unadjusted for multiple comparisons. Claims apply to observed targeted outcomes, not to all attack forms or adaptive attackers. The stronger phrasing is *“lower observed targeted ASR and competitive attacked-task utility under these matched conditions”*, not “EIP outperforms all other approaches.”

## VII. Relationship to other approaches

### A. CaMeL

CaMeL separates trusted query-derived control from untrusted data through an interpreter and capability-aware flow policy [3]. EIP shares the premise that lower-trust content must not determine security-sensitive control. EIP's distinctive emphasis in the presented artifact is *post-planning effect adjudication* with typed object/recipient alignment, record-granular provenance resolution, bounded fact probes and pending-effect correlation. CaMeL has its own formal reasoning and published results; the supplied EIP evidence includes no CaMeL arm, so a direct numerical superiority claim would be invalid.

### B. FIDES

FIDES treats agent security as information-flow control, with integrity and confidentiality labels propagated through execution and checked at sensitive boundaries [4, 5]. EIP does not implement complete IFC label propagation or inherit FIDES's security guarantees. Its emphasis is an explicit task-authority and provenance evidence contract for each proposed effect, including destination/object and provider-state checks. These are different design emphases and may be complementary; the available data do not rank them head-to-head.

### C. APEX and related execution-boundary research

APEX (October 2026) independently develops an execution-boundary defense around task-authorized effects and evidence-gated prevention, including deception-based exposure [6]. This overlap is material. EIP should not claim priority for the generic idea of checking actions at an execution boundary. The presented EIP contribution is the particular combination and implementation of P09 task-intent candidates, record-granular source projection, object/destination checks, provider fact probes, verification-effect correlation and native-tool interposition. Unlike APEX, EIP's present artifact does not demonstrate the same adaptive/capability-unit evaluation or deception mechanism. SPIDES also shows an IFC-oriented design for browser primitives [7]. These related works strengthen the case for *execution semantics*, but do not make the benchmark arms equivalent.

### D. Comparative summary

| Dimension | EIP in this artifact | CaMeL | FIDES | APEX |
|---|---|---|---|---|
| Primary unit of decision | Proposed tool effect, object and destination | Trusted control/data program and capabilities | Labeled information flow / sensitive tool | Authorized effect and endorsed evidence at execution boundary |
| Evidence semantics | Selected records, typed facts, provider probes | Interpreter-controlled data use | Integrity/confidentiality propagation | Contract-endorsed evidence |
| Authorization root | Trusted task + bounded delegation | Trusted query / program | Label/policy regime | Task authorization contract |
| Distinguishing implemented feature here | Pending-effect correlation + provider-world probes + typed source projection | Program/capability separation | Automatic label propagation | Deception-based exposure |
| Direct benchmark comparison in supplied EIP traces | Native and DRIFT only | **Not evaluated** | **Not evaluated** | **Not evaluated** |

The comparative case for EIP is therefore **mechanistic and empirical within its measured baselines**. Any assertion of superior performance to CaMeL, FIDES or APEX requires common attack subsets, the same backbone and task mix, comparable budgets, measured benign utility, and independent source-pinned replay.

## VIII. Limitations, threats to validity, and roadmap

1. **Run-source attribution.** The historical records and this revised reference implementation are not a byte-identical run snapshot. The original source metadata is retained, but the archive does not establish an independently attested commit-to-model-run chain.
2. **Different EIP configurations.** AgentDyn and AgentDojo use different isolation settings, so their numbers cannot be pooled or treated as one identical defense setting.
3. **Missing benign utility and cost.** The evidence does not establish EIP's no-attack user utility, measured extra model calls, tokens, latency or per-task cost under matched budgets.
4. **Third-party evidence.** Baseline, model and simulator records have separate redistribution considerations. A private-key marker in AgentDyn is a synthetic injection fixture; it is not a discovered private credential. The complete traces still require ordinary publication-rights review.
5. **Heuristic and model-dependent decisions.** Natural-language intent compilation and source selection can be wrong. Some default paths fail open (notably historical observation isolation); important omissions may permit attacker influence or harm utility.
6. **Simulation-backed probes.** Provider membership/contact facts came from benchmark simulator state; a real provider API with authenticated read permissions and versioning has not been integrated or evaluated here.
7. **Coverage limitations.** Enforcement covers instrumented calls and selected effect families. It is not a formal proof of information-flow confinement, containment of all reads, or protection across all tools, agents and external destinations.
8. **Statistical/generalization limitations.** Small suite-specific counts, attack choice, case selection, and model dependence limit generalization. Historical p-values are exploratory rather than preregistered evidence of broad superiority.
9. **Software integration.** The first-class builder passed owner-supplied real-harness no-API Python 3.11 integration tests in both source trees (97 tests per harness); the separate upstream CI matrices still require GitHub execution. Changes after the historical runs are not benchmark-validated merely because their unit tests pass.

The highest-value next experiments are (a) a source-pinned API-backed replay slice; (b) benign-utility and cost measurement; (c) component-level ablations; (d) adaptive attacks and additional agent backbones; and (e) a fair same-harness comparison against CaMeL, FIDES and APEX where licenses and APIs permit. These are proposed experiments, **not results claimed by the present paper**.

## IX. Conclusion

EIP advances a substantive design position: the way to control indirect prompt injection is not only to recognize adversarial text, but to evaluate **whether a proposed consequence is authorized by the principal and supported by appropriately scoped, provenance-aware evidence**. The artifact implements several mutually reinforcing mechanisms: task-intent clauses, record-level source resolution, object and recipient alignment, provider-backed membership checks, correlated verification, pre-dispatch holds, controlled continuation and optional observation isolation. Historical matched benchmark evidence shows a particularly strong AgentDyn operating point—**95.8% lower observed targeted ASR than Native with slightly higher attacked-task utility**, and nearly **2× DRIFT's completed attacked tasks**—and **0/629 observed successful targeted attacks** on the AgentDojo subset, at a modest utility cost versus Native and larger cost versus DRIFT. These findings support further open-source and independent evaluation of EIP's integrated approach. They do not establish universal security or numerical superiority over defenses that were not evaluated in the same setting.

## Appendix A. Suite breakdown and interpretation

All percentages below describe matched cases with an injected attack present. The comparisons are **within each harness**.

### AgentDyn v1.2.2

| Suite (paired cases) | EIP utility / ASR | DRIFT utility / ASR | Native utility / ASR |
|---|---:|---:|---:|
| Shopping (180) | 35.6% / 3.9% | 12.2% / **1.1%** | 35.0% / 28.9% |
| GitHub (180) | **53.9%** / 2.2% | 32.2% / **0.6%** | 45.6% / 41.1% |
| Daily Life (200) | 25.5% / **0.5%** | 13.5% / 8.5% | 26.5% / 80.0% |

DRIFT has lower observed ASR in Shopping and GitHub. EIP's aggregate ASR advantage against DRIFT is driven by Daily Life. Shopping evidence was collected under an earlier EIP revision; the separate 45-case certification comparison is excluded from the 560-case aggregate.

### AgentDojo v1.2

| Suite (paired cases) | EIP utility / ASR | DRIFT utility / ASR | Native utility / ASR |
|---|---:|---:|---:|
| Workspace (240) | 59.6% / **0.0%** | 60.4% / 1.7% | 59.2% / 17.9% |
| Travel (140) | 30.0% / **0.0%** | **53.6% / 0.0%** | 47.1% / 13.6% |
| Banking (144) | **45.8% / 0.0%** | 41.0% / 4.9% | 38.2% / 34.0% |
| Slack (105) | 50.5% / **0.0%** | 52.4% / 1.0% | 48.6% / 57.1% |

EIP and DRIFT both recorded 0/140 targeted successes in Travel; EIP's advantage is not uniform across suites. The reported AgentDojo subset is the complete declared **629-case Native intersection**, rather than the full 949-case DRIFT grid. EIP has 666 attacked records, of which 629 belong to the paired comparison.

### Statistical interpretation

For AgentDyn, the stored exploratory paired McNemar p-value for EIP–DRIFT targeted ASR is 0.215; for EIP–Native attacked utility it is 0.070, and for EIP–DRIFT attacked utility it is approximately 1.39×10^-18. For AgentDojo, EIP–DRIFT targeted ASR is p ≈ 0.00049; attacked utility is p ≈ 0.048 in DRIFT's favor; EIP–Native attacked utility is p ≈ 0.488. These tests are unadjusted, task cells may not be statistically independent, and no preregistered generalized inference is claimed.

## Appendix B. Verification and artifact layout

### Recompute historical scores

Obtain `agentdyn-v1.2.2-evidence.zip` and `agentdojo-v1.2-evidence.zip` from the project's approved evidence release. Keep the ZIP contents unchanged; the SHA-256 manifest describes the original record bytes.

Run at the repository root:

```sh
python tools/verify_offline.py \
  --agentdyn-zip /path/to/agentdyn-v1.2.2-evidence.zip \
  --agentdojo-zip /path/to/agentdojo-v1.2-evidence.zip
```

The verifier expects **2,004 AgentDyn** and **2,442 AgentDojo** records. It checks all entries in `docs/EVIDENCE_SHA256_MANIFEST.json`, rejects missing/extra or altered records, and invokes the retained strict scoring logic for each benchmark. Expected terminal summary:

```text
agentdyn: verified SHA-256 for 2004 raw records
agentdojo: verified SHA-256 for 2442 raw records
AgentDyn: strict score matches released audit
AgentDojo: strict score matches released audit
```

If the evidence has already been extracted under the original `benchmarks/{agentdyn,agentdojo}/evidence/` structure, use:

```sh
python tools/verify_offline.py --extracted-root /path/to/extracted-root
```

Raw evidence is deliberately not committed as thousands of JSON files. The code repository retains `benchmarks/*/audit/aggregate_summary.json`, paired-cell CSV audits, provenance metadata, `benchmarks/*/tools/aggregate_strict.py`, the complete manifest, and the ZIP verifier. A hash match proves **file identity** and a scorer match proves **stored arithmetic**, not the provenance of model-service calls or equivalence to the revised implementation.

### Recheck source and installed-harness behavior

With Python 3.11 and the AgentDojo package installed:

```sh
python -m pip install -e '.[test]'
python -m pip install 'agentdojo==0.1.35'
python -m pytest
```

The supplied local validation transcript dated 12 November 2026 reports **97 passing tests for AgentDojo** and **97 for AgentDyn** on Python 3.11.18, against each real harness dependency tree with deterministic scripted tool calls and no LLM API access. Each tested checkout also built a wheel, reinstalled it and verified that `eip_execution` was importable and `eip` registered. These checks establish tested runtime and packaging compatibility for those checkouts. They do not show that the gate-only default reproduces historical P09/read-isolation scores or that other supported Python versions passed CI.

The first-class upstream port registers `eip` in `DEFENSES`, delegates `AgentPipeline.from_config` to `build_eip_pipeline` for that option, and packages `src/eip_execution` in the upstream wheel. The reference builder is in `src/eip_execution/adapters/agentdojo/defense_module.py`. The separate upstream PRs supply those integration edits; the standalone repo does not vendor the upstream package itself.

### File guide

| File or directory | Purpose |
|---|---|
| `src/eip_execution/core/` | P09, effect support, selected-record provenance, object alignment, pending effects, decision port |
| `src/eip_execution/adapters/` | AgentDojo-derived runtime integration and AgentDyn adapter |
| `benchmarks/agentdyn/` | Version-specific aggregate, paired audits, original provenance metadata and strict scoring |
| `benchmarks/agentdojo/` | Equivalent AgentDojo records plus recovered-cell provenance |
| `docs/EVIDENCE_SHA256_MANIFEST.json` | Expected hash of every historical JSON record |
| `tools/verify_offline.py` | Full trace ZIP hash and aggregate verification |
| `tests/` | Unit and integration regression tests |
| `.github/workflows/` | Source tests and optional evidence-release verification |

## Appendix C. Native tool policy scope

EIP is installed ahead of native tool dispatch, but **interception does not imply full authorization coverage** for every tool. The adapter applies effect-specific checks to a defined set of consequential function names. `tests/integration/test_tool_coverage.py` compares recognized categories with the installed benchmark's suite tool declarations so newly added functions require review.

This reference version adds explicit checks for `append_to_file` and `reschedule_calendar_event`, with tests for authorized and unauthorized calls. These changes postdate the historical evaluations. They must not be credited with the archived EIP scores.

The following native function names are acknowledged but **not comprehensively covered by the current effect-specific EIP policy**, depending on suite:

`cart_remove_product`, `clear_cart`, `create_dir`, `download_file_through_id`, `git_clone`, `git_delete_ssh_key`, `git_pull`, `login_github_account`, `login_shopping_account`, `verify_github_account`, `verify_shopping_account`, `verify_transaction`.

Some of these are workflow steps, local mutations or authentication-related actions. A production implementation should classify each tool using explicit semantics and supported argument checks before claiming broad coverage. An unrecognized tool is not automatically made safe by passing through the decision element. Neither a blanket unknown-tool denial policy nor universal effect coverage is claimed in the measured implementation.

## Appendix D. Historical evidence and license scope

The per-file manifest and audit CSVs are part of this repository; complete trajectories are separate evidence assets. AgentDyn's `InjectionTask4` includes an intentional synthetic OpenSSH private-key marker in the benchmark attack text. Its appearance in trace records is not evidence of leakage of a real credential. Other recorded third-party trajectories and contact fields require normal privacy and redistribution review before publication.

The MIT license in `LICENSE` covers EIP-authored implementation, tests, scorers and documentation, **not automatically the third-party benchmark fixtures, Native/DRIFT trajectories or model-generated records**. The separate `LICENSE_SCOPE.md` states the relevant boundary. A redacted evidence edition would require a distinctly identified archive and a separately recomputed manifest; it cannot be substituted silently for the original hash-verified records.

## References

[1] E. Debenedetti et al., “AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents,” 2024. Project: https://github.com/ethz-spylab/agentdojo ; results guidance: https://agentdojo.spylab.ai/results/ .

[2] SaFo-Lab, “AgentDyn: Dynamic Evaluation of Agent Defenses,” repository and source, https://github.com/SaFo-Lab/AgentDyn (accessed 8 Nov. 2026).

[3] E. Debenedetti et al., “Defeating Prompt Injections by Design” (CaMeL), arXiv:2503.18813, 2025; 2026 IEEE SaTML publication DOI: 10.1109/SaTML68715.2026.00040. https://arxiv.org/abs/2503.18813 .

[4] M. Costa et al., “Securing AI Agents with Information-Flow Control” (FIDES), Microsoft Research, 2025. https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/ .

[5] Microsoft, “Agent Security with FIDES,” Agent Framework documentation, 2026. https://learn.microsoft.com/en-us/agent-framework/agents/security .

[6] X. Zheng et al., “APEX: Active Protection at Execution Boundaries for LLM Agents,” arXiv:2610.06966, 2026. https://arxiv.org/abs/2610.06966 .

[7] E. Zverev et al., “SPIDES: Information-Flow Control for Browser Agents,” Microsoft Research, Oct. 2026. https://www.microsoft.com/en-us/research/publication/spides-information-flow-control-for-browser-agents/ .

[8] EIP reference artifact, `README.md`, `docs/TECHNICAL.md`, `docs/EVIDENCE_SHA256_MANIFEST.json`, and `tools/verify_offline.py`, 2026.

