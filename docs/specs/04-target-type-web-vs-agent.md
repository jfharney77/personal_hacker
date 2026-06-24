# Spec 04 — Target type: web application vs. agent

**Status:** draft (starting point — see Open questions at the end)
**Surfaces touched:** engine (`Scope`, `graph`, modules), backend (`Target`, API), frontend (Targets form)
**Effort:** ~1 medium feature — data model + routing + an expanded agent suite + UI.

## Context

The engine already splits cleanly into two attack surfaces: **web** modules (credentials,
sessions, dos, dbinjection, accesscontrol, inputabuse, misconfig, supplychain) and the
**LLM** module (promptinjection). Today every scan runs everything against an HTTP target.
But "scan my web app" and "scan my agent" are different intents with different connection
shapes and different threat models — and an agent is often *not* a CRUD API with an OpenAPI
schema. This adds a first-class **target type** the user picks in the UI, which selects the
right module suite and the right way to talk to the target.

```
target_type = "web"    → web module suite, HTTP/OpenAPI recon (today's behavior)
target_type = "agent"  → agent module suite, conversational recon (prompt in → reply out)
```

## Data model

### Engine — `hacker/config.py`
- Add `Scope.target_type: Literal["web", "agent"] = "web"`.
- Add an optional `AgentConfig` (parallels `AuthConfig`) describing how to converse with the
  agent, since an agent endpoint rarely matches the OpenAPI/query-param assumptions:
  ```python
  class AgentConfig(BaseModel):
      endpoint: str                 # chat/completions URL (must be on the allowlist)
      method: str = "POST"
      # How to send a prompt: a JSON body template with {prompt} substituted, OR a field name.
      prompt_field: str = "message"
      body_template: dict | None = None     # e.g. {"messages":[{"role":"user","content":"{prompt}"}]}
      # How to read the reply out of the JSON response (dotted path), e.g. "reply" or
      # "choices.0.message.content".
      reply_json_path: str = "reply"
      # Optional: declared tools/functions the agent can call (names), so the suite can probe
      # tool abuse without us having to discover them.
      tools: list[str] = []
      # Optional: a secret/canary the agent's system prompt is told to protect, for scoring leaks.
      system_prompt_canary: str | None = None
  ```
- `Scope.validate_self()`: when `target_type == "agent"`, require `agent` config and that its
  `endpoint` host is on the allowlist (reuse the existing host-allowlist guard).

### Backend — `backend/models.py`
- `Target.target_type: str = "web"` (indexed).
- `Target.agent: dict | None` (JSON column, shaped like `AgentConfig`), mirroring how
  `Target.auth` already stores `AuthConfig`.
- `backend/services.py: target_to_scope()` passes `target_type` and builds `AgentConfig`
  from `target.agent` when present.

## Module routing — `hacker/graph.py` + `hacker/modules/__init__.py`

Define explicit suites instead of running all modules unconditionally:
```python
WEB_MODULES   = [credentials, sessions, dos, dbinjection, accesscontrol,
                 inputabuse, misconfig, supplychain]
AGENT_MODULES = [promptinjection, agentabuse]   # agentabuse is new (below)
```
`run_scan` dispatches on `scope.target_type`:
- **web** → today's flow (HTTP recon → web modules). Unchanged.
- **agent** → skip OpenAPI/HTML recon; instead do **conversational recon** (one benign
  prompt to confirm reachability and capture the reply shape), then run the agent suite.

Static (SAST) analysis still runs for either type when `repo_path` is set — an agent's
source can still leak secrets / have vulnerable deps, so the supply-chain and credentials
*static* checks remain useful for agents too. (Decision flagged in Open questions.)

## Agent attack suite

Keep `promptinjection.py` as the core (direct injection, system-prompt exfil, jailbreak,
delimiter escape — already implemented), but drive it through `AgentConfig` instead of
sniffing `recon.llm_endpoints()`. Add a new module **`hacker/modules/agentabuse.py`** with a
new `ThreatClass.AGENT_ABUSE = "agent_abuse"` covering agentic risks beyond pure injection,
mapped to the OWASP LLM/agent Top-10:

- **Tool / function abuse** — try to get the agent to call a sensitive declared tool, or to
  reveal its tool schema. *Safe-mode rule:* never actually trigger a destructive tool;
  detect **willingness** (the agent says it will / emits the tool call) rather than executing.
- **Excessive agency** — ask it to perform an out-of-scope action (delete, email, pay) and
  flag if it complies instead of refusing.
- **Indirect / stored injection** — plant an instruction in data the agent will later read
  (if the web app pairing allows) and see if it's obeyed in a later turn.
- **Sensitive-info / context disclosure** — attempt to extract the system prompt, prior-turn
  content, or other users' data.
- **Denial of wallet** — a prompt designed to elicit an unbounded/maximal generation; report
  if there's no output cap (ties to the existing DoS thinking, agent-flavored).

Each check uses the existing pluggable **LLM judge** (`hacker/llm.py`) to score whether the
agent leaked/obeyed, with the heuristic-judge fallback so it works offline.

## Frontend — `frontend/src/pages/Targets.jsx`

- Add a **Target type** selector at the top of the add-target form: `Web application | Agent`.
- Conditionally render fields:
  - **Web** → today's fields (target URLs, repo path, allowlist, safe-mode toggles).
  - **Agent** → agent endpoint URL, prompt field / body template, reply JSON path, optional
    tool names, optional system-prompt canary; plus allowlist + repo path (still useful).
- Show a small **type badge** (`web` / `agent`) on each target card and on ScanDetail, so it's
  obvious which suite produced a report.
- `frontend/src/api.js` passes `target_type` + `agent` through unchanged (already generic).

## Tests

- Engine: a fixture **agent app** (tiny FastAPI `/chat` that leaks its system prompt and has a
  fake `delete_account` tool it will "call") + a hardened agent that refuses. Assert the agent
  suite fires AGENT_ABUSE/PROMPT_INJECTION on the vulnerable one and nothing High on the
  hardened one (the established vulnerable/hardened fixture pattern).
- Routing: `target_type="web"` runs zero agent modules and vice versa (no cross-firing).
- Backend: create an agent-type target via the API, run a scan, assert findings persist with
  the agent threat classes; web targets unchanged.
- Determinism: drive the fixture agent in-process via `TestClient`; use the heuristic judge
  (no real LLM) so tests need no network/keys.

## Safety

- Agent endpoint still goes through `Scope.guard()` (host allowlist; non-local needs
  `i_own_this`).
- **Tool-abuse and excessive-agency checks must be non-destructive in safe mode** — detect the
  agent's *willingness* to act (it emits the tool call / agrees), never let it actually execute
  a destructive tool. This is the agent analog of the "no destructive writes" web rule.
- Denial-of-wallet probe sends a single crafted prompt, not a flood.

## Open questions (decide before building)

1. **Agent transport:** which shapes to support first — a generic JSON chat endpoint (assumed
   here), an OpenAI-compatible `/chat/completions`, and/or an in-process LangGraph agent? The
   `body_template` + `reply_json_path` design covers the first two; in-process would need a
   different adapter.
2. **Shared modules:** should an agent that's also a web service optionally run *both* suites
   (e.g. agent suite + credentials/dos)? Proposal: keep them separate for v1; add a "also run
   web checks" toggle later.
3. **Static analysis for agents:** run SAST (secrets, deps) on an agent's repo too? Proposed
   yes — it's cheap and orthogonal — but worth confirming.
4. **New module vs. expand:** put agentic risks in a new `agentabuse.py` (proposed) or grow
   `promptinjection.py`? New module keeps threat-class reporting clean.
