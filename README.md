# Agent Permission Firewall

A GenLayer Intelligent Contract that acts as a permission and spending firewall for autonomous AI agents. Instead of relying on a single deterministic check, high-risk action requests are evaluated through GenLayer's Equivalence Principle: multiple validators independently query an LLM and must agree on the decision before it is bound to on-chain state.

## Why This Exists

Autonomous agents that spend funds or trigger actions on behalf of a user need a policy layer that can reason about intent, not just check numeric limits. A single AI call is not trustworthy on its own — it can hallucinate, be prompt-injected, or simply disagree from run to run. This contract uses GenLayer's decentralized validator consensus so that no single model's opinion can unilaterally approve a risky action. It also enforces that only the authorized address bound to an agent can act on its behalf, and gives policies an explicit human-approval gate for higher-risk agents.

## Contract Lifecycle

```
register_agent → set_policy → add_allowed_action → submit_action → evaluate_action_consensus → [approve_human_review, if required] → record_execution
```

## State Design

| Storage | Purpose |
|---|---|
| `admin` | Address allowed to manage agents, policies, allowed actions, human review approvals, and execution recording |
| `agents` | Registered agents: `agent_id -> { owner address, active }` |
| `policies` | Per-agent spending limit, human-review flag, and policy version |
| `allowed_actions` | Whitelist of `agent_id:action` pairs an agent may request |
| `actions` | Submitted action requests (agent, action type, amount, scope) |
| `action_status` | Current lifecycle state of each action (`SUBMITTED`, `APPROVED`, `REJECTED`, `EXECUTED`) |
| `decisions` | Final AI consensus result and reasoning per action |
| `human_reviews` | Explicit human approval record per action, when required by policy |
| `execution_proofs` | Persisted proof string submitted at execution time |

## Methods

### Admin — Setup

- **`register_agent(agent_id: str, owner: str)`**
  Registers a new agent and binds it to a single authorized submitting address (passed as a hex string and converted to `Address` internally). Only this address may submit actions under this `agent_id`. Admin only.

- **`set_policy(agent_id: str, max_spending: u256, requires_human_review: bool, version: u32)`**
  Sets the spending limit, human-review requirement, and policy version for an agent. Admin only.

- **`add_allowed_action(agent_id: str, action: str)`**
  Whitelists a specific action type for an agent. Actions not on this list are rejected at submission time.

### Agent — Action Lifecycle

- **`submit_action(action_id: str, agent_id: str, action: str, amount: u256, scope_id: str)`**
  Submits a new action request. Must be called by the address bound to `agent_id` at registration — no other address may submit on that agent's behalf. Deterministically enforces:
  - the agent is registered, active, and the caller is its authorized owner
  - `amount <= policy.max_spending`
  - the action is on the agent's allowed-actions whitelist

  Sets status to `SUBMITTED`.

- **`evaluate_action_consensus(action_id: str)`**
  The core consensus step. Guards against double-evaluation (an action can only be evaluated once — status must be `SUBMITTED`). Uses GenLayer's leader/validator pattern:

  1. The **leader** sends the action details — including the requested amount, spending limit, and permission scope — to an LLM and asks it to return a structured `{"decision": "APPROVED"|"REJECTED", "reasoning": "..."}` verdict.
  2. Each **validator** independently re-runs the same LLM evaluation from scratch — it does **not** just check the shape of the leader's answer.
  3. Validators compare only the `decision` field against their own independent result (the `reasoning` text is expected to vary between runs and is not compared).
  4. The result is only bound to contract state once a majority of validators agree. If they don't, GenLayer rotates to a new leader and retries.

  Sets status to `APPROVED` or `REJECTED` based on the agreed decision.

- **`approve_human_review(action_id: str)`**
  Explicit human-approval step, required before execution for any agent whose policy has `requires_human_review = True` — even after AI consensus already returned `APPROVED`. Admin only. Fails if the action was not AI-approved or if the agent's policy does not require human review.

- **`record_execution(action_id: str, proof: str)`**
  Marks an `APPROVED` action as `EXECUTED` and persists the given proof string. Admin only. Fails if:
  - the action was never AI-approved, or
  - the agent's policy requires human review and `approve_human_review` has not yet been called for this action.

### Read-Only

- **`get_action_status(action_id: str) -> str`** — current lifecycle status, or `NOT_FOUND`.
- **`get_decision(action_id: str) -> str`** — final AI consensus result, or `NOT_FOUND`.
- **`get_execution_proof(action_id: str) -> str`** — persisted execution proof, or `NOT_FOUND`.
- **`is_human_reviewed(action_id: str) -> bool`** — whether an explicit human approval has been recorded.

## Why This Is Real Consensus (Not a Format Check)

A common anti-pattern is a validator that only checks that the leader's output *looks* valid (correct JSON shape, allowed enum value) without verifying the *substance* of the decision. This contract avoids that: every validator re-executes the same LLM evaluation independently and the leader's result is only accepted if the objective `decision` field matches across a majority of validators. A validator here can genuinely disagree with the leader and force a rotation — the leader does not decide alone.

## Security Properties

- **Agent-to-address binding**: only the address registered as an agent's `owner` may submit actions under that agent's ID — no caller can act on behalf of an agent it doesn't control.
- **No re-evaluation / result-shopping**: once an action has been evaluated, `evaluate_action_consensus` cannot be called again on it, preventing repeated attempts to "roll" a REJECTED into an APPROVED.
- **Explicit human review gate**: when a policy requires human review, execution is blocked until an authorized approval is explicitly recorded on-chain, regardless of the AI consensus result.
- **Whitelisted actions only**: an agent can only request action types explicitly allowed by the admin.
- **Hard spending ceiling**: enforced deterministically at submission time, before any AI evaluation runs.
- **Execution requires approval**: `record_execution` cannot mark an action executed unless consensus produced `APPROVED`, and, when required, human review is also complete.
- **Persisted execution proof**: the proof supplied at execution time is stored on-chain and retrievable via `get_execution_proof`, not discarded.

## On-Chain Test Evidence

Full lifecycle tested end-to-end on GenLayer Studio (`explorer-studio.genlayer.com`), including both authorization fixes requested in the second review round:

| Step | Method | Result | Transaction Hash |
|---|---|---|---|
| 1 | Deploy | SUCCESS | `0x52c65a8c0fdba1b706ce7a619018711fd5e4a3b254a608ce156f0a107b773241` |
| 2 | `register_agent` (bound to owner address) | SUCCESS | `0xde3c32c4af76c406a7dff361033ca1d16457db7f2cb49b44ffa06ef9889ec948` |
| 3 | `set_policy` (`requires_human_review = true`) | SUCCESS | `0x860fdd0cee2099118d0ff69114120a2c5e1ca1658cdbd91151ac80256474b294` |
| 4 | `add_allowed_action` | SUCCESS | `0x0caa8e19408f74b33421bca239f483bbd3f5ca60920075426b9b8f8dfe02b654` |
| 5 | `submit_action` (called by the authorized owner address) | SUCCESS | `0x63ac56bb19663120a0b2cde811911097f366dbf3912f6e3eaed93f3c7b8061f8` |
| 6 | `submit_action` (called by an unauthorized address) | **Correctly reverted** — `AssertionError: Sender is not authorized to act as this agent` | `0xe85c0846b6036e80738e41a0e93f890fca3ce6f6f6ffec3122572baf2166e026` |
| 7 | `evaluate_action_consensus` | **APPROVED** — reasoning explicitly referenced the permission scope | `0xd75663422ea479e288270cd8a4ef73be53b16c23ae00eb2c2e75e45394d55274` |
| 8 | `record_execution` (attempted before human review) | **Correctly reverted** — `AssertionError: Execution blocked: pending human review` | `0xc666b5b74d314760b18f2943a47ddc73fd8fc78f4f6797b675e16f16903ed52b` |
| 9 | `approve_human_review` | SUCCESS | `0x40b3fee9c428fa2b2f2e59c2672e6fcd95d9e198522b9343deb7e4b5ed89bcfa` |
| 10 | `record_execution` (after human review) | SUCCESS — status became `EXECUTED` | `0xfeeb3dcf7353a3d6aeeb37316f99ff86bb563c9e4a9ba4fd34f4c88f6578c24f` |

Each transaction can be inspected at `https://explorer-studio.genlayer.com/tx/{hash}` to see the full consensus history, including individual validator agreement/disagreement and leader rotation.
