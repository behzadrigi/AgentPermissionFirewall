# Agent Permission Firewall

A GenLayer Intelligent Contract that acts as a permission and spending firewall for autonomous AI agents. Instead of relying on a single deterministic check, high-risk action requests are evaluated through GenLayer's Equivalence Principle: multiple validators independently query an LLM and must agree on the decision before it is bound to on-chain state.

## Why This Exists

Autonomous agents that spend funds or trigger actions on behalf of a user need a policy layer that can reason about intent, not just check numeric limits. A single AI call is not trustworthy on its own — it can hallucinate, be prompt-injected, or simply disagree from run to run. This contract uses GenLayer's decentralized validator consensus so that no single model's opinion can unilaterally approve a risky action.

## Contract Lifecycle

```
register_agent → set_policy → add_allowed_action → submit_action → evaluate_action_consensus → record_execution
```

## State Design

| Storage | Purpose |
|---|---|
| `admin` | Address allowed to manage agents, policies, and allowed actions |
| `agents` | Registered agent IDs |
| `policies` | Per-agent spending limit, human-review flag, and policy version |
| `allowed_actions` | Whitelist of `agent_id:action` pairs an agent may request |
| `actions` | Submitted action requests (agent, action type, amount) |
| `action_status` | Current lifecycle state of each action (`SUBMITTED`, `APPROVED`, `REJECTED`, `EXECUTED`) |
| `decisions` | Final AI consensus result and reasoning per action |

## Methods

### Admin — Setup

- **`register_agent(agent_id: str)`**
  Registers a new agent. Admin only.

- **`set_policy(agent_id: str, max_spending: u256, requires_human_review: bool, version: u32)`**
  Sets the spending limit and policy version for an agent. Admin only.

- **`add_allowed_action(agent_id: str, action: str)`**
  Whitelists a specific action type for an agent. Actions not on this list are rejected at submission time.

### Agent — Action Lifecycle

- **`submit_action(action_id: str, agent_id: str, action: str, amount: u256, scope_id: str)`**
  Submits a new action request. Deterministically enforces:
  - the agent is registered and has a policy
  - `amount <= policy.max_spending`
  - the action is on the agent's allowed-actions whitelist

  Sets status to `SUBMITTED`.

- **`evaluate_action_consensus(action_id: str)`**
  The core consensus step. Guards against double-evaluation (an action can only be evaluated once — status must be `SUBMITTED`). Uses GenLayer's leader/validator pattern:

  1. The **leader** sends the action details to an LLM and asks it to return a structured `{"decision": "APPROVED"|"REJECTED", "reasoning": "..."}` verdict, checking for spending-limit compliance, policy violations, and prompt-injection patterns.
  2. Each **validator** independently re-runs the same LLM evaluation from scratch — it does **not** just check the shape of the leader's answer.
  3. Validators compare only the `decision` field against their own independent result (the `reasoning` text is expected to vary between runs and is not compared).
  4. The result is only bound to contract state once a majority of validators agree. If they don't, GenLayer rotates to a new leader and retries.

  Sets status to `APPROVED` or `REJECTED` based on the agreed decision.

- **`record_execution(action_id: str, proof: str)`**
  Marks an `APPROVED` action as `EXECUTED`. Admin only. Fails if the action was never approved.

### Read-Only

- **`get_action_status(action_id: str) -> str`** — current lifecycle status, or `NOT_FOUND`.
- **`get_decision(action_id: str) -> str`** — final AI consensus result, or `NOT_FOUND`.

## Why This Is Real Consensus (Not a Format Check)

A common anti-pattern is a validator that only checks that the leader's output *looks* valid (correct JSON shape, allowed enum value) without verifying the *substance* of the decision. This contract avoids that: every validator re-executes the same LLM evaluation independently and the leader's result is only accepted if the objective `decision` field matches across a majority of validators. A validator here can genuinely disagree with the leader and force a rotation — the leader does not decide alone.

## Security Properties

- **No re-evaluation / result-shopping**: once an action has been evaluated, `evaluate_action_consensus` cannot be called again on it, preventing repeated attempts to "roll" a REJECTED into an APPROVED.
- **Whitelisted actions only**: an agent can only request action types explicitly allowed by the admin.
- **Hard spending ceiling**: enforced deterministically at submission time, before any AI evaluation runs.
- **Execution requires approval**: `record_execution` cannot mark an action executed unless consensus produced `APPROVED`.

## On-Chain Test Evidence

Full lifecycle tested end-to-end on GenLayer Studio (`explorer-studio.genlayer.com`):

| Step | Method | Result | Transaction Hash |
|---|---|---|---|
| 1 | Deploy | SUCCESS | `0x667e816e34194093077a446bd542a6877248016404a8df37fb54040702746302` |
| 2 | `register_agent` | SUCCESS | `0x737cfb426cb87cbad72e9f55a01138124d1826cf05a1de713c00f174fced805d` |
| 3 | `set_policy` | SUCCESS | `0x081ffea2558b72e478a0634fe4eef117cba90e6cc19dbb7ceb9f448216d09da1` |
| 4 | `add_allowed_action` | SUCCESS | `0x0d8d7f4b9c68a8a469396b368b9cff7a81bf4f679223c86e999dd7a37c200dc5` |
| 5 | `submit_action` | SUCCESS | `0xc914ad541d5c2cdef59b95bc3e8d3d27498c12b49eebfb885975ad0ee3fc438b` |
| 6 | `evaluate_action_consensus` (1st call) | **APPROVED** — leader rotated once after an initial malformed LLM response, then reached quorum | `0x0e446d05f9558ee83aea3f3bf6e8b7c4a65b3c2674016c1d03c96c54f4cad502` |
| 7 | `evaluate_action_consensus` (2nd call, same action) | Correctly reverted — `AssertionError: Action has already been evaluated` | `0x8f040f6c0bc1977f58d837813b118d252569a88fe5e0c95d8adcbbf527e96166` |
| 8 | `record_execution` | SUCCESS — status became `EXECUTED` | `0x6bdf6faa9e7339460b26ad661bb50fb7f123e73fb35ed2224d82d9162bccb575` |

Each transaction can be inspected at `https://explorer-studio.genlayer.com/tx/{hash}` to see the full consensus history, including individual validator agreement/disagreement and leader rotation.
