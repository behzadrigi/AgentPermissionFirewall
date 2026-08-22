# AgentPermissionFirewall

A GenLayer Intelligent Contract that serves as a security firewall for Autonomous AI Agents. It enforces spending limits, permission scopes, allowed actions, and rate limits, with AI-powered consensus evaluation.

## Features & Methods

### 1. Agent Management
* `register_agent`: Registers a new AI agent with owner address, max spending limit, allowed actions list, and assigned permission scopes.
* `get_agent`: Read method returning current status (`ACTIVE`, `SUSPENDED`, etc.) and metrics.

### 2. Access Control & Scopes
* `create_scope`: Defines new permission scopes with risk levels (e.g., LOW, MEDIUM, HIGH).
* `set_rate_limit`: Restricts the maximum number of requests/actions allowed per agent.

### 3. Execution & AI Validation
* `submit_action`: Allows agents to submit action requests (e.g., `SWAP`, `TRANSFER`). Enforces automatic security assertions on max spending and allowed action types.
* `evaluate_action`: Triggered for AI consensus verification on action parameters.
* `security_validate_action`: Executes final security checks before completing the execution lifecycle.

## Testing & Verification
All contract methods, including happy paths and boundary test cases (unauthorized action blocking and spending limit assertions), have been successfully tested and verified on the GenLayer Testnet.
