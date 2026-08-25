"""
Integration tests for AgentPermissionFirewall.

Run with:
    gltest --network studionet
    (or --network localnet / testnet_asimov)

These tests exercise the full action lifecycle:
register_agent -> set_policy -> add_allowed_action -> submit_action
-> evaluate_action_consensus -> record_execution

and verify the two properties that were the subject of the previous
review round:
  1. evaluate_action_consensus uses real leader/validator consensus
     (exercised indirectly: a SUCCESS result here can only happen if
     a majority of independent validators agreed on the decision).
  2. An action cannot be evaluated more than once (re-evaluation guard).
"""

from pathlib import Path

import pytest
from gltest import get_contract_factory
from gltest.assertions import tx_execution_succeeded, tx_execution_failed

CONTRACTS_DIR = Path(__file__).parent / "contracts"
CONTRACT_FILE = CONTRACTS_DIR / "agent_permission_firewall.py"

AGENT_ID = "agent-1"
ACTION_NAME = "transfer_funds"
MAX_SPENDING = 1000
ALLOWED_AMOUNT = 500
OVER_LIMIT_AMOUNT = 5000


@pytest.fixture
def deployed_contract():
    """Deploys a fresh instance of the contract for each test."""
    factory = get_contract_factory(contract_file_path=CONTRACT_FILE)
    contract = factory.deploy(args=[])
    return contract


@pytest.fixture
def ready_contract(deployed_contract):
    """
    Deploys the contract and brings it to a state where an agent is
    registered, has a policy, and has one allowed action -- the
    common setup shared by most of the tests below.
    """
    contract = deployed_contract

    tx = contract.register_agent(args=[AGENT_ID]).transact()
    assert tx_execution_succeeded(tx)

    tx = contract.set_policy(
        args=[AGENT_ID, MAX_SPENDING, False, 1]
    ).transact()
    assert tx_execution_succeeded(tx)

    tx = contract.add_allowed_action(args=[AGENT_ID, ACTION_NAME]).transact()
    assert tx_execution_succeeded(tx)

    return contract


def test_register_agent(deployed_contract):
    tx = deployed_contract.register_agent(args=[AGENT_ID]).transact()
    assert tx_execution_succeeded(tx)


def test_set_policy_requires_registered_agent(deployed_contract):
    """set_policy must fail for an agent that was never registered."""
    tx = deployed_contract.set_policy(
        args=["unregistered-agent", MAX_SPENDING, False, 1]
    ).transact()
    assert tx_execution_failed(tx)


def test_submit_action_within_limits_succeeds(ready_contract):
    tx = ready_contract.submit_action(
        args=["action-1", AGENT_ID, ACTION_NAME, ALLOWED_AMOUNT, "scope-1"]
    ).transact()
    assert tx_execution_succeeded(tx)

    status = ready_contract.get_action_status(args=["action-1"]).call()
    assert status == "SUBMITTED"


def test_submit_action_over_spending_limit_fails(ready_contract):
    """
    The spending cap must be enforced deterministically before any AI
    evaluation runs -- an over-limit request should never even reach
    evaluate_action_consensus.
    """
    tx = ready_contract.submit_action(
        args=["action-over-limit", AGENT_ID, ACTION_NAME, OVER_LIMIT_AMOUNT, "scope-1"]
    ).transact()
    assert tx_execution_failed(tx)

    status = ready_contract.get_action_status(args=["action-over-limit"]).call()
    assert status == "NOT_FOUND"


def test_submit_action_with_non_allowed_action_fails(ready_contract):
    tx = ready_contract.submit_action(
        args=["action-bad-type", AGENT_ID, "not_whitelisted", ALLOWED_AMOUNT, "scope-1"]
    ).transact()
    assert tx_execution_failed(tx)


def test_evaluate_action_consensus_produces_a_decision(ready_contract):
    """
    End-to-end consensus test: submits a legitimate, in-policy action
    and confirms that after evaluation a majority-agreed decision
    (APPROVED or REJECTED) has been bound to contract state.
    """
    contract = ready_contract

    tx = contract.submit_action(
        args=["action-consensus", AGENT_ID, ACTION_NAME, ALLOWED_AMOUNT, "scope-1"]
    ).transact()
    assert tx_execution_succeeded(tx)

    tx = contract.evaluate_action_consensus(args=["action-consensus"]).transact()
    assert tx_execution_succeeded(tx)

    decision = contract.get_decision(args=["action-consensus"]).call()
    assert decision in ("APPROVED", "REJECTED")

    status = contract.get_action_status(args=["action-consensus"]).call()
    assert status == decision


def test_action_cannot_be_evaluated_twice(ready_contract):
    """
    Security regression test for the re-evaluation / result-shopping
    guard: once a decision has been reached, calling
    evaluate_action_consensus again on the same action_id must fail
    instead of allowing another AI evaluation attempt.
    """
    contract = ready_contract

    tx = contract.submit_action(
        args=["action-once", AGENT_ID, ACTION_NAME, ALLOWED_AMOUNT, "scope-1"]
    ).transact()
    assert tx_execution_succeeded(tx)

    tx = contract.evaluate_action_consensus(args=["action-once"]).transact()
    assert tx_execution_succeeded(tx)

    # Second attempt on the same action_id must be rejected.
    tx = contract.evaluate_action_consensus(args=["action-once"]).transact()
    assert tx_execution_failed(tx)


def test_record_execution_requires_prior_approval(ready_contract):
    """record_execution must fail for an action that was never approved."""
    contract = ready_contract

    tx = contract.submit_action(
        args=["action-no-decision", AGENT_ID, ACTION_NAME, ALLOWED_AMOUNT, "scope-1"]
    ).transact()
    assert tx_execution_succeeded(tx)

    # No evaluate_action_consensus call happened yet -> no Decision exists.
    tx = contract.record_execution(args=["action-no-decision", "proof-x"]).transact()
    assert tx_execution_failed(tx)


def test_get_action_status_not_found_for_unknown_action(deployed_contract):
    status = deployed_contract.get_action_status(args=["does-not-exist"]).call()
    assert status == "NOT_FOUND"


def test_get_decision_not_found_for_unknown_action(deployed_contract):
    decision = deployed_contract.get_decision(args=["does-not-exist"]).call()
    assert decision == "NOT_FOUND"
