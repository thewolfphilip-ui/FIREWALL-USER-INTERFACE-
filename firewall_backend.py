"VILA CODE"
import ipaddress
import subprocess
import json


def run_nft(command):
    result = subprocess.run(
        ["nft", *command],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    return result.stdout


def get_input_chains():
    ruleset = json.loads(run_nft(["-j", "list", "ruleset"]))

    chains = []

    for item in ruleset.get("nftables", []):
        chain = item.get("chain")

        if not chain:
            continue

        if chain.get("hook") == "input":
            chains.append({
                "family": chain["family"],
                "table": chain["table"],
                "name": chain["name"],
                "policy": chain.get("policy", "unknown")
            })

    return chains


def get_default_policy():
    chains = get_input_chains()

    if not chains:
        raise RuntimeError("No input base chains found")

    return chains


if __name__ == "__main__":
    try:
        for chain in get_default_policy():
            print(
                f'{chain["family"]} '
                f'{chain["table"]} '
                f'{chain["name"]}: '
                f'{chain["policy"]}'
            )

    except RuntimeError as error:
        print("Firewall error:", error)

def set_default_policy(policy):

    policies = {
        "allow": "accept",
        "deny": "drop"
    }

    if policy not in policies:
        raise ValueError("Invalid policy")

    run_nft([
        "chain",
        "inet",
        "filter",
        "input",
        "{",
        "policy",
        policies[policy],
        ";",
        "}"
    ])

    return get_default_policy()

def add_firewall_rule(protocol, action, port=None):

    # Validate protocol
    allowed_protocols = ["tcp", "udp", "icmp"]

    if protocol not in allowed_protocols:
        raise ValueError("Invalid protocol")

    # Validate action
    actions = {
        "allow": "accept",
        "block": "drop"
    }

    if action not in actions:
        raise ValueError("Invalid action")

    command = [
        "add",
        "rule",
        "inet",
        "filter",
        "input"
    ]

    # Add port condition for TCP or UDP
    if port is not None:

        if protocol not in ["tcp", "udp"]:
            raise ValueError("Ports are only supported for TCP and UDP")

        port = int(port)

        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535")

        command.extend([
            protocol,
            "dport",
            str(port)
        ])

    else:
        command.extend([
            "meta",
            "l4proto",
            protocol
        ])

    command.append(actions[action])

    run_nft(command)

    return "Firewall rule added successfully"


def get_firewall_rules():

    ruleset = json.loads(
        run_nft(["-j", "list", "ruleset"])
    )

    rules = []

    for item in ruleset.get("nftables", []):

        rule = item.get("rule")

        if rule is None:
            continue

        if (
            rule.get("family") == "inet"
            and rule.get("table") == "filter"
            and rule.get("chain") == "input"
        ):
            rules.append(rule)

    return rules


def delete_firewall_rule(handle):

    try:
        handle = int(handle)
    except (ValueError, TypeError):
        raise ValueError("Invalid rule handle")

    if handle <= 0:
        raise ValueError("Invalid rule handle")

    run_nft([
        "delete",
        "rule",
        "inet",
        "filter",
        "input",
        "handle",
        str(handle)
    ])

    return "Firewall rule deleted successfully"



