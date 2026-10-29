"""Collect selected NSX objects through the Salt VCF extension."""
import json
import os
from pathlib import Path


def snapshot(output_dir, profile=None, domain="default"):
    """Write native extension results locally; coverage is deliberately partial."""
    if domain != "default":
        raise ValueError("The VCF group list module supports the default domain only")
    required = ("vcf_nsx_security_policy.list_", "vcf_nsx_firewall_rule.list_",
                "vcf_nsx_group.list_", "vcf_nsx_service.list_")
    missing = [name for name in required if name not in __salt__]
    if missing:
        raise RuntimeError("Missing Salt VCF extension functions: " + ", ".join(missing))

    def checked(name, result):
        if not isinstance(result, dict) or not isinstance(result.get("results"), list):
            raise RuntimeError("Unexpected VCF extension response for " + name)
        if result.get("cursor"):
            raise RuntimeError("Incomplete paginated VCF extension response for " + name)
        return result

    policies = checked("policies", __salt__[required[0]](domain=domain, profile=profile))
    groups = checked("groups", __salt__[required[2]](profile=profile))
    services = checked("services", __salt__[required[3]](profile=profile))
    rules = {}
    for policy in policies["results"]:
        policy_id = policy.get("id") if isinstance(policy, dict) else None
        if not policy_id:
            raise RuntimeError("Security policy is missing its id")
        rules[policy_id] = checked("rules", __salt__[required[1]](policy=policy_id, domain=domain, profile=profile))
    data = {"policies": policies, "groups": groups, "services": services, "rules": rules}
    directory = Path(output_dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    for name, value in data.items():
        target = directory / (name + ".json")
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output)
        os.chmod(target, 0o600)
    return {"coverage": "partial", "policies": len(policies["results"]),
            "output_dir": str(directory)}
