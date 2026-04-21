"""Enrich findings with data not present in the finding itself.

Run BEFORE fold to improve grouping accuracy.

Primary use case: backfill AMI IDs for EC2 findings that don't include
Resources[].Details.AwsEc2Instance.ImageId (common with Config rule findings).

Requires boto3 and appropriate IAM permissions (ec2:DescribeInstances).
"""


def enrich_ami_ids(findings: list[dict], region: str = None) -> list[dict]:
    """Backfill AMI IDs for EC2 instance findings missing ImageId.

    Calls describe-instances for instances that lack AMI info.
    Adds _findingfold_ami tag to the resource for the AMI rule to pick up.
    """
    try:
        import boto3
    except ImportError:
        return findings  # Silently skip enrichment without boto3

    # Collect instance IDs that need AMI lookup
    needs_ami = {}  # instance_id → list of (finding_idx, resource_idx)
    for fi, f in enumerate(findings):
        for ri, r in enumerate(f.get("Resources", [])):
            if r.get("Type") != "AwsEc2Instance":
                continue
            ec2 = r.get("Details", {}).get("AwsEc2Instance", {})
            if ec2.get("ImageId"):
                continue
            iid = r.get("Id", "")
            # Extract instance ID from ARN or direct ID
            if iid.startswith("arn:"):
                parts = iid.split("/")
                iid = parts[-1] if parts else iid
            if iid.startswith("i-"):
                needs_ami.setdefault(iid, []).append((fi, ri))

    if not needs_ami:
        return findings

    # Batch describe-instances
    client = boto3.client("ec2", region_name=region) if region else boto3.client("ec2")
    instance_ids = list(needs_ami.keys())

    ami_map = {}
    for i in range(0, len(instance_ids), 100):
        batch = instance_ids[i:i + 100]
        try:
            resp = client.describe_instances(InstanceIds=batch)
            for res in resp.get("Reservations", []):
                for inst in res.get("Instances", []):
                    ami_map[inst["InstanceId"]] = inst.get("ImageId", "")
        except Exception:
            continue  # Skip batch on error, don't fail the whole run

    # Backfill
    for iid, ami_id in ami_map.items():
        if not ami_id:
            continue
        for fi, ri in needs_ami.get(iid, []):
            r = findings[fi]["Resources"][ri]
            tags = r.get("Tags", {})
            if isinstance(tags, dict):
                tags["_findingfold_ami"] = ami_id
            else:
                tags.append({"Key": "_findingfold_ami", "Value": ami_id})
            r["Tags"] = tags

    return findings
