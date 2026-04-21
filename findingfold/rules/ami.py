"""Group findings by source AMI.

Depends on Resources[].Details.AwsEc2Instance.ImageId being populated.
Run enrich.py before fold to backfill missing AMI IDs via describe-instances.
"""

from . import BaseRule


class AmiRule(BaseRule):
    name = "ami"

    def match(self, finding: dict):
        for r in finding.get("Resources", []):
            image_id = (r.get("Details", {}).get("AwsEc2Instance", {}).get("ImageId")
                        or r.get("Details", {}).get("AwsEcrContainerImage", {}).get("ImageDigest"))
            if not image_id:
                # Check enrichment tag
                for tag in r.get("Tags", {}).items() if isinstance(r.get("Tags"), dict) else []:
                    if tag[0] == "_findingfold_ami":
                        image_id = tag[1]
                        break
            if image_id:
                title = finding.get("Title", "unknown finding")
                key = f"ami:{image_id}:{title}"
                return {
                    "key": key,
                    "root_cause": f"AMI {image_id} — {title}",
                    "fix_target": image_id,
                    "recommendation": f"Rebuild AMI {image_id} with patched packages, then rotate instances",
                    "reason": f"ImageId={image_id}",
                }
        return None
