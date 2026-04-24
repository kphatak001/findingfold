"""LLM-powered false positive filter for security findings.

Runs BEFORE fold. Sends findings in batches to an LLM that classifies
each as likely-true-positive or likely-false-positive based on:
- Finding title + severity + generator
- Resource context (type, tags, config)
- Common FP patterns (test accounts, dev resources, suppressed-but-active)

Based on: "Sifting the Noise: A Comparative Study of LLM Agents in
Vulnerability False Positive Filtering" (arXiv 2604)

Usage:
  findingfold findings.json --filter-fp
  findingfold findings.json --filter-fp --fp-backend openai
"""

from __future__ import annotations
import json
import os
import re
import sys

BATCH_SIZE = 20  # findings per LLM call

SYSTEM_PROMPT = """You are a security finding triage expert. For each finding, determine if it is likely a FALSE POSITIVE based on these signals:

- Resource is in a test/dev/sandbox account or has dev/test/staging tags
- Finding is informational with no actionable remediation
- Resource no longer exists (terminated instance, deleted bucket)
- Finding is a duplicate of another finding with different ID
- Config rule finding on a resource that is compliant by design (e.g., S3 bucket with SSE-S3 flagged for missing SSE-KMS)
- GuardDuty finding with very low severity on expected traffic patterns

For each finding, respond with ONLY a JSON array of objects:
[{"id": "<finding_id>", "fp": true/false, "reason": "brief reason"}]

Be conservative: when in doubt, mark as TRUE POSITIVE (fp: false). Only mark fp: true when you have high confidence."""


def filter_false_positives(
    findings: list[dict],
    backend: str | None = None,
    verbose: bool = False,
) -> tuple[list[dict], list[dict]]:
    """Filter likely false positives from findings.

    Returns (kept, removed) tuple.
    """
    call_llm = _get_backend(backend)
    kept, removed = [], []

    for i in range(0, len(findings), BATCH_SIZE):
        batch = findings[i:i + BATCH_SIZE]
        summaries = [_summarize_finding(f) for f in batch]
        prompt = f"Classify these {len(batch)} security findings:\n\n" + json.dumps(summaries, indent=2)

        try:
            results = call_llm(prompt)
            fp_ids = {r["id"] for r in results if r.get("fp")}
            if verbose and fp_ids:
                reasons = {r["id"]: r.get("reason", "") for r in results if r.get("fp")}
                for fid, reason in reasons.items():
                    sys.stderr.write(f"  [FP] {fid}: {reason}\n")
        except Exception as e:
            sys.stderr.write(f"  ⚠️  FP filter batch error: {e}\n")
            fp_ids = set()

        for f in batch:
            if f.get("Id", "") in fp_ids:
                removed.append(f)
            else:
                kept.append(f)

    return kept, removed


def _summarize_finding(f: dict) -> dict:
    """Extract the fields an LLM needs to judge FP likelihood."""
    resources = []
    for r in f.get("Resources", []):
        res = {"type": r.get("Type", ""), "id": r.get("Id", "")}
        tags = r.get("Tags", {})
        if isinstance(tags, dict) and tags:
            res["tags"] = {k: v for k, v in tags.items() if not k.startswith("_findingfold")}
        resources.append(res)
    return {
        "id": f.get("Id", ""),
        "title": f.get("Title", ""),
        "severity": f.get("Severity", {}).get("Label", ""),
        "generator": f.get("GeneratorId", ""),
        "workflow_status": f.get("Workflow", {}).get("Status", ""),
        "resources": resources,
    }


def _parse_llm_json(text: str) -> list[dict]:
    """Extract JSON array from LLM response."""
    m = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL)
    if m:
        return json.loads(m.group(1))
    m = re.search(r"\[.*\]", text, re.DOTALL)
    if m:
        return json.loads(m.group(0))
    raise ValueError(f"No JSON array in response: {text[:200]}")


def _get_backend(backend: str | None):
    """Return a callable(prompt) -> list[dict] for the chosen LLM backend."""
    if backend == "anthropic" or (backend is None and os.environ.get("ANTHROPIC_API_KEY")):
        import anthropic
        client = anthropic.Anthropic()
        def call(prompt):
            resp = client.messages.create(
                model="claude-sonnet-4-20250514", max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            return _parse_llm_json(resp.content[0].text)
        return call

    if backend == "openai" or (backend is None and os.environ.get("OPENAI_API_KEY")):
        import openai
        client = openai.OpenAI()
        def call(prompt):
            resp = client.chat.completions.create(
                model="gpt-4o", max_tokens=4096,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )
            return _parse_llm_json(resp.choices[0].message.content)
        return call

    raise RuntimeError(
        "No LLM backend for --filter-fp. Set ANTHROPIC_API_KEY or OPENAI_API_KEY, "
        "or use --fp-backend anthropic|openai"
    )
