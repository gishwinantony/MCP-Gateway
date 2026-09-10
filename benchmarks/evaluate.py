#!/usr/bin/env python3
"""Measure the two things the gateway claims to improve.

1. Retrieval quality: does search actually surface the right tool? Reported
   per retrieval leg so the hybrid design is justified by numbers rather than
   by assertion.
2. Context cost: how many tokens the tool list costs with and without
   dynamic retrieval.

Run from the repository root:  python benchmarks/evaluate.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from fake_mcp_server import bulk_tools

from mcpgateway.protocol import ToolDef
from mcpgateway.retrieval import ToolIndex, estimate_tokens

# Two query sets, kept separate because they measure different things.
#
# DIRECT: how a model usually phrases a call once it knows roughly what the
# integration is. Shares vocabulary with the tool definitions.
DIRECT_QUERIES: list[tuple[str, str]] = [
    ("refund a stripe invoice", "bulk__refund_invoice"),
    ("void an invoice in stripe", "bulk__void_invoice"),
    ("create an invoice for this customer", "bulk__create_invoice"),
    ("restart the api deployment", "bulk__restart_deployment"),
    ("scale the checkout deployment to more replicas", "bulk__scale_deployment"),
    ("roll back the deployment", "bulk__rollback_deployment"),
    ("get logs for the deployment", "bulk__get_logs_for_deployment"),
    ("create a jira issue for this bug", "bulk__create_issue"),
    ("close the jira issue", "bulk__close_issue"),
    ("assign the issue to someone", "bulk__assign_issue"),
    ("send a slack message to the channel", "bulk__send_message"),
    ("search slack messages", "bulk__search_message"),
    ("mute the datadog monitor", "bulk__mute_monitor"),
    ("trigger a pagerduty incident", "bulk__trigger_incident"),
    ("resolve the pagerduty incident", "bulk__resolve_incident"),
    ("upload an object to s3", "bulk__upload_object"),
    ("presign an s3 object url", "bulk__presign_object"),
    ("query a postgres table", "bulk__query_table"),
    ("send an email with sendgrid", "bulk__send_email"),
    ("vacuum a postgres table", "bulk__vacuum_table"),
]

# PARAPHRASE: intent expressed with deliberately no shared vocabulary. This is
# the case a lexical index cannot solve, and it is measured rather than hidden.
PARAPHRASE_QUERIES: list[tuple[str, str]] = [
    ("give the customer their money back", "bulk__refund_invoice"),
    ("cancel a bill issued by mistake", "bulk__void_invoice"),
    ("charge a customer for this month", "bulk__create_invoice"),
    ("the api pods are unhealthy, bounce them", "bulk__restart_deployment"),
    ("we need more capacity for checkout", "bulk__scale_deployment"),
    ("undo the last release", "bulk__rollback_deployment"),
    ("open a ticket for this bug", "bulk__create_issue"),
    ("mark the ticket as done", "bulk__close_issue"),
    ("post an update in the team channel", "bulk__send_message"),
    ("stop the alert from firing while we fix it", "bulk__mute_monitor"),
    ("declare an outage and wake the on-call engineer", "bulk__trigger_incident"),
    ("the outage is over", "bulk__resolve_incident"),
    ("put this file in cloud storage", "bulk__upload_object"),
    ("give me a temporary download link", "bulk__presign_object"),
    ("run a read query against the database", "bulk__query_table"),
    ("reclaim dead rows in the database", "bulk__vacuum_table"),
]


def recall_at(index: ToolIndex, k: int, leg: str, queries) -> float:
    hits = 0
    for query, expected in queries:
        if leg == "hybrid":
            results = [h.name for h in index.search(query, k=k)]
        else:
            pool = list(index._docs.values())
            ranked = (
                index._rank_bm25(query, pool)
                if leg == "bm25"
                else index._rank_vector(query, pool)
            )
            results = [name for name, _ in ranked[:k]]
        if expected in results:
            hits += 1
    return hits / len(queries)


def report(index: ToolIndex, label: str, queries) -> None:
    print(f"\n{label}  ({len(queries)} queries)")
    print(f"{'retrieval leg':<16} {'recall@1':>9} {'recall@3':>9} {'recall@5':>9}")
    print("-" * 46)
    for leg in ("bm25", "vector", "hybrid"):
        row = [recall_at(index, k, leg, queries) for k in (1, 3, 5)]
        print(f"{leg:<16} {row[0]:>8.0%} {row[1]:>8.0%} {row[2]:>8.0%}")


def main() -> None:
    tools = [ToolDef.from_mcp("bulk", raw) for raw in bulk_tools()]
    index = ToolIndex()
    index.build(tools)

    print(f"Catalogue: {len(tools)} tools across 10 services")
    report(index, "Direct queries (vocabulary overlaps the tool definitions)", DIRECT_QUERIES)
    report(index, "Paraphrase queries (no shared vocabulary)", PARAPHRASE_QUERIES)
    print(
        "\nThe paraphrase row is the honest limit of a lexical index. Closing it "
        "needs a\nsemantic embedder; ToolIndex takes any backend implementing "
        "Embedder.embed()."
    )

    print("\nContext cost of the tool list (approx. tokens, 4 chars/token)")
    print("-" * 62)
    print(f"{'catalogue size':<16} {'full list':>12} {'top-8 exposed':>15} {'saved':>8}")
    for size in (10, 25, 45):
        subset = tools[:size]
        subset_cost = estimate_tokens(subset)
        exposed = estimate_tokens(subset[: min(8, size)])
        print(
            f"{size:<16} {subset_cost:>12} {exposed:>15} "
            f"{1 - exposed / subset_cost:>7.0%}"
        )
    print(
        "\nBelow ~20 tools the saving does not justify the extra search hop, which "
        "is why\nretrieval only engages above gateway.retrieval.max_tools_exposed."
    )


if __name__ == "__main__":
    main()
