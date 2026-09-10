from __future__ import annotations

import sys
from pathlib import Path
from typing import ClassVar

import pytest

from mcpgateway.protocol import ToolDef
from mcpgateway.retrieval import ToolIndex, estimate_tokens, tokenize

sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
from fake_mcp_server import bulk_tools


@pytest.fixture
def index() -> ToolIndex:
    tools = [ToolDef.from_mcp("bulk", raw) for raw in bulk_tools()]
    idx = ToolIndex()
    idx.build(tools)
    return idx


def test_tokenizer_splits_snake_and_camel_case():
    assert tokenize("create_invoice") == ["create", "invoice"]
    assert tokenize("createInvoice") == ["create", "invoice"]


def test_index_covers_every_tool(index):
    assert len(index) == len(bulk_tools())


def test_exact_terms_rank_first(index):
    hits = index.search("refund a stripe invoice", k=3)
    assert hits[0].name == "bulk__refund_invoice"


def test_paraphrased_intent_matches_when_vocabulary_overlaps(index):
    hits = index.search("acknowledge the incident that is paging me", k=5)
    names = [hit.name for hit in hits]
    assert "bulk__acknowledge_incident" in names


def test_pure_semantic_paraphrase_is_a_known_limitation(index):
    """The default backend is lexical, so it misses zero-overlap paraphrase.

    "wake up the on-call engineer" shares no tokens or trigrams with
    "Trigger an incident in pagerduty". This test pins the limitation so the
    behaviour is documented rather than discovered in production.
    """
    hits = index.search("the service is down, wake up the on-call engineer", k=5)
    assert not any("incident" in hit.name for hit in hits)


def test_a_semantic_embedder_closes_the_gap(index):
    """Swapping the embedding backend is the supported fix for the above."""

    class ConceptEmbedder:
        """Stand-in for a real embedding model: maps text to concept axes."""

        dimension = 4
        CONCEPTS: ClassVar[dict[int, tuple[str, ...]]] = {
            0: ("incident", "pagerduty", "on-call", "oncall", "paging", "outage", "down", "wake"),
            1: ("invoice", "stripe", "refund", "billing", "payment"),
            2: ("deployment", "kubernetes", "k8s", "scale", "restart", "pod"),
            3: ("message", "slack", "email", "send", "notify"),
        }

        def embed(self, text: str) -> dict[int, float]:
            lowered = text.lower()
            raw = {
                axis: float(sum(word in lowered for word in words))
                for axis, words in self.CONCEPTS.items()
            }
            norm = sum(v * v for v in raw.values()) ** 0.5 or 1.0
            return {axis: value / norm for axis, value in raw.items() if value}

    tools = [ToolDef.from_mcp("bulk", raw) for raw in bulk_tools()]
    semantic = ToolIndex(embedder=ConceptEmbedder())
    semantic.build(tools)

    hits = semantic.search("the service is down, wake up the on-call engineer", k=5)
    assert any("incident" in hit.name for hit in hits)


def test_typos_are_tolerated_by_the_vector_leg(index):
    hits = index.search("scale a kubernets deploymnt", k=5)
    names = [hit.name for hit in hits]
    assert "bulk__scale_deployment" in names


def test_hybrid_fusion_uses_both_legs(index):
    hits = index.search("send a slack message", k=3)
    top = hits[0]
    assert top.name == "bulk__send_message"
    assert top.bm25_rank is not None and top.vector_rank is not None


def test_candidate_filter_is_respected(index):
    allowed = ["bulk__create_issue", "bulk__close_issue"]
    hits = index.search("stripe invoice", k=5, candidates=allowed)
    assert {hit.name for hit in hits} <= set(allowed)


def test_empty_query_returns_nothing(index):
    assert index.search("   ", k=5) == []


def test_retrieval_cuts_context_cost(index):
    tools = [ToolDef.from_mcp("bulk", raw) for raw in bulk_tools()]
    full = estimate_tokens(tools)
    hits = index.search("refund a stripe invoice", k=8)
    by_name = {t.qualified_name: t for t in tools}
    selected = estimate_tokens([by_name[h.name] for h in hits])
    assert full > 2000
    # Exposing eight retrieved tools should cost well under a quarter of the
    # full catalogue.
    assert selected < full * 0.25
