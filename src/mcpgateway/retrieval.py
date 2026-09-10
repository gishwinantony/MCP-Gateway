"""Dynamic tool retrieval.

Exposing 400 tools to a model costs tens of thousands of context tokens on
every single turn and measurably degrades tool selection. The gateway instead
indexes the catalogue and exposes only the tools relevant to the request.

Retrieval is hybrid: BM25 over tokens (exact vocabulary, tool names) fused with
cosine similarity over character-trigram vectors (typo and morphology
tolerance). Both run in-process with no external service. The embedding backend
is pluggable, so a real embedding model can be dropped in without touching the
gateway.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol

from .protocol import ToolDef

TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    """Lowercase, split on non-alphanumerics, and also split camelCase/snake_case."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    return TOKEN_RE.findall(spaced.lower())


class Embedder(Protocol):
    """Anything that turns text into a sparse or dense vector."""

    dimension: int

    def embed(self, text: str) -> dict[int, float]: ...


class TrigramEmbedder:
    """Hashed character-trigram vectors with L2 normalisation.

    Deterministic, dependency-free, and good enough to match "delete a file"
    against "remove_file". Swap in a transformer embedder for production
    recall; the interface is the same.
    """

    def __init__(self, dimension: int = 4096) -> None:
        self.dimension = dimension

    def embed(self, text: str) -> dict[int, float]:
        normalized = f"  {re.sub(r'[^a-z0-9]+', ' ', text.lower()).strip()}  "
        counts: Counter[int] = Counter()
        for i in range(len(normalized) - 2):
            trigram = normalized[i : i + 3]
            counts[hash(trigram) % self.dimension] += 1
        norm = math.sqrt(sum(v * v for v in counts.values())) or 1.0
        return {index: value / norm for index, value in counts.items()}


def cosine(a: dict[int, float], b: dict[int, float]) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(value * b.get(index, 0.0) for index, value in a.items())


@dataclass(slots=True)
class Document:
    name: str
    text: str
    tokens: list[str]
    vector: dict[int, float]
    length: int


@dataclass(slots=True)
class Hit:
    name: str
    score: float
    bm25_rank: int | None = None
    vector_rank: int | None = None


class ToolIndex:
    """Searchable index over tool definitions."""

    def __init__(self, embedder: Embedder | None = None, *, k1: float = 1.5, b: float = 0.75):
        self.embedder = embedder or TrigramEmbedder()
        self.k1 = k1
        self.b = b
        self._docs: dict[str, Document] = {}
        self._df: Counter[str] = Counter()
        self._avg_length = 0.0

    # --- indexing --------------------------------------------------------

    @staticmethod
    def document_text(tool: ToolDef) -> str:
        """Flatten the searchable surface of a tool into one string."""
        parts = [tool.server, tool.name.replace("_", " "), tool.title or "", tool.description]
        properties = (tool.input_schema or {}).get("properties")
        if isinstance(properties, dict):
            for field_name, spec in properties.items():
                parts.append(field_name.replace("_", " "))
                if isinstance(spec, dict) and isinstance(spec.get("description"), str):
                    parts.append(spec["description"])
        return " ".join(p for p in parts if p)

    def build(self, tools: Iterable[ToolDef]) -> None:
        self._docs.clear()
        self._df.clear()
        for tool in tools:
            text = self.document_text(tool)
            tokens = tokenize(text)
            self._docs[tool.qualified_name] = Document(
                name=tool.qualified_name,
                text=text,
                tokens=tokens,
                vector=self.embedder.embed(text),
                length=len(tokens),
            )
            for token in set(tokens):
                self._df[token] += 1
        total = sum(doc.length for doc in self._docs.values())
        self._avg_length = (total / len(self._docs)) if self._docs else 0.0

    def __len__(self) -> int:
        return len(self._docs)

    # --- search ----------------------------------------------------------

    def search(
        self,
        query: str,
        k: int = 8,
        *,
        candidates: Sequence[str] | None = None,
        rrf_k: int = 60,
    ) -> list[Hit]:
        """Return the top-k tools for a query using reciprocal rank fusion."""
        if not self._docs or not query.strip():
            return []
        pool = (
            [self._docs[n] for n in candidates if n in self._docs]
            if candidates is not None
            else list(self._docs.values())
        )
        if not pool:
            return []

        bm25_ranked = self._rank_bm25(query, pool)
        vector_ranked = self._rank_vector(query, pool)

        bm25_rank = {name: i + 1 for i, (name, _) in enumerate(bm25_ranked)}
        vector_rank = {name: i + 1 for i, (name, _) in enumerate(vector_ranked)}

        fused: dict[str, float] = {}
        for name, rank in bm25_rank.items():
            fused[name] = fused.get(name, 0.0) + 1.0 / (rrf_k + rank)
        for name, rank in vector_rank.items():
            fused[name] = fused.get(name, 0.0) + 1.0 / (rrf_k + rank)

        ordered = sorted(fused.items(), key=lambda kv: (-kv[1], kv[0]))[:k]
        return [
            Hit(
                name=name,
                score=round(score, 6),
                bm25_rank=bm25_rank.get(name),
                vector_rank=vector_rank.get(name),
            )
            for name, score in ordered
        ]

    def _rank_bm25(self, query: str, pool: list[Document]) -> list[tuple[str, float]]:
        query_tokens = tokenize(query)
        if not query_tokens:
            return []
        total_docs = len(self._docs)
        scored: list[tuple[str, float]] = []
        for doc in pool:
            counts = Counter(doc.tokens)
            score = 0.0
            for token in query_tokens:
                frequency = counts.get(token, 0)
                if not frequency:
                    continue
                df = self._df.get(token, 0) or 1
                idf = math.log(1 + (total_docs - df + 0.5) / (df + 0.5))
                denominator = frequency + self.k1 * (
                    1 - self.b + self.b * (doc.length / (self._avg_length or 1))
                )
                score += idf * (frequency * (self.k1 + 1)) / denominator
            if score > 0:
                scored.append((doc.name, score))
        return sorted(scored, key=lambda kv: (-kv[1], kv[0]))

    def _rank_vector(self, query: str, pool: list[Document]) -> list[tuple[str, float]]:
        query_vector = self.embedder.embed(query)
        scored = [(doc.name, cosine(query_vector, doc.vector)) for doc in pool]
        scored = [(name, score) for name, score in scored if score > 0.01]
        return sorted(scored, key=lambda kv: (-kv[1], kv[0]))


def estimate_tokens(tools: Iterable[ToolDef]) -> int:
    """Rough token cost of a tool list (~4 characters per token).

    Used to report how much context dynamic retrieval actually saves.
    """
    from .protocol import canonical_json

    characters = sum(len(canonical_json(tool.to_mcp())) for tool in tools)
    return characters // 4
