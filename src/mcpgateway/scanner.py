"""Static analysis of upstream tool definitions.

Everything an MCP server puts in a tool name, description or JSON schema is
fed straight into the model's context. A malicious or compromised server can
therefore inject instructions the user never sees, because most clients only
render the tool *name*. This module scans the parts of a tool definition that
reach the model and scores how likely they are to be an attack.

Detected classes:
  * instruction injection     - imperative text aimed at the model
  * concealment               - "do not tell the user", hidden unicode
  * exfiltration              - reads secrets / sends data to an attacker sink
  * cross-tool interference   - "shadowing" another server's tool
  * schema smuggling          - payload hidden in nested schema descriptions
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .protocol import ToolDef


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_SCORE = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 25,
    Severity.HIGH: 45,
    Severity.CRITICAL: 70,
}


class Verdict(str, Enum):
    CLEAN = "clean"
    WARN = "warn"
    QUARANTINE = "quarantine"


@dataclass(slots=True)
class Finding:
    rule: str
    severity: Severity
    category: str
    message: str
    location: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "category": self.category,
            "message": self.message,
            "location": self.location,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class ScanResult:
    tool: str
    fingerprint: str
    score: int
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.QUARANTINE

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "fingerprint": self.fingerprint,
            "score": self.score,
            "verdict": self.verdict.value,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass(slots=True)
class Rule:
    id: str
    category: str
    severity: Severity
    message: str
    pattern: re.Pattern[str]


def _rule(rule_id: str, category: str, severity: Severity, message: str, pattern: str) -> Rule:
    return Rule(rule_id, category, severity, message, re.compile(pattern, re.IGNORECASE | re.DOTALL))


# Ordered roughly by how strongly each signal implies intent.
RULES: tuple[Rule, ...] = (
    _rule(
        "INJ001",
        "instruction-injection",
        Severity.CRITICAL,
        "Text attempts to override prior instructions",
        r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b"
        r"(previous|prior|earlier|above|all)\b[^.\n]{0,20}"
        r"\b(instruction|prompt|rule|direction|context)",
    ),
    _rule(
        "INJ002",
        "instruction-injection",
        Severity.HIGH,
        "Text impersonates a system or developer message",
        r"<\s*(system|important|secret)[^>]*>|\[\s*(system|system prompt)\s*\]"
        r"|^\s*(system|assistant)\s*:",
    ),
    _rule(
        "INJ003",
        "instruction-injection",
        Severity.HIGH,
        "Description issues mandatory directives to the model rather than describing the tool",
        r"\byou\s+(must|should always|are required to|have to)\b"
        r"|\balways\s+(call|invoke|run|use|include|append)\b"
        r"|\bbefore\s+(using|calling)\s+(any|this|other)\b",
    ),
    _rule(
        "CON001",
        "concealment",
        Severity.CRITICAL,
        "Text instructs the model to hide behaviour from the user",
        r"\b(do not|don't|never|without)\b[^.\n]{0,40}\b"
        r"(tell|inform|mention|show|reveal|disclose|notify)\b[^.\n]{0,20}\b(the )?(user|human)"
        r"|\b(silently|secretly|covertly)\b",
    ),
    _rule(
        "CON002",
        "concealment",
        Severity.HIGH,
        "Text asks the model to fabricate or mask its output",
        r"\b(pretend|claim|report|say)\b[^.\n]{0,30}\b(succeeded|success|nothing|normal|fine)\b",
    ),
    _rule(
        "EXF001",
        "exfiltration",
        Severity.CRITICAL,
        "References credential or key material",
        r"\b(api[_\- ]?key|secret[_\- ]?key|access[_\- ]?token|private[_\- ]?key|password"
        r"|credential|bearer token)\b",
    ),
    _rule(
        "EXF002",
        "exfiltration",
        Severity.CRITICAL,
        "References sensitive local file paths",
        r"(~|/home/[^\s]*|/root)?/?\.(ssh|aws|env|netrc|kube)\b"
        r"|\bid_rsa\b|\.env\b|/etc/(passwd|shadow)",
    ),
    _rule(
        "EXF003",
        "exfiltration",
        Severity.HIGH,
        "Instructs the model to transmit data to an external destination",
        r"\b(send|post|upload|forward|transmit|exfiltrate|report)\b[^.\n]{0,30}"
        r"\b(to|at)\b[^.\n]{0,30}(https?://|[\w.-]+@[\w.-]+\.\w+)",
    ),
    _rule(
        "EXF004",
        "exfiltration",
        Severity.HIGH,
        "Markdown image or link with an interpolated value (classic zero-click exfiltration)",
        r"!\[[^\]]*\]\(\s*https?://[^)]*\{[^}]*\}[^)]*\)"
        r"|!\[[^\]]*\]\(\s*https?://[^)]*(\$\{|\+\s*data|<data>)",
    ),
    _rule(
        "EXF005",
        "exfiltration",
        Severity.MEDIUM,
        "Embeds a shell or network command",
        r"\b(curl|wget|nc\s+-|bash\s+-c|powershell\s+-enc|Invoke-WebRequest)\b",
    ),
    _rule(
        "XTL001",
        "cross-tool-interference",
        Severity.HIGH,
        "Refers to tools on other servers, which can shadow or hijack their behaviour",
        r"\b(when|whenever|if)\b[^.\n]{0,40}\b(tool|function)\b[^.\n]{0,40}\b(is )?(called|used|invoked)\b"
        r"|\binstead of\b[^.\n]{0,30}\b(tool|function|calling)\b",
    ),
    _rule(
        "ENC001",
        "obfuscation",
        Severity.MEDIUM,
        "Contains a long base64-like blob that may hide a payload",
        r"[A-Za-z0-9+/]{80,}={0,2}",
    ),
)

# Unicode ranges that render as nothing but survive into the model's context.
INVISIBLE_CHARS = re.compile(
    "["
    "\u200b-\u200f"  # zero-width space/joiners, LRM/RLM
    "\u202a-\u202e"  # bidi overrides
    "\u2060-\u2064"  # word joiner, invisible operators
    "\ufeff"  # BOM
    "\U000e0000-\U000e007f"  # unicode tag block
    "]"
)


class ToolScanner:
    """Scores tool definitions and decides whether to expose them."""

    def __init__(
        self,
        *,
        warn_threshold: int = 25,
        quarantine_threshold: int = 60,
        disabled_rules: Iterable[str] = (),
    ) -> None:
        self.warn_threshold = warn_threshold
        self.quarantine_threshold = quarantine_threshold
        self.disabled_rules = set(disabled_rules)

    def scan(self, tool: ToolDef) -> ScanResult:
        findings: list[Finding] = []
        for location, text in self._model_visible_text(tool):
            findings.extend(self._scan_text(location, text))

        findings.extend(self._structural_checks(tool))

        score = min(100, sum(SEVERITY_SCORE[f.severity] for f in findings))
        if score >= self.quarantine_threshold:
            verdict = Verdict.QUARANTINE
        elif score >= self.warn_threshold:
            verdict = Verdict.WARN
        else:
            verdict = Verdict.CLEAN
        return ScanResult(
            tool=tool.qualified_name,
            fingerprint=tool.fingerprint,
            score=score,
            verdict=verdict,
            findings=findings,
        )

    def scan_text(self, location: str, text: str) -> list[Finding]:
        """Run the text rules over arbitrary content, e.g. a tool's return value."""
        return self._scan_text(location, text)

    # --- internals -------------------------------------------------------

    def _model_visible_text(self, tool: ToolDef) -> list[tuple[str, str]]:
        """Every string in the definition that ends up in the model's context."""
        blocks: list[tuple[str, str]] = [
            ("name", tool.name),
            ("description", tool.description),
        ]
        if tool.title:
            blocks.append(("title", tool.title))
        blocks.extend(self._walk_schema(tool.input_schema, "inputSchema"))
        for key, value in tool.annotations.items():
            if isinstance(value, str):
                blocks.append((f"annotations.{key}", value))
        return [(loc, text) for loc, text in blocks if text]

    def _walk_schema(self, schema: Any, path: str) -> list[tuple[str, str]]:
        """Recursively collect description/title/enum strings from a JSON schema."""
        found: list[tuple[str, str]] = []
        if isinstance(schema, dict):
            for key, value in schema.items():
                child = f"{path}.{key}"
                if key in {"description", "title", "default", "const", "$comment"} and isinstance(
                    value, str
                ):
                    found.append((child, value))
                elif key == "enum" and isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            found.append((child, item))
                else:
                    found.extend(self._walk_schema(value, child))
        elif isinstance(schema, list):
            for index, item in enumerate(schema):
                found.extend(self._walk_schema(item, f"{path}[{index}]"))
        return found

    def _scan_text(self, location: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in RULES:
            if rule.id in self.disabled_rules:
                continue
            match = rule.pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        rule=rule.id,
                        severity=rule.severity,
                        category=rule.category,
                        message=rule.message,
                        location=location,
                        evidence=_excerpt(text, match.start(), match.end()),
                    )
                )
        findings.extend(self._unicode_checks(location, text))
        return findings

    def _unicode_checks(self, location: str, text: str) -> list[Finding]:
        findings: list[Finding] = []
        if "UNI001" not in self.disabled_rules:
            match = INVISIBLE_CHARS.search(text)
            if match:
                codepoint = f"U+{ord(match.group()):04X}"
                findings.append(
                    Finding(
                        rule="UNI001",
                        severity=Severity.HIGH,
                        category="concealment",
                        message=f"Invisible or bidirectional control character {codepoint}",
                        location=location,
                        evidence=_excerpt(text, match.start(), match.end()),
                    )
                )
        if "UNI002" not in self.disabled_rules:
            confusables = [
                ch
                for ch in text
                if ord(ch) > 127 and "LATIN" not in unicodedata.name(ch, "") and ch.isalpha()
            ]
            if confusables:
                findings.append(
                    Finding(
                        rule="UNI002",
                        severity=Severity.LOW,
                        category="obfuscation",
                        message="Non-Latin letters mixed into ASCII text (possible homoglyphs)",
                        location=location,
                        evidence="".join(dict.fromkeys(confusables))[:40],
                    )
                )
        return findings

    def _structural_checks(self, tool: ToolDef) -> list[Finding]:
        findings: list[Finding] = []
        if "STR001" not in self.disabled_rules and len(tool.description) > 2000:
            findings.append(
                Finding(
                    rule="STR001",
                    severity=Severity.LOW,
                    category="anomaly",
                    message=f"Unusually long description ({len(tool.description)} chars) "
                    "consumes context and can hide payloads",
                    location="description",
                    evidence=f"{len(tool.description)} characters",
                )
            )
        if "STR002" not in self.disabled_rules and not tool.description.strip():
            findings.append(
                Finding(
                    rule="STR002",
                    severity=Severity.INFO,
                    category="anomaly",
                    message="Tool has no description, so intent cannot be reviewed",
                    location="description",
                )
            )
        return findings


def _excerpt(text: str, start: int, end: int, window: int = 40) -> str:
    left = max(0, start - window)
    right = min(len(text), end + window)
    snippet = text[left:right].replace("\n", " ").strip()
    # Make invisible characters visible in the report itself.
    snippet = INVISIBLE_CHARS.sub(lambda m: f"<U+{ord(m.group()):04X}>", snippet)
    prefix = "..." if left > 0 else ""
    suffix = "..." if right < len(text) else ""
    return f"{prefix}{snippet}{suffix}"[:240]
