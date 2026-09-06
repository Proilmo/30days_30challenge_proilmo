#!/usr/bin/env python3
"""
sql_injection_detector.py
==========================
A standalone, dependency-free SQL Injection (SQLi) detector for Python.

Purpose
-------
Analyze user-supplied strings (form fields, query params, JSON values, etc.)
and flag ones that look like SQL injection attempts. This is a DEFENSIVE
tool meant to be used as:
  - a pre-validation layer in front of a web app / API,
  - a log/traffic scanner to find suspicious historical requests,
  - a unit-test helper to sanity check input sanitization.

It is heuristic/pattern-based, not a proof of safety. Parameterized
queries / prepared statements are still the real fix — this tool only
helps you catch and log suspicious input.

Usage
-----
As a library:
    from sql_injection_detector import SQLInjectionDetector

    detector = SQLInjectionDetector()
    result = detector.analyze("1 OR 1=1 --")
    print(result.is_malicious, result.risk_score, result.matches)

As a CLI:
    python3 sql_injection_detector.py "1' OR '1'='1"
    python3 sql_injection_detector.py --file suspicious_inputs.txt
    echo "admin'--" | python3 sql_injection_detector.py --stdin
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class PatternMatch:
    category: str
    pattern_desc: str
    matched_text: str
    weight: int


@dataclass
class AnalysisResult:
    original_input: str
    normalized_input: str
    matches: list[PatternMatch] = field(default_factory=list)
    risk_score: int = 0

    @property
    def is_malicious(self) -> bool:
        return self.risk_score >= 30

    @property
    def severity(self) -> Severity:
        if self.risk_score >= 80:
            return Severity.CRITICAL
        if self.risk_score >= 50:
            return Severity.HIGH
        if self.risk_score >= 30:
            return Severity.MEDIUM
        return Severity.LOW

    def report(self) -> str:
        lines = [
            f"Input          : {self.original_input!r}",
            f"Risk score     : {self.risk_score}",
            f"Severity       : {self.severity.value}",
            f"Malicious?     : {'YES' if self.is_malicious else 'no'}",
        ]
        if self.matches:
            lines.append("Matched signals:")
            for m in self.matches:
                lines.append(
                    f"  - [{m.category}] {m.pattern_desc} (+{m.weight}) -> {m.matched_text!r}"
                )
        else:
            lines.append("Matched signals: none")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# Detector
# --------------------------------------------------------------------------

class SQLInjectionDetector:
    """
    Heuristic SQL injection detector.

    Detection strategy (each layer adds weighted points to a risk score):
      1. Normalize input (URL-decode, collapse whitespace, lowercase copy
         for matching) so encoded/obfuscated payloads are still caught.
      2. Match against curated regex pattern groups covering the major
         SQLi technique families (tautologies, UNION-based, comments,
         stacked queries, blind/time-based, error-based, function abuse).
      3. Add smaller heuristic points for suspicious structural traits
         (unbalanced quotes, excessive special characters, encoded
         payload markers).
      4. Combine into a 0-100 risk score and classify severity.
    """

    # Each tuple: (category, human description, compiled regex, weight)
    _PATTERNS: list[tuple[str, str, re.Pattern, int]] = [
        # --- Tautologies / always-true conditions ---
        ("tautology", "classic OR/AND always-true condition",
         re.compile(r"(\bor\b|\band\b)\s+['\"]?\s*\w+\s*['\"]?\s*=\s*['\"]?\s*\w+", re.I), 35),
        ("tautology", "numeric always-true condition (e.g. 1=1)",
         re.compile(r"\b(\d+)\s*=\s*\1\b"), 30),

        # --- Comment sequences used to truncate queries ---
        ("comment", "SQL line comment (--)",
         re.compile(r"(--|#)\s*$|--\s+"), 20),
        ("comment", "SQL block comment (/* */)",
         re.compile(r"/\*.*?\*/", re.S), 20),

        # --- UNION-based injection ---
        ("union", "UNION SELECT clause",
         re.compile(r"\bunion\b(\s+all)?\s+select\b", re.I), 40),

        # --- Stacked / batched queries ---
        ("stacked", "stacked query terminator followed by DML/DDL",
         re.compile(r";\s*(select|insert|update|delete|drop|alter|create|exec|execute)\b", re.I), 40),

        # --- Data-modifying / destructive statements ---
        ("dml_ddl", "DROP TABLE/DATABASE",
         re.compile(r"\bdrop\s+(table|database|schema)\b", re.I), 45),
        ("dml_ddl", "ALTER/TRUNCATE statement",
         re.compile(r"\b(alter|truncate)\s+table\b", re.I), 35),
        ("dml_ddl", "INSERT/UPDATE/DELETE injected alongside a query",
         re.compile(r"\b(insert\s+into|update\s+\w+\s+set|delete\s+from)\b", re.I), 25),

        # --- Blind / time-based techniques ---
        ("time_blind", "time-delay function abuse (SLEEP/WAITFOR/BENCHMARK/PG_SLEEP)",
         re.compile(r"\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(", re.I), 45),

        # --- Error-based / information gathering ---
        ("error_based", "information_schema / system catalog probing",
         re.compile(r"\binformation_schema\b|\bsys\.(tables|columns|databases)\b", re.I), 35),
        ("error_based", "extractvalue/updatexml error-based injection",
         re.compile(r"\b(extractvalue|updatexml)\s*\(", re.I), 40),
        ("error_based", "version/user/database fingerprinting functions",
         re.compile(r"\b(version|current_user|database|user)\s*\(\s*\)", re.I), 20),

        # --- Dangerous stored procedures / command execution ---
        ("exec", "xp_cmdshell or exec()/execute() call",
         re.compile(r"\bxp_cmdshell\b|\bexec(ute)?\s*\(", re.I), 45),

        # --- Suspicious quoting / escaping patterns ---
        ("quote_break", "attempt to break out of a quoted string",
         re.compile(r"('\s*(or|and)\s+|'\s*;|\"\s*(or|and)\s+|\"\s*;)", re.I), 25),

        # --- Encoded / obfuscated payload markers ---
        ("obfuscation", "hex-encoded literal (0x...)",
         re.compile(r"\b0x[0-9a-f]{4,}\b", re.I), 20),
        ("obfuscation", "CHAR()/CONCAT() based string building",
         re.compile(r"\bchar\s*\(\s*\d+", re.I), 20),
        ("obfuscation", "inline comment used to split keywords (e.g. UN/**/ION)",
         re.compile(r"\b\w+/\*.*?\*/\w*\b", re.S), 25),
    ]

    def __init__(self, threshold: int = 30):
        self.threshold = threshold

    # ---- normalization -----------------------------------------------

    @staticmethod
    def _normalize(raw: str) -> str:
        text = raw
        # Decode URL-encoding (possibly applied more than once).
        for _ in range(2):
            decoded = urllib.parse.unquote_plus(text)
            if decoded == text:
                break
            text = decoded
        # Collapse repeated whitespace so split-up keywords still match.
        text = re.sub(r"\s+", " ", text)
        return text

    @staticmethod
    def _structural_heuristics(raw: str) -> list[PatternMatch]:
        matches: list[PatternMatch] = []

        single_quotes = raw.count("'")
        if single_quotes % 2 == 1:
            matches.append(PatternMatch(
                "structural", "unbalanced single quote", "'", 15))

        special_count = len(re.findall(r"[;'\"\-\-#/*=]", raw))
        if special_count >= 6:
            matches.append(PatternMatch(
                "structural", "high density of special characters",
                f"{special_count} special chars", 10))

        if len(raw) > 0 and special_count / max(len(raw), 1) > 0.3:
            matches.append(PatternMatch(
                "structural", "special characters dominate the input",
                f"{special_count}/{len(raw)} chars", 10))

        return matches

    # ---- main entry point ----------------------------------------------

    def analyze(self, raw_input: str) -> AnalysisResult:
        if raw_input is None:
            raw_input = ""

        normalized = self._normalize(raw_input)
        result = AnalysisResult(original_input=raw_input, normalized_input=normalized)

        for category, desc, pattern, weight in self._PATTERNS:
            m = pattern.search(normalized)
            if m:
                result.matches.append(PatternMatch(category, desc, m.group(0), weight))

        result.matches.extend(self._structural_heuristics(raw_input))

        # Sum weights, cap at 100, with diminishing returns after 3 hits
        # of the same category to avoid one payload type dominating the score.
        seen_categories: dict[str, int] = {}
        score = 0
        for m in result.matches:
            count = seen_categories.get(m.category, 0)
            factor = 1.0 if count == 0 else (0.5 if count == 1 else 0.25)
            score += m.weight * factor
            seen_categories[m.category] = count + 1

        result.risk_score = min(100, round(score))
        return result

    def is_malicious(self, raw_input: str) -> bool:
        return self.analyze(raw_input).risk_score >= self.threshold

    def scan_batch(self, inputs: list[str]) -> list[AnalysisResult]:
        return [self.analyze(i) for i in inputs]


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _run_cli() -> int:
    parser = argparse.ArgumentParser(
        description="Heuristic SQL Injection detector for strings, files, or stdin."
    )
    parser.add_argument("text", nargs="?", help="A single string to analyze.")
    parser.add_argument("--file", help="Path to a file with one input per line.")
    parser.add_argument("--stdin", action="store_true", help="Read a single input from stdin.")
    parser.add_argument("--threshold", type=int, default=30,
                         help="Risk score threshold to flag as malicious (default: 30).")
    parser.add_argument("--quiet", action="store_true",
                         help="Only print flagged (malicious) results.")
    args = parser.parse_args()

    detector = SQLInjectionDetector(threshold=args.threshold)

    inputs: list[str] = []
    if args.text:
        inputs.append(args.text)
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            inputs.extend(line.rstrip("\n") for line in f if line.strip())
    if args.stdin:
        inputs.append(sys.stdin.readline().rstrip("\n"))

    if not inputs:
        parser.print_help()
        return 1

    flagged = 0
    for text in inputs:
        result = detector.analyze(text)
        if result.is_malicious:
            flagged += 1
        if args.quiet and not result.is_malicious:
            continue
        print(result.report())
        print("-" * 60)

    print(f"Scanned {len(inputs)} input(s), flagged {flagged} as malicious "
          f"(threshold={args.threshold}).")
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())