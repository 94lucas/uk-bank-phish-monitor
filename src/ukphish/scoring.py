"""Risk scoring for candidate domains.

Each domain is evaluated against every monitored brand. The highest-scoring
brand wins. Every point awarded comes with a human-readable reason, so an
analyst can always see *why* a domain was flagged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import Brand, Settings

# Small, deliberately conservative set of look-alike characters seen in
# phishing domains. Extend it as you observe new tricks in the wild.
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",  # Cyrillic
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ⅼ": "l",
    "á": "a", "à": "a", "â": "a", "ä": "a", "é": "e", "è": "e", "ê": "e",
    "í": "i", "ï": "i", "ó": "o", "ö": "o", "ú": "u", "ü": "u",
}
MULTI_CHAR_HOMOGLYPHS = {"rn": "m", "vv": "w", "cl": "d"}


@dataclass
class ScoreResult:
    domain: str
    score: int = 0
    brand: str | None = None
    reasons: list[str] = field(default_factory=list)
    allowlisted: bool = False


def clean_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    return domain


def decode_idna(domain: str) -> str:
    """Convert punycode labels (xn--) to Unicode so homoglyphs become visible."""
    labels = []
    for label in domain.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def normalise_homoglyphs(text: str) -> str:
    """Map look-alike characters to a canonical form. Apply it to BOTH the domain
    and the brand keyword, so 'bardays' and 'barc1ays' both match 'barclays'."""
    text = "".join(HOMOGLYPHS.get(ch, ch) for ch in text)
    for fake, real in MULTI_CHAR_HOMOGLYPHS.items():
        text = text.replace(fake, real)
    return text


def osa_distance(a: str, b: str) -> int:
    """Optimal string alignment distance: Levenshtein plus adjacent transpositions,
    so 'barclasy' is 1 edit away from 'barclays'."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def is_allowlisted(domain: str, brands: list[Brand]) -> bool:
    for brand in brands:
        for legit in brand.legit_domains:
            if domain == legit or domain.endswith("." + legit):
                return True
    return False


def _score_against_brand(raw: str, normalised: str, tokens: list[str],
                         brand: Brand, w: dict) -> tuple[int, list[str]]:
    score, reasons = 0, []
    flat_raw = raw.replace("-", "").replace(".", "")
    flat_norm = normalised.replace("-", "").replace(".", "")

    for kw in brand.keywords:
        kw_flat = kw.replace("-", "")
        if kw_flat in flat_raw:
            return w["brand_keyword"], [f"brand keyword '{kw}'"]
        if normalise_homoglyphs(kw_flat) in flat_norm:
            score = w["brand_keyword"] + w["homoglyph_brand"]
            reasons = [f"brand keyword '{kw}' hidden with look-alike characters"]
            return score, reasons

    # Typosquatting: only for keywords long enough to avoid noise.
    for kw in brand.keywords:
        if len(kw) < 6:
            continue
        max_dist = 1 if len(kw) < 9 else 2
        kw_norm = normalise_homoglyphs(kw)
        for tok in tokens:
            if abs(len(tok) - len(kw_norm)) > max_dist:
                continue
            dist = osa_distance(tok, kw_norm)
            if 0 < dist <= max_dist:
                return w["typosquat"], [f"'{tok}' is {dist} edit(s) from '{kw}'"]
    return score, reasons


def score_domain(domain: str, settings: Settings) -> ScoreResult:
    domain = clean_domain(domain)
    result = ScoreResult(domain=domain)

    if is_allowlisted(domain, settings.brands):
        result.allowlisted = True
        return result

    w = settings.weights
    unicode_domain = decode_idna(domain)
    normalised = normalise_homoglyphs(unicode_domain)
    tokens = [t for t in re.split(r"[.\-]", normalised) if t]

    # 1. Brand impersonation (best match wins)
    best_score, best_reasons = 0, []
    for brand in settings.brands:
        s, r = _score_against_brand(domain, normalised, tokens, brand, w)
        if s > best_score:
            best_score, best_reasons, result.brand = s, r, brand.name
    result.score += best_score
    result.reasons += best_reasons

    # 2. Generic risk signals
    if "xn--" in domain:
        result.score += w["punycode"]
        result.reasons.append(f"punycode label (renders as '{unicode_domain}')")

    found = [word for word in settings.suspicious_words if word in normalised]
    if found:
        result.score += min(len(found) * w["suspicious_word"], w["suspicious_word_cap"])
        result.reasons.append("suspicious words: " + ", ".join(found))

    tld = domain.rsplit(".", 1)[-1]
    if tld in settings.abused_tlds:
        result.score += w["abused_tld"]
        result.reasons.append(f"frequently abused TLD '.{tld}'")

    if domain.count(".") >= 3:
        result.score += w["deep_subdomain"]
        result.reasons.append("deep subdomain structure")

    # Without any brand signal, generic words alone are not enough to matter.
    if result.brand is None:
        result.score = min(result.score, settings.thresholds["store"] - 1)

    return result
