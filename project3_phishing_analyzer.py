"""
phishing_analyzer.py
=====================

Phishing Awareness Analyzer
----------------------------
An educational tool that mimics the *first triage step* a junior SOC
(Security Operations Center) analyst performs when a suspicious email
is reported by an employee.

WHAT THIS TOOL IS
------------------
This is a rule-based (keyword + heuristic + regex) text analyzer. It reads
the raw text of an email/message and looks for patterns that are commonly
associated with phishing: urgency language, credential-harvesting requests,
suspicious links, and impersonation of trusted brands.

WHAT THIS TOOL IS NOT
-----------------------
- It does NOT block, quarantine, or delete anything.
- It does NOT connect to the internet, resolve DNS, or check real
  blacklists/reputation services (that would require external APIs).
- It is NOT a replacement for enterprise email security systems
  (Secure Email Gateways, SPF/DKIM/DMARC enforcement, sandboxing, etc.)
- It will produce false positives and false negatives, like any
  rule-based system. This is discussed in the "Testing Strategy"
  section of the accompanying README.

WHY RULE-BASED DETECTION (AND NOT ML)?
----------------------------------------
Real-world phishing filters (e.g., Microsoft Defender, Proofpoint, Google's
phishing detection) combine several detection LAYERS:
    1. Rule-based heuristics (what we build here) - fast, explainable,
       cheap to run, easy for a human analyst to audit.
    2. Reputation/threat-intel lookups (domain age, blacklists, WHOIS).
    3. Machine learning / NLP models trained on millions of samples.
    4. Sender authentication protocols (SPF, DKIM, DMARC).
A junior analyst is expected to understand layer 1 deeply, because it's
the layer that is *explainable* -- you can show a manager exactly why a
message was flagged. That's the skill this project is designed to teach.

Author: DecodeLabs Cybersecurity Internship Project
"""

from __future__ import annotations

import re
import sys
import os
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple


# ======================================================================
# SECTION 1: CONFIGURATION / KNOWLEDGE BASE
# ======================================================================
#
# In a real SOC, these lists would live in a database or a threat-intel
# feed that gets updated continuously. Here we hardcode them so the
# logic is transparent and easy to extend. Keeping configuration data
# separate from logic (functions below) is a basic clean-code principle:
# it means a non-programmer analyst could update these lists without
# touching the code that processes them.

# --- 1a. Suspicious keywords/phrases ------------------------------------
# CONCEPT: Phishing emails rely on a fairly small, well-studied vocabulary
# because the underlying psychological tactics (urgency, fear, reward)
# repeat across campaigns. Phrases are checked in addition to single
# words because "click here" is far more suspicious as a phrase than
# "click" and "here" are individually.
PHISHING_KEYWORDS: List[str] = [
    "urgent", "immediately", "verify", "confirm", "update",
    "click here", "login now", "account suspended", "payment failed",
    "security alert", "password expired", "action required",
    "congratulations", "winner", "prize", "free", "limited time",
    "claim now", "confidential", "verify identity", "banking",
    "invoice", "gift card",
]

# --- 1b. Credential / sensitive-data request terms ----------------------
# CONCEPT: Legitimate organizations essentially NEVER ask you to reply
# with a password, OTP, or CVV by email. Any email that requests these
# is attempting "credential harvesting" -- stealing the keys to an
# account rather than exploiting a technical vulnerability.
CREDENTIAL_TERMS: List[str] = [
    "password", "pin", "otp", "verification code", "credit card",
    "cvv", "banking details", "social security number", "ssn",
    "personal information",
]

# --- 1c. Urgency / fear (social engineering) phrases ---------------------
# CONCEPT: These phrases are designed to trigger a "fight or flight"
# stress response, which measurably reduces a victim's critical
# thinking. Analysts call this "pretext urgency."
URGENCY_FEAR_PHRASES: List[str] = [
    "immediate action required", "final warning", "account suspended",
    "account will be deleted", "limited time", "today only", "act now",
    "failure to respond", "last chance",
]

# --- 1d. Authority / impersonation cues ----------------------------------
# CONCEPT: Attackers borrow the credibility of a trusted authority
# (a bank, IT department, government agency, or executive) to make the
# victim comply without question. This is "authority bias."
AUTHORITY_PHRASES: List[str] = [
    "it department", "your bank", "government", "irs", "hr department",
    "ceo", "law enforcement", "legal action", "compliance department",
]

# --- 1e. Known URL shorteners --------------------------------------------
# CONCEPT: Shorteners are legitimate tools (used constantly on social
# media) but attackers abuse them to hide a malicious destination
# behind an innocuous-looking short link, defeating "hover to preview"
# habits that security-aware users rely on.
URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "shorturl.at", "ow.ly", "is.gd",
    "buff.ly", "goo.gl", "rebrand.ly",
}

# --- 1f. Non-standard / high-abuse top-level domains ---------------------
# CONCEPT: Some TLDs (.xyz, .top, .click, .work, .support, .click, .icu)
# are cheap to register in bulk and are statistically over-represented
# in phishing campaigns, per multiple annual threat reports (e.g.
# Interisle Consulting's Phishing Landscape studies). Their presence is
# a WEAK signal on its own but strengthens other signals.
SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "click", "work", "support", "icu", "gq", "tk", "ml",
    "loan", "win", "party", "review",
}

# --- 1g. Well-known brand names commonly impersonated --------------------
# Used to detect "typosquatting" - domains that are visually similar to
# a trusted brand but are not actually owned by that brand.
IMPERSONATED_BRANDS: List[str] = [
    "microsoft", "apple", "amazon", "paypal", "google", "netflix",
    "bankofamerica", "wellsfargo", "chase", "dhl", "fedex", "irs",
    "facebook", "instagram", "linkedin",
]

# Simulated domain blacklist (Optional Feature #3: Domain Reputation
# Simulation). In production this would be a live feed (e.g. PhishTank,
# OpenPhish) queried over an API -- here it's a small static sample so
# the project runs fully offline.
SIMULATED_BLACKLIST: Set[str] = {
    "secure-login-account.xyz",
    "amaz0n-security-login.xyz",
    "secure-bank-login.xyz",
    "paypa1-verify.com",
    "microsoft-login-support.top",
}

# --- Risk score weighting table ------------------------------------------
# CONCEPT: Each detected signal contributes points toward a 0-100 risk
# score. Weights below are *illustrative*, not derived from a formal
# statistical model -- in a production system these would be tuned
# using labeled historical data (a dataset of confirmed phishing vs.
# confirmed legitimate emails) and something like logistic regression.
# We keep the weights as named constants (not "magic numbers") so the
# scoring logic in calculate_risk_score() stays readable and the
# rationale is documented once, here.
SCORE_WEIGHTS: Dict[str, int] = {
    "keyword": 6,              # per unique suspicious keyword, capped
    "credential_request": 12,  # per unique credential term, capped
    "urgency_fear": 10,        # per unique urgency/fear phrase, capped
    "authority": 6,            # per unique authority phrase, capped
    "suspicious_url": 15,      # per suspicious URL, capped
    "url_shortener": 10,       # per shortener link found
    "ip_based_url": 15,        # URL using a raw IP instead of a domain
    "blacklisted_domain": 25,  # domain matches simulated blacklist
    "brand_impersonation": 20, # typosquatted brand name detected
}

# Caps prevent one category (e.g., 15 repeated keywords) from
# dominating the score and drowning out other signal types.
CATEGORY_CAP: Dict[str, int] = {
    "keyword": 18,
    "credential_request": 24,
    "urgency_fear": 20,
    "authority": 12,
    "suspicious_url": 30,
    "url_shortener": 20,
    "ip_based_url": 15,
    "blacklisted_domain": 25,
    "brand_impersonation": 20,
}


# ======================================================================
# SECTION 2: DATA STRUCTURES
# ======================================================================

@dataclass
class UrlFinding:
    """
    Holds the analysis result for a single URL found in the message.

    Using a dataclass (rather than a plain dict) gives us type safety,
    auto-generated __repr__ for debugging, and IDE autocompletion --
    all good clean-code practices for anything beyond a trivial script.
    """
    url: str
    domain: str
    reasons: List[str] = field(default_factory=list)
    is_ip_based: bool = False
    is_shortener: bool = False
    is_blacklisted: bool = False
    impersonated_brand: str | None = None

    @property
    def is_suspicious(self) -> bool:
        """A URL is 'suspicious' if it triggered at least one reason."""
        return len(self.reasons) > 0


@dataclass
class AnalysisResult:
    """
    Aggregates every finding from a full analysis pass. This is passed
    from analyze_message() to generate_report() / display_results(),
    keeping "compute the findings" cleanly separated from "format the
    findings for display" (a form of separation of concerns).
    """
    original_text: str
    keywords_found: List[str] = field(default_factory=list)
    credential_requests_found: List[str] = field(default_factory=list)
    urgency_fear_found: List[str] = field(default_factory=list)
    authority_found: List[str] = field(default_factory=list)
    social_engineering_techniques: List[str] = field(default_factory=list)
    url_findings: List[UrlFinding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"
    red_flag_checklist: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


# ======================================================================
# SECTION 3: INPUT HANDLING
# ======================================================================

def get_user_input() -> str:
    """
    Collects a multi-line email/message from the console.

    WHY: Real emails span many lines, so a single input() call is not
    enough. We let the user type/paste multiple lines and signal the
    end of input by typing a line containing only 'END' (a common
    convention for console multi-line input), or by sending EOF
    (Ctrl+D on macOS/Linux, Ctrl+Z then Enter on Windows).

    Returns:
        str: The full multi-line message as a single string.
    """
    print("Paste the email/message below.")
    print("Type a single line containing only 'END' when finished")
    print("(or press Ctrl+D / Ctrl+Z to submit).\n")

    lines: List[str] = []
    try:
        while True:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
    except EOFError:
        # User pressed Ctrl+D / Ctrl+Z instead of typing END.
        pass

    return "\n".join(lines)


def load_message_from_file(filepath: str) -> str:
    """
    Loads message text from a .txt file (Optional Feature #7).

    Defensive programming: we validate the path exists, is a file
    (not a directory), and handle encoding/permission errors
    gracefully instead of letting the program crash with a raw
    traceback, which would be a poor experience for a non-programmer
    analyst using this tool.

    Args:
        filepath: Path to a .txt file containing the message.

    Returns:
        The file's text content.

    Raises:
        FileNotFoundError: if the path does not exist.
        ValueError: if the path is not a readable text file.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"No such file: {filepath}")
    if not os.path.isfile(filepath):
        raise ValueError(f"Path is not a file: {filepath}")

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except PermissionError as exc:
        raise ValueError(f"Permission denied reading file: {filepath}") from exc


# ======================================================================
# SECTION 4: DETECTION FUNCTIONS
# ======================================================================

def _find_unique_phrases(text: str, phrases: List[str]) -> List[str]:
    """
    Internal helper: case-insensitively searches `text` for each phrase
    in `phrases` and returns the phrases that were found, with no
    duplicates, preserving the original casing/order of `phrases`.

    WHY A SHARED HELPER: detect_keywords(), detect_credential_requests(),
    detect_urgency_fear(), and detect_authority() all do the exact same
    "case-insensitive phrase search with de-duplication" operation on
    different word lists. Extracting this avoids duplicated logic
    (explicitly required by the project spec) and means a bug fix here
    automatically fixes all four detectors.

    Args:
        text: The message text to search (any case).
        phrases: List of keywords/phrases to look for.

    Returns:
        List of the phrases (in their original casing from `phrases`)
        that appear in `text`, without duplicates.
    """
    text_lower = text.lower()
    found: List[str] = []
    seen: Set[str] = set()

    for phrase in phrases:
        phrase_lower = phrase.lower()
        # \b word boundaries prevent partial-word matches, e.g. we don't
        # want "free" to match inside "freedom". re.escape handles
        # phrases that contain regex-special characters safely.
        pattern = r"\b" + re.escape(phrase_lower) + r"\b"
        if re.search(pattern, text_lower):
            if phrase_lower not in seen:
                found.append(phrase)
                seen.add(phrase_lower)

    return found


def detect_keywords(text: str) -> List[str]:
    """
    Detects suspicious phishing keywords/phrases in the message.

    Case-insensitive, phrase-aware (e.g. matches "click here" as a unit,
    not just "click"), and de-duplicated.
    """
    return _find_unique_phrases(text, PHISHING_KEYWORDS)


def detect_credential_requests(text: str) -> List[str]:
    """
    Detects language requesting sensitive credentials or personal data.

    CONCEPT (Credential Theft): Attackers ultimately want something they
    can monetize or use for further access: a password grants direct
    account takeover; an OTP or verification code defeats
    two-factor-authentication; a CVV/SSN enables financial fraud or
    identity theft. Legitimate companies design their real login flows
    so that this information is *never* requested via email reply,
    because email is unencrypted-in-transit-by-default and easily
    spoofed -- so any such request is a major red flag.
    """
    return _find_unique_phrases(text, CREDENTIAL_TERMS)


def detect_urgency_fear(text: str) -> List[str]:
    """
    Detects urgency/fear-based social engineering phrases.

    CONCEPT: Psychologically, urgency and fear short-circuit deliberate
    ("System 2") thinking and push people toward fast, automatic
    ("System 1") reactions -- exactly the mental state an attacker
    wants a victim in before they click a malicious link.
    """
    return _find_unique_phrases(text, URGENCY_FEAR_PHRASES)


def detect_authority(text: str) -> List[str]:
    """
    Detects language invoking a trusted authority (bank, IT dept,
    government, executive, etc.) to pressure compliance.

    CONCEPT: Human beings are conditioned from childhood to comply with
    authority figures. "Business Email Compromise" (BEC) attacks
    frequently impersonate a CEO or manager for exactly this reason.
    """
    return _find_unique_phrases(text, AUTHORITY_PHRASES)


def detect_social_engineering(
    urgency_fear: List[str], authority: List[str], credential_reqs: List[str]
) -> List[str]:
    """
    Summarizes which *categories* of social engineering technique are
    present, based on findings from the more granular detectors above.

    This produces the high-level "Social Engineering Techniques" section
    of the final report (e.g. "Urgency", "Fear", "Authority", "Reward").

    Args:
        urgency_fear: phrases found by detect_urgency_fear().
        authority: phrases found by detect_authority().
        credential_reqs: phrases found by detect_credential_requests().

    Returns:
        A list of technique category names present in the message.
    """
    techniques: List[str] = []

    if urgency_fear:
        techniques.append("Urgency")
        # Certain phrases are specifically fear-based (threat of loss)
        fear_specific = {"account will be deleted", "final warning",
                          "account suspended", "failure to respond"}
        if any(p.lower() in fear_specific for p in urgency_fear):
            techniques.append("Fear")

    if authority:
        techniques.append("Authority")

    if credential_reqs:
        techniques.append("Credential Harvesting")

    return techniques


# ---- URL extraction and analysis ----------------------------------------

# Regex explanation (documented once here rather than inline, per the
# spec's "clear comments only when necessary" guidance):
#   https?://       matches "http://" or "https://"
#   [^\s<>"']+      matches one-or-more characters that are NOT
#                    whitespace or common delimiter characters that
#                    would terminate a URL in plain text (quotes, angle
#                    brackets). This is a pragmatic, "good enough for
#                    plain-text email" URL matcher -- not a full RFC 3986
#                    URL parser (which would be considerably more complex).
URL_REGEX = re.compile(r"https?://[^\s<>\"']+")

IP_HOST_REGEX = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)


def extract_urls(text: str) -> List[str]:
    """
    Extracts all http(s) URLs from the message text using regex.

    Returns:
        List of raw URL strings, in the order they appear, with
        duplicates removed but original order preserved.
    """
    matches = URL_REGEX.findall(text)
    seen: Set[str] = set()
    unique_urls: List[str] = []
    for url in matches:
        # Trim common trailing punctuation that regex may accidentally
        # capture, e.g. a URL immediately followed by a period or comma
        # at the end of a sentence.
        cleaned = url.rstrip(").,;:!?")
        if cleaned not in seen:
            unique_urls.append(cleaned)
            seen.add(cleaned)
    return unique_urls


def _extract_domain(url: str) -> str:
    """
    Extracts the domain (host) portion of a URL without relying on
    the `urllib.parse` module's full feature set, to keep this
    beginner-readable. Handles the common case of
    'scheme://host[:port][/path...]'.
    """
    without_scheme = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    # Domain ends at the first '/', '?', or '#'
    domain = re.split(r"[/?#]", without_scheme, maxsplit=1)[0]
    # Strip a port number if present, e.g. example.com:8080
    domain = domain.split(":")[0]
    # Strip userinfo if present, e.g. user@example.com
    if "@" in domain:
        domain = domain.split("@")[-1]
    return domain.lower()


def _check_typosquatting(domain: str) -> str | None:
    """
    Heuristically checks whether `domain` looks like it is impersonating
    a well-known brand without actually being that brand's real domain.

    CONCEPT (Typosquatting & Homograph Attacks): Attackers register
    domains that are visually or textually similar to a trusted brand,
    e.g.:
        - Character substitution: "amaz0n" (zero for 'o'),
          "paypa1" (one for 'l') -- a classic "homograph" trick that
          exploits how similar certain characters look.
        - Added words: "microsoft-login", "applestore-security" --
          exploits the fact that people skim domains rather than
          reading them carefully, and that a familiar brand name
          appearing *anywhere* in a domain feels reassuring.
        - Real brand domains are typically just "brand.com" (or a small
          number of known official domains) -- not
          "brand-something.tld" or "brandsomething.tld".

    Returns:
        The brand name being impersonated, or None if no impersonation
        pattern is detected.
    """
    domain_no_tld = re.sub(r"\.[a-z]{2,}$", "", domain, flags=re.IGNORECASE)
    normalized = domain_no_tld.lower()
    # Common leetspeak substitutions attackers use to fool quick visual
    # scanning: 0->o, 1->l/i, 3->e, 5->s, 4->a
    de_leeted = (
        normalized.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("4", "a")
    )

    for brand in IMPERSONATED_BRANDS:
        if brand in normalized or brand in de_leeted:
            # If the domain IS simply "<brand>.<tld>" it's plausibly the
            # real company -- we don't flag exact matches, only
            # look-alikes (brand embedded alongside other text/characters,
            # or altered via leetspeak).
            if normalized == brand:
                continue
            return brand
    return None


def analyze_urls(urls: List[str]) -> List[UrlFinding]:
    """
    Runs every URL-based heuristic against each extracted URL and
    returns a structured UrlFinding per URL.

    Heuristics applied:
        1. IP-address-based host (e.g. http://192.168.10.10/login)
        2. Known URL shortener domain (e.g. bit.ly)
        3. Non-standard/high-abuse TLD (e.g. .xyz, .top)
        4. Domain present in the simulated blacklist
        5. Typosquatting / brand impersonation
        6. Excessive subdomains (e.g. login.security.paypal.fake.com)
        7. Overall URL length (very long URLs are harder for a human
           to visually verify and are often used to bury a malicious
           real destination after a long, legitimate-looking prefix)

    Args:
        urls: Raw URL strings from extract_urls().

    Returns:
        List of UrlFinding objects, one per input URL.
    """
    findings: List[UrlFinding] = []

    for url in urls:
        domain = _extract_domain(url)
        finding = UrlFinding(url=url, domain=domain)

        # 1. IP-based URL
        host_only = domain.split(":")[0]
        if IP_HOST_REGEX.match(host_only):
            finding.is_ip_based = True
            finding.reasons.append(
                "Uses a raw IP address instead of a domain name "
                "(legitimate organizations essentially never link "
                "directly to an IP address)."
            )

        # 2. URL shortener
        if domain in URL_SHORTENERS:
            finding.is_shortener = True
            finding.reasons.append(
                f"Uses the URL shortener '{domain}', which hides the "
                "true destination address."
            )

        # 3. Suspicious / high-abuse TLD
        tld = domain.split(".")[-1] if "." in domain else ""
        if tld in SUSPICIOUS_TLDS:
            finding.reasons.append(
                f"Uses the top-level domain '.{tld}', which is "
                "inexpensive to register in bulk and is "
                "disproportionately used in phishing campaigns."
            )

        # 4. Simulated blacklist match
        if domain in SIMULATED_BLACKLIST:
            finding.is_blacklisted = True
            finding.reasons.append(
                "Domain matches a known-malicious entry in the "
                "simulated threat-intelligence blacklist."
            )

        # 5. Typosquatting / brand impersonation
        impersonated = _check_typosquatting(domain)
        if impersonated:
            finding.impersonated_brand = impersonated
            finding.reasons.append(
                f"Domain appears to impersonate the brand "
                f"'{impersonated.title()}' (typosquatting/homograph "
                "pattern) without being that brand's real domain."
            )

        # 6. Excessive subdomains (more than 3 labels before the TLD is
        # unusual for legitimate consumer-facing login pages, and is a
        # technique used to bury a fake brand name in a long, official-
        # looking hostname, e.g. "paypal.com.verify-account.xyz").
        labels = domain.split(".")
        if len(labels) > 4:
            finding.reasons.append(
                f"Unusually high number of subdomains ({len(labels)} "
                "labels), a technique sometimes used to make a "
                "fraudulent domain look like a legitimate subdomain "
                "of a trusted brand."
            )

        # 7. Excessively long URL
        if len(url) > 90:
            finding.reasons.append(
                f"URL is unusually long ({len(url)} characters), making "
                "it difficult for a human to visually verify the real "
                "destination."
            )

        findings.append(finding)

    return findings


# ======================================================================
# SECTION 5: RISK SCORING
# ======================================================================

def calculate_risk_score(
    keywords: List[str],
    credential_requests: List[str],
    urgency_fear: List[str],
    authority: List[str],
    url_findings: List[UrlFinding],
) -> int:
    """
    Combines every detected signal into a single 0-100 risk score.

    SCORING METHODOLOGY (explained in full, as required by the spec):
    Each category of finding contributes a fixed number of points per
    unique item detected (see SCORE_WEIGHTS), up to a per-category
    maximum (see CATEGORY_CAP) so that no single category can dominate
    the score on its own -- e.g., an email that happens to repeat the
    word "urgent" five times should NOT score as high as one that
    combines a blacklisted, brand-impersonating URL with a genuine
    request for a password.

    Category contributions:
        - Suspicious keywords:        6 pts each, capped at 18
        - Credential requests:        12 pts each, capped at 24
        - Urgency/fear phrases:       10 pts each, capped at 20
        - Authority phrases:          6 pts each, capped at 12
        - Each suspicious URL:        15 pts (any single trigger reason)
          -> capped at 30 total across all suspicious URLs
        - URL shorteners:             10 pts each, capped at 20
        - IP-based URLs:              15 pts each, capped at 15
        - Blacklisted domains:        25 pts each, capped at 25
        - Brand impersonation:        20 pts each, capped at 20

    All category subtotals are summed, then the grand total is clamped
    to the range [0, 100] so the score always stays interpretable as
    "percent confidence this is phishing."

    NOTE ON REALISM: This is a transparent, rule-based scoring model
    designed for teaching purposes. A production anti-phishing system
    would instead train a statistical or ML model on a large labeled
    dataset to learn these weights empirically, rather than having a
    human assign them by intuition, as we do here.

    Returns:
        Integer risk score from 0 to 100.
    """
    def capped(count: int, weight: int, cap: int) -> int:
        return min(count * weight, cap)

    total = 0
    total += capped(len(keywords), SCORE_WEIGHTS["keyword"], CATEGORY_CAP["keyword"])
    total += capped(
        len(credential_requests),
        SCORE_WEIGHTS["credential_request"],
        CATEGORY_CAP["credential_request"],
    )
    total += capped(
        len(urgency_fear), SCORE_WEIGHTS["urgency_fear"], CATEGORY_CAP["urgency_fear"]
    )
    total += capped(
        len(authority), SCORE_WEIGHTS["authority"], CATEGORY_CAP["authority"]
    )

    suspicious_urls = [f for f in url_findings if f.is_suspicious]
    total += capped(
        len(suspicious_urls),
        SCORE_WEIGHTS["suspicious_url"],
        CATEGORY_CAP["suspicious_url"],
    )

    shorteners = [f for f in url_findings if f.is_shortener]
    total += capped(
        len(shorteners),
        SCORE_WEIGHTS["url_shortener"],
        CATEGORY_CAP["url_shortener"],
    )

    ip_based = [f for f in url_findings if f.is_ip_based]
    total += capped(
        len(ip_based), SCORE_WEIGHTS["ip_based_url"], CATEGORY_CAP["ip_based_url"]
    )

    blacklisted = [f for f in url_findings if f.is_blacklisted]
    total += capped(
        len(blacklisted),
        SCORE_WEIGHTS["blacklisted_domain"],
        CATEGORY_CAP["blacklisted_domain"],
    )

    impersonating = [f for f in url_findings if f.impersonated_brand]
    total += capped(
        len(impersonating),
        SCORE_WEIGHTS["brand_impersonation"],
        CATEGORY_CAP["brand_impersonation"],
    )

    return max(0, min(total, 100))


def classify_risk_level(score: int) -> str:
    """
    Maps a numeric risk score to a human-readable risk level.

    Thresholds (documented rationale):
        0-24   -> LOW      : isolated or no red flags; likely benign.
        25-59  -> MEDIUM   : some red flags present; warrants caution
                              and independent verification.
        60-100 -> HIGH     : multiple strong red flags; treat as
                              phishing until proven otherwise.

    These thresholds are intentionally simple round numbers for
    teaching purposes. Production systems tune thresholds against
    labeled data to balance false positive vs. false negative rates.
    """
    if score >= 60:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


# ======================================================================
# SECTION 6: RED FLAG CHECKLIST & RECOMMENDATIONS
# ======================================================================

def build_red_flag_checklist(result: AnalysisResult) -> List[str]:
    """
    Builds a plain-English checklist of every distinct red flag category
    detected, suitable for showing to a non-technical employee
    (Optional Feature #1).
    """
    checklist: List[str] = []

    if result.keywords_found:
        checklist.append("Suspicious keywords/phrases present")
    if result.credential_requests_found:
        checklist.append("Requests sensitive credentials or personal data")
    if "Urgency" in result.social_engineering_techniques:
        checklist.append("Creates a false sense of urgency")
    if "Fear" in result.social_engineering_techniques:
        checklist.append("Uses fear/threat-based language")
    if "Authority" in result.social_engineering_techniques:
        checklist.append("Impersonates or invokes a trusted authority")
    if any(f.is_suspicious for f in result.url_findings):
        checklist.append("Contains at least one suspicious URL")
    if any(f.is_ip_based for f in result.url_findings):
        checklist.append("Link uses a raw IP address instead of a domain")
    if any(f.is_shortener for f in result.url_findings):
        checklist.append("Uses a URL shortener to hide the real destination")
    if any(f.is_blacklisted for f in result.url_findings):
        checklist.append("Link domain matches a known-malicious blacklist entry")
    if any(f.impersonated_brand for f in result.url_findings):
        checklist.append("Link domain impersonates a well-known brand")

    return checklist


def generate_recommendations(result: AnalysisResult) -> List[str]:
    """
    Produces tailored security recommendations based on which specific
    categories of red flags were detected (Optional Feature #6).
    """
    recs: List[str] = []

    if result.risk_level == "LOW":
        recs.append("No significant phishing indicators were detected, "
                     "but always remain cautious with unexpected emails.")
        return recs

    if any(f.is_suspicious for f in result.url_findings):
        recs.append("Do not click any links in this message.")
    if any(f.is_blacklisted for f in result.url_findings):
        recs.append("This link matches a known-malicious domain — "
                     "do not visit it under any circumstances.")
    if any(f.impersonated_brand for f in result.url_findings):
        recs.append("Do not trust the sender's claimed identity — "
                     "verify by contacting the company directly through "
                     "its official website or phone number, not any "
                     "contact info in this message.")
    if result.credential_requests_found:
        recs.append("Never share passwords, PINs, OTPs, or financial "
                     "details in response to an email.")
    if result.social_engineering_techniques:
        recs.append("Slow down — urgency and fear are common phishing "
                     "tactics designed to prevent careful thinking.")

    recs.append("Verify the sender's email address independently before "
                "taking any action.")
    recs.append("Report this message to your IT/security department.")

    if result.risk_level == "HIGH":
        recs.append("Delete the message after reporting it.")

    # De-duplicate while preserving order (in case multiple triggers
    # produced the same recommendation text).
    seen: Set[str] = set()
    unique_recs: List[str] = []
    for r in recs:
        if r not in seen:
            unique_recs.append(r)
            seen.add(r)
    return unique_recs


# ======================================================================
# SECTION 7: ORCHESTRATION
# ======================================================================

def analyze_message(text: str) -> AnalysisResult:
    """
    Runs the full detection pipeline against a message and returns a
    populated AnalysisResult. This is the single "entry point" function
    that ties every detector together, keeping main() itself very thin
    (main() should just handle I/O, not business logic).

    Args:
        text: The raw email/message text to analyze.

    Returns:
        A fully populated AnalysisResult.

    Raises:
        ValueError: if `text` is empty or only whitespace.
    """
    if not text or not text.strip():
        raise ValueError("Cannot analyze an empty message.")

    result = AnalysisResult(original_text=text)

    result.keywords_found = detect_keywords(text)
    result.credential_requests_found = detect_credential_requests(text)
    result.urgency_fear_found = detect_urgency_fear(text)
    result.authority_found = detect_authority(text)
    result.social_engineering_techniques = detect_social_engineering(
        result.urgency_fear_found, result.authority_found,
        result.credential_requests_found,
    )

    urls = extract_urls(text)
    result.url_findings = analyze_urls(urls)

    result.risk_score = calculate_risk_score(
        result.keywords_found,
        result.credential_requests_found,
        result.urgency_fear_found,
        result.authority_found,
        result.url_findings,
    )
    result.risk_level = classify_risk_level(result.risk_score)
    result.red_flag_checklist = build_red_flag_checklist(result)
    result.recommendations = generate_recommendations(result)

    return result


# ======================================================================
# SECTION 8: REPORT GENERATION / DISPLAY
# ======================================================================

def generate_report(result: AnalysisResult) -> str:
    """
    Formats an AnalysisResult into the final human-readable report
    string (matching the style requested in the project spec).

    Separating "build the report string" (this function) from "print it
    to the console" (display_results()) makes the report reusable —
    e.g., it could be written to a file or sent over an API without
    any change to this function.
    """
    lines: List[str] = []
    add = lines.append

    add("=" * 40)
    add("PHISHING ANALYSIS REPORT")
    add("=" * 40)
    add("")

    add("Suspicious Keywords")
    add("-" * 20)
    if result.keywords_found:
        for kw in result.keywords_found:
            add(f"- {kw.title()}")
    else:
        add("- None detected")
    add("")

    add("Suspicious URLs")
    add("-" * 20)
    suspicious = [f for f in result.url_findings if f.is_suspicious]
    if suspicious:
        for finding in suspicious:
            add(f"- {finding.url}")
            for reason in finding.reasons:
                add(f"    -> {reason}")
    elif result.url_findings:
        add("- URLs found, but none were flagged as suspicious")
    else:
        add("- None detected")
    add("")

    add("Credential Requests")
    add("-" * 20)
    if result.credential_requests_found:
        for term in result.credential_requests_found:
            add(f"- {term.title()}")
    else:
        add("- None detected")
    add("")

    add("Social Engineering Techniques")
    add("-" * 20)
    if result.social_engineering_techniques:
        for tech in result.social_engineering_techniques:
            add(f"- {tech}")
    else:
        add("- None detected")
    add("")

    if result.red_flag_checklist:
        add("Red Flag Checklist")
        add("-" * 20)
        for flag in result.red_flag_checklist:
            add(f"[X] {flag}")
        add("")

    add("Risk Score")
    add("-" * 20)
    add(f"{result.risk_score} / 100")
    add("")

    add("Risk Level")
    add("-" * 20)
    add(result.risk_level)
    add("")

    add("Conclusion")
    add("-" * 20)
    conclusions = {
        "LOW": "This message shows no strong indicators of phishing, "
               "but general caution is always warranted.",
        "MEDIUM": "This message contains some suspicious indicators and "
                  "should be treated with caution. Verify independently "
                  "before acting on it.",
        "HIGH": "This message is highly likely to be a phishing attempt.",
    }
    add(conclusions[result.risk_level])
    add("")

    add("Recommendations")
    add("-" * 20)
    for rec in result.recommendations:
        add(f"* {rec}")
    add("")
    add("=" * 40)

    return "\n".join(lines)


def display_results(result: AnalysisResult) -> None:
    """Prints the formatted report to the console."""
    print("\n" + generate_report(result))


# ======================================================================
# SECTION 9: MAIN PROGRAM
# ======================================================================

def _prompt_input_source() -> str:
    """
    Interactively asks the user whether they want to paste a message
    or load one from a file, and returns the resulting raw text.
    Isolated from main() to keep main() readable at a glance.
    """
    print("Phishing Awareness Analyzer")
    print("=" * 40)
    print("1) Paste an email/message")
    print("2) Load a message from a .txt file")
    choice = input("Select an option (1 or 2): ").strip()

    if choice == "2":
        filepath = input("Enter the path to the .txt file: ").strip()
        try:
            return load_message_from_file(filepath)
        except (FileNotFoundError, ValueError) as exc:
            print(f"\n[Error] {exc}")
            print("Falling back to manual paste input.\n")
            return get_user_input()

    return get_user_input()


def main() -> None:
    """
    Program entry point. Handles I/O and error presentation only; all
    analysis logic lives in analyze_message() and its helpers, per the
    single-responsibility principle.
    """
    try:
        text = _prompt_input_source()
        result = analyze_message(text)
        display_results(result)
    except ValueError as exc:
        # Raised by analyze_message() for empty input, or by our own
        # input validation -- a clean, expected error path.
        print(f"\n[Error] {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nAnalysis cancelled by user.")
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001 - top-level safety net
        # Catch-all so an unexpected bug never dumps a raw traceback on
        # a non-technical user; still surfaces the error for debugging.
        print(f"\n[Unexpected Error] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()