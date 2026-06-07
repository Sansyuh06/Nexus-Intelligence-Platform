"""
CVE-Guard: Gemini 3 Reasoning Engine.

Uses the Google Gemini API to intelligently extract vulnerable methods
from CVE descriptions, reason about exploitability, and determine
whether source code invocations are actually dangerous.

This is what makes CVE-Guard an *agent* — not a script.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from ..config import config

logger = logging.getLogger(__name__)

# Known CVE → method mappings as fallback when Gemini is unavailable
_KNOWN_METHODS: Dict[str, Dict[str, str]] = {
    "CVE-2021-44228": {
        "method": "JndiLookup.lookup()",
        "class": "org.apache.logging.log4j.core.lookup.JndiLookup",
        "patterns": "JndiLookup,lookup,LogManager.getLogger,JNDI",
    },
    "CVE-2022-22965": {
        "method": "CachedIntrospectionResults.forClass()",
        "class": "org.springframework.beans.CachedIntrospectionResults",
        "patterns": "ClassPathXmlApplicationContext,getClass,forName,getRuntime",
    },
    "CVE-2022-42889": {
        "method": "StringSubstitutor.replace()",
        "class": "org.apache.commons.text.StringSubstitutor",
        "patterns": "StringSubstitutor,replace,lookup,ScriptStringLookup",
    },
    "CVE-2021-42550": {
        "method": "JoranConfigurator.startDocument()",
        "class": "ch.qos.logback.core.joran.spi.JoranConfigurator",
        "patterns": "startDocument,JoranConfigurator,insertFromJNDI",
    },
}


class GeminiEngine:
    """Wraps the Google Gemini API for CVE reasoning tasks."""

    def __init__(self) -> None:
        self._client = None
        self._model = config.gemini_model
        if config.has_gemini:
            try:
                from google import genai
                self._client = genai.Client(api_key=config.gemini_api_key)
                logger.info("Gemini engine initialised with model: %s", self._model)
            except ImportError:
                logger.warning(
                    "google-genai package not installed. "
                    "Install with: pip install google-genai"
                )
            except Exception as exc:
                logger.warning("Failed to initialise Gemini client: %s", exc)

    @property
    def available(self) -> bool:
        return self._client is not None

    # ── Method Extraction ───────────────────────────────────────────

    def extract_vulnerable_method(
        self,
        cve_id: str,
        description: str,
        package_name: str = "",
    ) -> Dict[str, str]:
        """Use Gemini to extract the vulnerable method from a CVE description.

        Falls back to regex / known-method lookup when Gemini is unavailable.
        """
        # Fast path: known CVE
        if cve_id in _KNOWN_METHODS:
            logger.info("Using known method mapping for %s", cve_id)
            return _KNOWN_METHODS[cve_id]

        if not self.available or not description:
            return {"method": "Unknown", "class": "Unknown", "patterns": ""}

        prompt = f"""You are a security researcher. Given a CVE description, extract the specific vulnerable method.

CVE ID: {cve_id}
Package: {package_name}
Description: {description}

Respond with ONLY a JSON object (no markdown, no code fences):
{{
  "method": "ClassName.methodName()",
  "class": "fully.qualified.ClassName",
  "patterns": "comma,separated,search,patterns,for,grep"
}}

If you cannot determine the method, use "Unknown" for method and class."""

        try:
            response = self._client.models.generate_content(
                model=self._model,
                contents=prompt,
            )
            text = response.text.strip()
            # Strip markdown fences if present
            if text.startswith("```"):
                text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            result = json.loads(text)
            logger.info("Gemini extracted method for %s: %s", cve_id, result.get("method"))
            return result
        except Exception as exc:
            logger.warning("Gemini method extraction failed for %s: %s", cve_id, exc)
            return {"method": "Unknown", "class": "Unknown", "patterns": ""}

    # ── Invocation Analysis ─────────────────────────────────────────

    def analyse_invocation(
        self,
        vulnerable_method: str,
        source_code: str,
        file_path: str,
    ) -> Dict[str, Any]:
        """Use Gemini to determine if a code snippet actually invokes the vulnerable path.

        This goes beyond regex — it reasons about whether the usage pattern
        is actually exploitable (e.g., user-controlled input reaching the method).
        """
        if not self.available or not source_code:
            return {"invoked": False, "confidence": 0.0, "reasoning": "Gemini unavailable"}

        prompt = f"""You are a security auditor. Analyse this source code to determine if it invokes the vulnerable method in a way that is exploitable.

Vulnerable method: {vulnerable_method}
File: {file_path}

Source code:
```
{source_code[:3000]}
```

Respond with ONLY a JSON object (no markdown, no code fences):
{{
  "invoked": true/false,
  "confidence": 0.0 to 1.0,
  "line_number": number or null,
  "reasoning": "brief explanation"
}}"""

        try:
            response = self._client.models.generate_content(
                model=self._model,
                contents=prompt,
            )
            text = response.text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            result = json.loads(text)
            logger.info(
                "Gemini invocation analysis for %s: invoked=%s confidence=%s",
                file_path, result.get("invoked"), result.get("confidence"),
            )
            return result
        except Exception as exc:
            logger.warning("Gemini invocation analysis failed: %s", exc)
            return {"invoked": False, "confidence": 0.0, "reasoning": f"Analysis error: {exc}"}

    # ── Cross-Verification Reasoning ────────────────────────────────

    def resolve_source_conflict(
        self,
        cve_id: str,
        source_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """When NVD, OSV, and GitHub Advisory disagree, ask Gemini to reason
        about which source is most likely correct and why."""
        if not self.available:
            return {"resolution": "unknown", "reasoning": "Gemini unavailable"}

        prompt = f"""You are a CVE analyst. Multiple vulnerability databases returned conflicting information for {cve_id}. Determine which source is most likely correct.

Source data:
{json.dumps(source_data, indent=2, default=str)[:3000]}

Respond with ONLY a JSON object (no markdown, no code fences):
{{
  "resolution": "agree" or "conflict",
  "most_trusted_source": "NVD" or "OSV" or "GitHub Advisory",
  "recommended_safe_version": "version string",
  "confidence": 0.0 to 1.0,
  "reasoning": "brief explanation of why sources disagree and which to trust"
}}"""

        try:
            response = self._client.models.generate_content(
                model=self._model,
                contents=prompt,
            )
            text = response.text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            return json.loads(text)
        except Exception as exc:
            logger.warning("Gemini conflict resolution failed: %s", exc)
            return {"resolution": "unknown", "reasoning": f"Error: {exc}"}


# Singleton
gemini = GeminiEngine()
