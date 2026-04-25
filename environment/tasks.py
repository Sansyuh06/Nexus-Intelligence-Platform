"""
CVE-Triage-Env: Task definitions.

Four tasks of increasing difficulty, each targeting a different CVE.
Includes a Level 4 "expert" task with remediation + unreliable sources.
"""

from __future__ import annotations

from environment.models import TaskConfig


TASKS: list[TaskConfig] = [
    TaskConfig(
        task_id="easy",
        name="GAV Extraction",
        description=(
            "Given CVE-2022-42889 (Text4Shell), identify the affected "
            "Group-Artifact-Version coordinates and the safe upgrade version. "
            "Use search_nvd and lookup_gav to gather "
            "information, then submit. "
            "Include your confidence (0.0-1.0) in your submission."
        ),
        difficulty="easy",
        cve_id="CVE-2022-42889",
        ground_truth={
            "group": "org.apache.commons",
            "artifact": "commons-text",
            "safe_version": "1.10.0",
        },
        max_steps=7,
    ),
    TaskConfig(
        task_id="medium",
        name="Method Discovery",
        description=(
            "Given CVE-2021-44228 (Log4Shell), identify the GAV coordinates, "
            "the specific vulnerable method, and the safe upgrade version. "
            "WARNING: Some tool outputs may contain inaccurate information. "
            "Cross-verify across multiple sources before submitting. "
            "Include your confidence (0.0-1.0) in your submission."
        ),
        difficulty="medium",
        cve_id="CVE-2021-44228",
        ground_truth={
            "group": "org.apache.logging.log4j",
            "artifact": "log4j-core",
            "vulnerable_method": "lookup",
            "safe_version": "2.15.0",
        },
        max_steps=8,
    ),
    TaskConfig(
        task_id="hard",
        name="Invocation Check",
        description=(
            "Given CVE-2022-22965 (Spring4Shell), "
            "perform a full investigation: "
            "identify GAV coordinates, the vulnerable method, "
            "whether the vulnerable method is actually invoked "
            "in the provided code snippet, "
            "and the safe upgrade version. CAUTION: "
            "Information sources may be "
            "unreliable. Use simulate_exploit to verify your findings. "
            "Include your confidence (0.0-1.0) in your submission."
        ),
        difficulty="hard",
        cve_id="CVE-2022-22965",
        ground_truth={
            "group": "org.springframework",
            "artifact": "spring-webmvc",
            "vulnerable_method": "bind",
            "invoked": False,
            "safe_version": "5.3.18",
        },
        max_steps=12,
    ),
    TaskConfig(
        task_id="expert",
        name="Full Investigation + Remediation",
        description=(
            "Given only CVE-2021-42550 (Logback JNDI), perform a complete "
            "security investigation from scratch. You must: (1) discover the "
            "affected package and version, "
            "(2) identify the vulnerable method, "
            "(3) determine if the method is invoked "
            "in the target code, "
            "(4) verify via exploit simulation, "
            "and (5) suggest a remediation. "
            "CRITICAL: Tool outputs may contain "
            "corrupted information. "
            "Cross-verify everything. "
            "Include your confidence (0.0-1.0)."
        ),
        difficulty="expert",
        cve_id="CVE-2021-42550",
        ground_truth={
            "group": "ch.qos.logback",
            "artifact": "logback-classic",
            "vulnerable_method": "startDocument",
            "invoked": False,
            "safe_version": "1.2.11",
            "patch_action": "upgrade",
        },
        max_steps=15,
    ),
]


def get_task(task_id: str) -> TaskConfig:
    """Look up a task by ID.

    Raises:
        ValueError: If *task_id* does not match any defined task.
    """
    for task in TASKS:
        if task.task_id == task_id:
            return task
    valid_ids = ", ".join(t.task_id for t in TASKS)
    raise ValueError(
        f"Task '{task_id}' not found. Valid IDs: {valid_ids}"
    )
