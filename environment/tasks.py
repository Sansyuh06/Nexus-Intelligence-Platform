"""
CVE-Triage-Env: Task definitions.

Three tasks of increasing difficulty, each targeting a different CVE.
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
            "Use search_nvd and lookup_gav to gather information, then submit."
        ),
        difficulty="easy",
        cve_id="CVE-2022-42889",
        ground_truth={
            "group": "org.apache.commons",
            "artifact": "commons-text",
            "safe_version": "1.10.0",
        },
        max_steps=5,
    ),
    TaskConfig(
        task_id="medium",
        name="Method Discovery",
        description=(
            "Given CVE-2021-44228 (Log4Shell), identify the GAV coordinates, "
            "the specific vulnerable method, and the safe upgrade version. "
            "Use search_nvd, fetch_advisory, and search_method to investigate, "
            "then submit your findings."
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
            "Given CVE-2022-22965 (Spring4Shell), perform a full investigation: "
            "identify GAV coordinates, the vulnerable method, whether the "
            "vulnerable method is actually invoked in the provided code snippet, "
            "and the safe upgrade version. Use all available actions to "
            "investigate before submitting."
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
