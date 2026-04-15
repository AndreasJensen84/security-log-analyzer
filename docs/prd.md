# PRD: security-log-analyzer v1

## Problem Statement

I want a small but realistic Python project that helps me learn how to build software step by step with AI while still understanding the structure and logic myself. The project should analyze Microsoft Entra sign-in exports locally, detect a few meaningful security findings, and produce a readable summary without requiring cloud deployment, complex infrastructure, or a large codebase.

The project also needs to be safe for a public repository. Real sign-in logs may be used locally for development and testing, but raw exports must never be committed or exposed publicly. The code should therefore be designed around a clear separation between private input data and public source code, with sanitized fixtures used for tests.

## Solution

Build a local Python CLI that accepts a path to either a Microsoft Entra sign-in JSON file or a directory containing multiple exported sign-in JSON files. The tool will load both interactive and non-interactive sign-ins, normalize them into a simple internal event model, convert timestamps from UTC into Norway local time, run a small set of deterministic security checks, and print a human-readable report.

The first version should stay intentionally small and beginner-friendly. It should focus on a clean internal structure, strong tests around externally visible behavior, and logic that is easy to explain in an interview or walkthrough. A future AI summary can be planned as an extension point, but not implemented as a real integration in v1.

## User Stories

1. As a learner building with AI, I want the project broken into small modules, so that I can understand each responsibility clearly.
2. As a learner practicing TDD, I want the project to grow through small test-first steps, so that I can see how requirements become code.
3. As a local user, I want to run the analyzer on my own machine, so that I do not need any cloud deployment or hosted service.
4. As a user of Microsoft Entra exports, I want the tool to accept the raw exported JSON shape, so that I do not need to manually reformat data before analysis.
5. As a user with multiple export files, I want the tool to read both interactive and non-interactive sign-in exports, so that I get a more complete picture of activity.
6. As a user with large export files, I want the analyzer to normalize only the fields needed for v1, so that the implementation stays simple and understandable.
7. As a user reading security findings, I want failed sign-ins to be counted correctly, so that I can quickly understand baseline sign-in health.
8. As a user investigating suspicious activity, I want the analyzer to detect repeated failed logins for the same user within a short time window, so that possible brute-force or password-spraying patterns stand out.
9. As a user reviewing work-hours activity, I want the analyzer to flag logins outside 08:00 to 16:00 in Norway local time, so that unusual access times are visible.
10. As a user in Norway, I want timestamps interpreted in Europe/Oslo local time, so that off-hours logic matches real local working hours including daylight-saving changes.
11. As a user reviewing the output, I want a short summary section first, so that I can understand the overall results immediately.
12. As a user reviewing findings, I want repeated-failure and off-hours results shown in separate sections, so that each type of risk is easy to scan.
13. As a user reading a public codebase, I want the internal analysis rules to be explicit and deterministic, so that I can explain why each finding appeared.
14. As a user running the tool against messy real data, I want clear error messages for missing files, invalid JSON, missing required fields, and invalid timestamps, so that failures are understandable.
15. As a user running the tool on an empty export, I want a graceful no-data result, so that the tool does not crash or produce confusing output.
16. As a user reviewing findings over multiple files, I want results combined into one report, so that I do not need to manually compare separate outputs.
17. As a beginner Python developer, I want the core logic implemented with straightforward dataclasses, functions, and standard library modules, so that the code is easy to follow.
18. As a project owner using a public repository, I want raw sign-in logs excluded from version control, so that private security data is not exposed.
19. As a future maintainer, I want the AI summary represented as a clearly isolated extension point, so that it can be added later without restructuring the project.
20. As a learner preparing to discuss the project, I want the report output to be deterministic and readable, so that I can confidently explain what the tool does and how it works.
21. As a learner exploring clean architecture, I want file I/O, domain logic, rendering, and CLI orchestration separated, so that each part can be tested in isolation.
22. As a future user of the tool, I want sensible defaults for analysis rules in v1, so that I can get value without needing many command-line flags.

## Implementation Decisions

- The tool will support Microsoft Entra sign-in exports in JSON format, specifically the interactive and non-interactive export files available from the local input path.
- The input path may point to either a single JSON file or a directory containing multiple JSON exports. When a directory is supplied, supported sign-in files are combined into one analysis run.
- Managed identity sign-ins are out of the main analysis scope for v1. If such a file is present, it may be ignored without failing the run.
- A normalization layer will convert raw Entra records into a smaller internal event model that exposes only the fields needed for v1 analysis.
- The normalized event model will include at minimum the event timestamp, user identity, IP address, success or failure outcome, failure metadata, and whether the sign-in was interactive.
- Success and failure will be derived from the Entra status object. An error code of `0` will be treated as success; any other code will be treated as failure.
- Timestamps from the raw export will be parsed as UTC and converted into `Europe/Oslo` local time before any off-hours analysis is performed.
- Off-hours logic will classify events outside `08:00` through `16:00` local time as suspicious for v1.
- Weekend sign-ins will also be treated as off-hours in v1, because the project goal is a simple, understandable heuristic rather than a fully customizable policy engine.
- Repeated failed logins will be detected per user using a threshold of `3` failed sign-ins within a rolling `15-minute` window.
- The analysis layer will be implemented as pure logic over normalized events and explicit configuration values, keeping the core security checks independent from file handling and CLI concerns.
- The report layer will generate a deterministic plain-text summary with a short overview first, followed by findings sections for repeated failures and off-hours activity.
- The CLI surface will remain intentionally small in v1. The primary command contract will be to pass an input path and receive a report on standard output.
- Analysis defaults will be defined in code through an explicit configuration object rather than scattered constants, making later CLI flags or custom settings easier to add.
- The project will favor standard library tools such as dataclasses, pathlib, json, argparse, and zoneinfo to keep the code readable and beginner-friendly.
- The design will preserve a clean extension point for an optional future AI summary, but no networked AI call will be implemented in v1.
- Privacy is a first-class project constraint. Real exported logs are local development inputs only and must remain outside version control.

## Testing Decisions

- A good test will verify externally visible behavior rather than internal implementation details. Tests should confirm what the loader returns, what the analyzer detects, and what the report prints, without coupling to private helper structure.
- Tests should use small, sanitized fixtures that represent realistic Entra events while avoiding any sensitive real-user data.
- The loader module will be tested for single-file loading, directory loading, support for both interactive and non-interactive exports, normalization of Entra records, success and failure classification, timezone conversion, and graceful handling of empty files or unsupported inputs.
- The analyzer module will be tested for failed-login counts, repeated-failure detection within the 15-minute rule, boundary behavior around the threshold, off-hours detection in `Europe/Oslo`, and weekend classification.
- The report module will be tested for stable, readable output structure, correct counts, correct inclusion of findings, and sensible output when no findings exist.
- The CLI module will receive a small number of smoke tests to confirm argument handling, successful end-to-end execution, and readable error output on invalid input.
- Existing test style in the codebase already establishes a useful starting pattern: small pytest tests using temporary files and direct assertions on public behavior. New tests should continue that style rather than introducing a heavier framework.
- Test data committed to the repository should always be synthetic or sanitized. Real local exports should remain ignored and never become fixtures.

## Out of Scope

- Real AI or LLM integration in v1.
- A web UI, API service, or database-backed application.
- Full Microsoft Entra schema coverage beyond the fields needed for the selected checks.
- Custom policy engines, user-specific schedules, or organization-wide exception rules.
- Geolocation risk scoring, impossible-travel detection, MFA posture analysis, or advanced threat intelligence.
- Automated remediation actions such as disabling accounts or sending alerts.
- Streaming ingestion, continuous monitoring, or scheduled background jobs.
- Managed identity analysis as a first-class feature in v1.

## Further Notes

- This project is explicitly both a learning exercise and a small realistic tool. Code clarity matters more than feature breadth.
- The most important architectural goal is to keep domain logic explainable. The learner should be able to describe how raw records become findings in a simple narrative.
- The implementation should be developed in small TDD slices so that each feature adds one clear behavior at a time.
- If future iterations add configurability, the existing explicit analysis configuration should be extended rather than mixing policy values directly into the CLI or report code.
- If future iterations add an AI summary, it should consume already-generated findings rather than reading raw logs directly.
