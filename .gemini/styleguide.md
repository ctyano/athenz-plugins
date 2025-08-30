# Style Guide

## Introduction

This style guide outlines the coding conventions for athenz-plugins.
This repository provides plugins for Athenz servers as jar files and as container images.
The repository runs GitHub Action workflows to run unit tests and to build the jar package.

## Key Principles

* **Readability:** Code should be easy to understand for all team members.
* **Maintainability:** Code should be easy to modify and extend.
* **Consistency:** Adhering to a consistent style across all projects improves
  collaboration and reduces errors.
* **Performance:** While readability is paramount, code should be efficient.

## Review format

When reviewing Pull Requests, follow the details and produce a structured summary in markdown with:

1. **Pull Request Title**  
2. **Summary of Changes** – High-level overview of what's modified or added.  
3. **Motivation** – Why these changes were made.  
4. **Impact** – How it affects Athenz Distribution (e.g., package builds, container behavior, UX, configuration).  
5. **Tests & Validation** – Indicate whether new or updated tests are present, or specify what testing is missing.  
6. **Potential Risks & Considerations** – Any breaking changes, backward compatibility concerns, or infrastructure implications.  
7. **Reviewer Checklist** – A bullet-list of followup questions or checkpoints for humans: e.g., “Does this require version bump?”, “Need documentation update?”, “Tested on x86_64 and arm64?”, etc.

Use concise, technical language, formatted with markdown headings, bullet lists, and bold labels. If context from the athenz-distribution repository matters (e.g., Makefile targets, container images, pkg formats), weave it in where relevant.

