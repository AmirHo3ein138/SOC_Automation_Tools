# SOC Automation Tools

## About This Repository

This repository is a personal collection of tools I've built to solve problems I run into on a daily basis as a SOC Analyst. Each tool starts from a real, recurring need in an operational SOC environment — where a large part of daily work (alert triage, checking Indicators of Compromise, and documenting findings) is still done manually across several disconnected sources, wasting time and increasing the risk of human error.

The goal of this project is to automate parts of these workflows with a focus on **Blue Team Operations**. It's not meant to be a commercial product or a generic framework — it's a set of practical tools that I use in my own work environment, and it will keep growing as new needs come up.

This repository is fully **Open Source**. Anyone working in a similar role (SOC Analyst, Threat Hunter, Detection Engineer) is welcome to use these tools, adapt them to their own environment, or contribute to their development.

## Project Philosophy

- **Driven by real needs:** every tool starts from an actual problem encountered in a SOC environment, not an abstract idea.
- **Blue Team focus:** the overall direction is defensive — triage, threat hunting, enrichment, and analysis.
- **Modular by design:** each tool is developed independently and has its own README.
- **Simplicity first:** priority is given to CLI tools that work well in terminal-driven SOC environments, without heavy or unnecessary dependencies.

## Available Tools

| Tool | Short Description | Docs |
|---|---|---|
| ThreatLens | Automated aggregation and enrichment of IOCs from multiple Threat Intelligence sources, with concurrent scanning and risk scoring | [Module docs](./ThreatLens/README.md) |

This table will be updated as new tools are added.

## Repository Structure

Each tool lives in its own folder with its internal structure, dependencies (`requirements.txt` or equivalent), and its own dedicated README. This means adding a new tool never requires touching existing ones.

## Installation & Usage

To use any tool, go into its dedicated folder and follow the installation/usage instructions in that tool's README. Each tool has its own dependencies and configuration (e.g., API keys stored in a `.env` file).

## Contributing

Since this repository is open source, pull requests, bug reports, and suggestions for improving existing tools or adding new ones are all welcome. Please open an issue to discuss the direction of any major change before submitting a large PR.

