# TrivySummary

A simple tool to summarise Trivy scan JSON output for reporting purposes. Package vulnerabilities are collapsed down to the respective CVE, and headline counts of vulnerabilities at different severities (using CVSS v3).

The tool has a number of options to aid reporting.
* It can take a single Trivy scan JSON file and summarise it to PDF or to JSON
* It can take two Trivy scan JSON files for the same logical component, taken at different points in time and compare them, again summarising to PDF or JSON

It also can aid CI/CD pipelines by exiting with an error if there are open vulnerabilities at that severity or above (e.g. fail if at least one CRITICAL or HIGH vulnerability has been found)

## Usage

Requires JDK 21 or higher


