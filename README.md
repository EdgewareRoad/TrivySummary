# TrivySummary

A simple tool to summarise Trivy scan JSON output for reporting purposes. Package vulnerabilities are collapsed down to the respective CVE, and headline counts of vulnerabilities at different severities (using CVSS v3).

The tool has a number of options to aid reporting.
* It can take a single Trivy scan JSON file and summarise it to PDF or to JSON
* It can take two Trivy scan JSON files for the same logical component, taken at different points in time and compare them, again summarising to PDF or JSON

It also can aid CI/CD pipelines by exiting with an error if there are open vulnerabilities at that severity or above (e.g. fail if at least one CRITICAL or HIGH vulnerability has been found)

## Usage

Requires Java Runtime Environment 17 or higher. Run application from the _bin_ folder (on Windows, use _trivysummary.bat_ not _trivysummary_).

To summarise a single Trivy JSON file, use the form:

```
trivysummary <trivyScanOutput>.json <args>
```

To summarise and compare two Trivy JSON files for the same component, use the form:

```
trivysummary <previousTrivyOutput>.json <latestTrivyOutput>.json <args>
```

For scan dates, this application uses the createdAt property added by later versions of Trivy (since v0.48.0). If this property is not present, the file last modified timestamp will be used (so be careful if copying	output JSON files between systems before running this app).

Arguments:
```
--help
    Displays this help message

--title=...
    Sets a report title. If unset, a default title is used containing the input file path(s) provided
	  
--outputFile=...
    The required output file name. If the filename ends in .pdf then the output is a PDF report.
    If not, a JSON format is used. Defaults to   "trivysummary.pdf" in the current working directory.

--failThreshold=...
    The severity threshold at or above which any open vulnerabilities will cause this app to return
    an error (returns -1, rather than 0).  Must be one of LOW, MEDIUM, HIGH or CRITICAL.
    If unset, defaults to LOW, i.e. any vulnerability is a fail condition.

--whitelist=...
    If set, one or more files in JSON format listing CVEs which should be whitelisted in the output.
    You can specify this argument more than once if you need to input multiple whitelists
    (e.g. if managing separate whitelists for your code vs. those for base images from other suppliers)
```
For sample JSON to whitelist [see here](src/test/resources/sampleWhitelist1.json)

