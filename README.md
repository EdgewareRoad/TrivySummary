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

### Arguments

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

### Whitelisting

This application supports whitelisting vulnerabilities, based on supplying one or more JSON files, each
in the format specified below.

Whitelisting a CVE causes it to be removed from the list of open vulnerabilities reported by Trivy and 
to exclude it from consideration as to the fail threshold (e.g. if the fail threshold is set to CRITICAL
and you whitelist the only open CRITICAL CVE, then the application will not report this as an error).

Each JSON file is an array of whitelisting entries. Each whitelisting entry has the following properties:

* vulnerabilityID _(mandatory)_
  
  The CVE reference.

* reason _(mandatory)_
 
  The justification for why this can be whitelisted, i.e. does not affect your code. Has it been confirmed
  as a false positive? Does your code feature-control this component to disable the exposure? etc.

* nextReviewDate _(mandatory)_

  A date in yyyy-MM-dd format. Must be specified. If you are creating a new item for immediate review
  (e.g. to allow your code to build until you have assessed whether you need to remediate before
  publication, then set this to today's date or a date in the past).

* approvalDate _(optional)_

  The date on which this vulnerability was reviewed, in yyyy-MM-dd format. Both the approvalDate and
  approvedBy fields must be set for TrivySummary to recognise this as having been approved. The
  approvalDate must not be in the future, or else TrivySummary will not recognise this as having been
  approved.

* approvedBy _(optional)_

  The name of the approver. Both the approvalDate and approvedBy fields must be set for TrivySummary
  to recognise this whitelisting as having been approved.

For sample JSON to whitelist [see here](src/test/resources/sampleWhitelist1.json)

