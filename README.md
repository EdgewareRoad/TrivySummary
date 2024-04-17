# TrivySummary

TrivySummary summarises Trivy scan JSON output for reporting purposes. Package vulnerabilities are collapsed down to the respective CVE, and headline counts of vulnerabilities at different severities (using CVSS v3). In addition, EPSS scores can also be retrieved, allowing
the exploitability and severity of all vulnerabilities to be graphed and optionally prioritised.

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

For scan dates, this application relies on the createdAt property added by
later versions of Trivy (since v0.48.0).

### Arguments

```
  --help
    Displays this help message

  --title=...
    Sets a report title. If unset, a default title is used containing
    the input file path(s) provided

  --outputFile=...
    The required output file name. If the filename ends in .pdf then the
    output is a PDF report. If not, a JSON format is used. Defaults to
    "trivysummary.pdf" in the current working directory.

  --failSeverityThreshold=...
    The severity threshold at or above which any open vulnerabilities
    will cause this app to return an error (returns -1, rather than 0).
    Must be one of LOW, MEDIUM, HIGH or CRITICAL.
    If unset, an error won't be returned for any set minimum severity
    but, if prioritisation is in use (see below), any open high priority
    vulnerabilities will generate an error.

  --whitelist=...
    If set, one or more files in JSON format listing CVEs which should be
    whitelisted in the output. You can specify this argument multiple times
    if you wish to load multiple whitelists

  --offline
    If set, TrivySummary will not attempt to access EPSS scores to assess
    the exploitability of CVEs. This will bypass graphing and prioritisation
    but is useful if using this tool from airgapped environments.

  --minimumCVSSToPrioritise
    If this is set, TrivySummary will categorise CVEs into high priority and
    lower priority bands. This should be a CVE CVSSv3 score, i.e. between
    0.0 and 10.0.
    If this isn't set but --minimumEPSSToPrioritise is set, then defaults to 0.0

  --minimumEPSSToPrioritise
    If this is set, TrivySummary will categorise CVEs into high priority and
    lower priority bands. This should be an EPSS score, i.e. between
    0.0 and 1.0.
    If this isn't set but --minimumCVSSToPrioritise is set, then defaults to 0.0
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

### Better remediation prioritisation through EPSS (exploitability scoring) and priority bands
The open source version of [Trivy](https://github.com/aquasecurity/trivy) only supports assessment against
severity (more properly, emphasising vendor assessment of severity). There are other means of scoring CVEs
including [EPSS](https://www.first.org/epss/), the Exploit Prediction Scoring System.

TrivySummary will, by default, add EPSS scores to each CVE (unless overridden by the _--offline_ flag) and
graph the results. CVEs which are of the highest combination of CVSS and EPSS will be labelled.

In addition, through the _--minimumCVSSToPrioritise_ and _--minimumEPSSToPrioritise_ flags, the user can
also set minimum thresholds for CVEs to be marked in the report as high priority or low priority.

**Please note** that a CVE's marked severity and CVSS score may not correspond, as vendors such as RedHat
often set a different vendor severity from that implied by the CVSS due to their assessment of the wider 
circumstances and how software is deployed and used. Trivy takes this into account and prefers the vendor
assessment (see [Severity Selection](https://aquasecurity.github.io/trivy/dev/docs/scanner/vulnerability/)
section).