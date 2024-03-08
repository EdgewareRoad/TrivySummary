package com.fujitsu.edgewareroad.trivyutils.dto.history;

import java.time.LocalDate;
import java.util.TreeMap;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScan;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilitySummary;

public class TrivyScanHistory {
    @JsonProperty("scanHistory")
    private TreeMap<LocalDate, TrivyScan> scanHistory = new TreeMap<>();

    public TrivyScanHistory()
    {
    }

    public void addScan(LocalDate dateOfScan, TrivyScan scan) throws TrivyScanHistoryMustBeForSameArtefact
    {
        if (scan != null)
        {
            if (scanHistory.size() > 0 && (!getArtefactName().equals(getArtefactNameFromArtefactNameAndVersion(scan.getArtifactName())) || !getArtefactType().equals(scan.getArtifactType())))
            {
                throw new TrivyScanHistoryMustBeForSameArtefact(this, scan);
            }

            scanHistory.put(dateOfScan, scan);
        }
    }

    public class TrivyScanHistoryNotDeepEnoughException extends Exception {
        public TrivyScanHistoryNotDeepEnoughException(String message)
        {
            super(message);
        }
    }

    public class TrivyScanHistoryMustBeForSameArtefact extends Exception {
        public TrivyScanHistoryMustBeForSameArtefact(TrivyScanHistory history, TrivyScan scan)
        {
            super(String.format("Could not compare scan for %s of type %s with scan of %s of type %s", getArtefactNameFromArtefactNameAndVersion(scan.getArtifactName()), scan.getArtifactType(), history.getArtefactName(), history.getArtefactType()));
        }
    }

    public String getArtefactName()
    {
        if (scanHistory.size() > 0)
        {
            return getArtefactNameFromArtefactNameAndVersion(scanHistory.values().iterator().next().getArtifactName());
        }
        else
        {
            return null;
        }
    }

    private String getArtefactNameFromArtefactNameAndVersion(String input)
    {
        if (input.contains(":"))
        {
            return input.substring(0, input.indexOf(":"));
        }
        else
        {
            return input;
        }
    }

    public String getArtefactType()
    {
        if (scanHistory.size() > 0)
        {
            return scanHistory.values().iterator().next().getArtifactType();
        }
        else
        {
            return null;
        }
    }

    public TrivyOneScanSummary getLatestScanSummary(String title) throws TrivyScanHistoryNotDeepEnoughException
    {
        if (scanHistory.size() < 1)
        {
            // We don't have a current scan, so this can't work
            throw new TrivyScanHistoryNotDeepEnoughException("No scan recorded.");
        }

        TrivyScan trivyScanTo = scanHistory.lastEntry().getValue();

        TrivyScanVulnerabilities lastVulnerabilities = trivyScanTo.getAllPackageVulnerabilities().getVulnerabilitiesWithoutPackages();

        return new TrivyOneScanSummary(title, getArtefactName(), getArtefactType(), trivyScanTo.getCreatedAt(),
            new TrivyScanVulnerabilitySummary(lastVulnerabilities));
    }

    public TrivyTwoScanComparison compareLatestScanWithPrevious(String title) throws TrivyScanHistoryNotDeepEnoughException
    {
        if (scanHistory.size() < 1)
        {
            // We don't have a current scan, so this can't work
            throw new TrivyScanHistoryNotDeepEnoughException("No scan recorded.");
        }
        else if (scanHistory.size() < 2)
        {
            // We don't have a previous scan, so this can't work
            throw new TrivyScanHistoryNotDeepEnoughException("No previous scan recorded.");
        }

        TrivyScan trivyScanFrom = scanHistory.lowerEntry(scanHistory.lastKey()).getValue();
        TrivyScan trivyScanTo = scanHistory.lastEntry().getValue();

        TrivyScanVulnerabilities lastVulnerabilities = trivyScanTo.getAllPackageVulnerabilities().getVulnerabilitiesWithoutPackages();
        TrivyScanVulnerabilities previousVulnerabilities = trivyScanFrom.getAllPackageVulnerabilities().getVulnerabilitiesWithoutPackages();

        // Get the list of new vulnerabilities introduced since the previous scan
        TrivyScanVulnerabilities newVulnerabilities = new TrivyScanVulnerabilities(lastVulnerabilities);
        newVulnerabilities.removeAll(previousVulnerabilities);

        // Get the list of unfixed vulnerabilities
        TrivyScanVulnerabilities unfixedVulnerabilities = new TrivyScanVulnerabilities(lastVulnerabilities);
        unfixedVulnerabilities.retainAll(previousVulnerabilities);

        // Get the list of fixed vulnerabilities
        TrivyScanVulnerabilities fixedVulnerabilities = new TrivyScanVulnerabilities(previousVulnerabilities);
        fixedVulnerabilities.removeAll(lastVulnerabilities);

        return new TrivyTwoScanComparison(title, getArtefactName(), getArtefactType(), trivyScanFrom.getCreatedAt(), trivyScanTo.getCreatedAt(),
            new TrivyScanVulnerabilitySummary(newVulnerabilities, unfixedVulnerabilities), new TrivyScanVulnerabilitySummary(fixedVulnerabilities));
    }

    public TreeMap<LocalDate, TrivyScan> getScanHistory() {
        return scanHistory;
    }

    protected void setScanHistory(TreeMap<LocalDate, TrivyScan> scanHistory) {
        this.scanHistory = scanHistory;
    }
}
