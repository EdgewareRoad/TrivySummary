package com.fujitsu.edgewareroad.trivyutils.dto.history;

import java.time.LocalDate;
import java.util.TreeMap;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScan;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilitySummary;

public class TrivyScanHistory {
    @JsonProperty("scanHistory")
    private TreeMap<LocalDate, TrivyScan> scanHistory = new TreeMap<>();

    @JsonProperty
    private boolean historyMayNotBeForSameArtefact = false;

    public TrivyScanHistory()
    {
    }

    public void addScan(LocalDate dateOfScan, TrivyScan scan) throws TrivyScanHistoryMustBeForSameArtefactType
    {
        if (scan != null)
        {
            if (scanHistory.size() > 0
                    && (!getArtefactNameWithoutVersion(getArtefactNames().get(0)).equals(getArtefactNameWithoutVersion(scan.getArtifactName())) || !getArtefactType ().equals(scan.getArtifactType())))
            {
                historyMayNotBeForSameArtefact = true;
                if (!getArtefactType().equals(scan.getArtifactType()))
                {
                    throw new TrivyScanHistoryMustBeForSameArtefactType(this, scan);
                }
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

    public class TrivyScanHistoryMustBeForSameArtefactType extends Exception {
        public TrivyScanHistoryMustBeForSameArtefactType(TrivyScanHistory history, TrivyScan scan)
        {
            super("Scan history must be for artefacts of the same type");
        }
    }

    public List<String> getArtefactNames()
    {
        ArrayList<String> artefactNames = new ArrayList<>();
        for (TrivyScan scan : scanHistory.values())
        {
            artefactNames.add(scan.getArtifactName());
        }
        return artefactNames;
    }

    private String getArtefactNameWithoutVersion(String input)
    {
        if (input != null)
        {
            String[] splitByDigits = input.split("(?<=\\D)(?=\\d)|(?<=\\d)(?=\\D)");
            return splitByDigits[0];
        }
        else
        {
            return "";
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

        return new TrivyOneScanSummary(title, trivyScanTo.getArtifactName(), trivyScanTo.getArtifactType(), trivyScanTo.getCreatedAt(),
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

        return new TrivyTwoScanComparison(title, getArtefactNames(), getArtefactType(), historyMayNotBeForSameArtefact, trivyScanFrom.getCreatedAt(), trivyScanTo.getCreatedAt(),
            new TrivyScanVulnerabilitySummary(newVulnerabilities, unfixedVulnerabilities), new TrivyScanVulnerabilitySummary(fixedVulnerabilities));
    }

    public TreeMap<LocalDate, TrivyScan> getScanHistory() {
        return scanHistory;
    }

    protected void setScanHistory(TreeMap<LocalDate, TrivyScan> scanHistory) {
        this.scanHistory = scanHistory;
    }
}
