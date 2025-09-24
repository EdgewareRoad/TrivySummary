package com.fujitsu.edgewareroad.trivyutils.dto.history;

import java.time.LocalDate;
import java.util.TreeMap;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScan;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanWhitelistedVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.whitelist.WhitelistEntries;

import lombok.Getter;
import lombok.Setter;

public class TrivyScanHistory {
    @JsonProperty("scanHistory")
    private @Getter @Setter TreeMap<LocalDate, TrivyScan> scanHistory = new TreeMap<>();

    @JsonProperty
    private boolean historyMayNotBeForSameArtefact = false;

    @JsonProperty
    private final @Getter WhitelistEntries whitelistEntries = new WhitelistEntries();

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

        TrivyScanWhitelistedVulnerabilities whitelistedVulnerabilities = new TrivyScanWhitelistedVulnerabilities();
        TrivyScanVulnerabilities lastVulnerabilities = trivyScanTo.getAllPackageVulnerabilities().getVulnerabilitiesWithoutPackages();
        lastVulnerabilities  = whitelistedVulnerabilities.filterWhitelistedVulnerabilities(lastVulnerabilities, whitelistEntries);

        return new TrivyOneScanSummary(title, trivyScanTo.getArtifactName(), trivyScanTo.getArtifactType(), trivyScanTo.getCreatedAt().toLocalDate(),
            lastVulnerabilities, whitelistedVulnerabilities);
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

        TrivyScanWhitelistedVulnerabilities whitelistedVulnerabilities = new TrivyScanWhitelistedVulnerabilities();
        TrivyScanVulnerabilities lastVulnerabilities = trivyScanTo.getAllPackageVulnerabilities().getVulnerabilitiesWithoutPackages();
        TrivyScanVulnerabilities previousVulnerabilities = trivyScanFrom.getAllPackageVulnerabilities().getVulnerabilitiesWithoutPackages();

        // Get the list of new vulnerabilities introduced since the previous scan
        TrivyScanVulnerabilities newVulnerabilities = new TrivyScanVulnerabilities(lastVulnerabilities);
        newVulnerabilities.removeAll(previousVulnerabilities);
        newVulnerabilities = whitelistedVulnerabilities.filterWhitelistedVulnerabilities(newVulnerabilities, whitelistEntries);

        // Get the list of unfixed vulnerabilities
        TrivyScanVulnerabilities unfixedVulnerabilities = new TrivyScanVulnerabilities(lastVulnerabilities);
        unfixedVulnerabilities.retainAll(previousVulnerabilities);
        unfixedVulnerabilities = whitelistedVulnerabilities.filterWhitelistedVulnerabilities(unfixedVulnerabilities, whitelistEntries);

        TrivyScanVulnerabilities openVulnerabilities = new TrivyScanVulnerabilities(unfixedVulnerabilities, Boolean.TRUE);
        openVulnerabilities.addAll(new TrivyScanVulnerabilities(newVulnerabilities, Boolean.FALSE));

        // Get the list of fixed vulnerabilities
        TrivyScanVulnerabilities fixedVulnerabilities = new TrivyScanVulnerabilities(previousVulnerabilities);
        fixedVulnerabilities.removeAll(lastVulnerabilities);

        return new TrivyTwoScanComparison(title, getArtefactNames(), getArtefactType(), historyMayNotBeForSameArtefact, trivyScanFrom.getCreatedAt().toLocalDate(), trivyScanTo.getCreatedAt().toLocalDate(),
            openVulnerabilities, fixedVulnerabilities, whitelistedVulnerabilities);
    }
}
