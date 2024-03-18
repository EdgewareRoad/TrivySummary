package com.fujitsu.edgewareroad.trivyutils.dto.history;

import java.text.DateFormat;
import java.util.Date;
import java.util.List;

import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilitySummary;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanWhitelistedVulnerabilities;

public class TrivyTwoScanComparison {
    private String title;
    private List<String> artefactNames;
    private String artefactType;
    private boolean historyMayNotBeForSameArtefact = false;
    private Date fromScanDate;
    private Date toScanDate;
    private TrivyScanVulnerabilitySummary vulnerabilitiesOpen;
    private TrivyScanVulnerabilitySummary vulnerabilitiesClosed;
    private TrivyScanWhitelistedVulnerabilities vulnerabilitiesWhitelisted;

    public TrivyTwoScanComparison(
        String title,
        List<String> artefactNames,
        String artefactType,
        boolean historyMayNotBeForSameArtefact,
        Date fromScanDate,
        Date toScanDate,
        TrivyScanVulnerabilitySummary vulnerabilitiesOpen,
        TrivyScanVulnerabilitySummary vulnerabilitiesClosed,
        TrivyScanWhitelistedVulnerabilities vulnerabilitiesWhitelisted) {

        if (title == null)
        {
            if (artefactNames.size() >= 2)
            {
                DateFormat format = DateFormat.getDateInstance(DateFormat.MEDIUM);
                title = String.format("Artefacts %s - %s of type %s, between %s and %s", artefactNames.get(0), artefactNames.get(1), artefactType, format.format(fromScanDate), format.format(toScanDate));
            }
            else
            {
                title = "SYSTEM ERROR: Need two scans to compare";
            }
        }

        this.title = title;
        this.artefactNames = artefactNames;
        this.artefactType = artefactType;
        this.historyMayNotBeForSameArtefact = historyMayNotBeForSameArtefact;
        this.fromScanDate = fromScanDate;
        this.toScanDate = toScanDate;
        this.vulnerabilitiesOpen = vulnerabilitiesOpen;
        this.vulnerabilitiesClosed = vulnerabilitiesClosed;
        this.vulnerabilitiesWhitelisted = vulnerabilitiesWhitelisted;
    }

    public String getTitle() {
        return title;
    }

    public String getEarlierArtefactName() {
        return artefactNames.get(0);
    }

    public String getLaterArtefactName() {
        return artefactNames.get(1);
    }

    public String getArtefactType() {
        return artefactType;
    }

    public boolean historyMayNotBeForSameArtefact()
    {
        return historyMayNotBeForSameArtefact;
    }

    public Date getFromScanDate() {
        return fromScanDate;
    }

    public Date getToScanDate() {
        return toScanDate;
    }

    public TrivyScanVulnerabilitySummary getOpenVulnerabilities() {
        return vulnerabilitiesOpen;
    }

    public TrivyScanVulnerabilitySummary getClosedVulnerabilities() {
        return vulnerabilitiesClosed;
    }

    public TrivyScanWhitelistedVulnerabilities getWhitelistedVulnerabilities() {
        return vulnerabilitiesWhitelisted;
    }
}
