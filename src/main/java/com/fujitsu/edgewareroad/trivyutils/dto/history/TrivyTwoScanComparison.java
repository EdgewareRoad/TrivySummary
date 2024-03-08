package com.fujitsu.edgewareroad.trivyutils.dto.history;

import java.text.DateFormat;
import java.util.Date;

import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilitySummary;

public class TrivyTwoScanComparison {
    private String title;
    private String artefactName;
    private String artefactType;
    private Date fromScanDate;
    private Date toScanDate;
    private TrivyScanVulnerabilitySummary vulnerabilitiesOpen;
    private TrivyScanVulnerabilitySummary vulnerabilitiesClosed;

    public TrivyTwoScanComparison(
        String title,
        String artefactName,
        String artefactType,
        Date fromScanDate,
        Date toScanDate,
        TrivyScanVulnerabilitySummary vulnerabilitiesOpen,
        TrivyScanVulnerabilitySummary vulnerabilitiesClosed) {

        if (title == null)
        {
            DateFormat format = DateFormat.getDateInstance(DateFormat.MEDIUM);
            title = String.format("Artefact %s of type %s, between %s and %s", artefactName, artefactType, format.format(fromScanDate), format.format(toScanDate));
        }

        this.title = title;
        this.artefactName = artefactName;
        this.artefactType = artefactType;
        this.fromScanDate = fromScanDate;
        this.toScanDate = toScanDate;
        this.vulnerabilitiesOpen = vulnerabilitiesOpen;
        this.vulnerabilitiesClosed = vulnerabilitiesClosed;
    }

    public String getTitle() {
        return title;
    }

    public String getArtefactName() {
        return artefactName;
    }

    public String getArtefactType() {
        return artefactType;
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
}
