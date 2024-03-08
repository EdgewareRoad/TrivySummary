package com.fujitsu.edgewareroad.trivyutils.dto.history;

import java.text.DateFormat;
import java.util.Date;

import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilitySummary;

public class TrivyOneScanSummary {
    private String title;
    private String artefactName;
    private String artefactType;
    private Date scanDate;
    private TrivyScanVulnerabilitySummary vulnerabilitiesOpen;

    public TrivyOneScanSummary(
        String title,
        String artefactName,
        String artefactType,
        Date scanDate,
        TrivyScanVulnerabilitySummary vulnerabilitiesOpen) {

        if (title == null)
        {
            DateFormat format = DateFormat.getDateInstance(DateFormat.MEDIUM);
            title = String.format("Artefact %s of type %s, scanned %s", artefactName, artefactType, format.format(scanDate));
        }

        this.title = title;
        this.artefactName = artefactName;
        this.artefactType = artefactType;
        this.scanDate = scanDate;
        this.vulnerabilitiesOpen = vulnerabilitiesOpen;
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

    public Date getScanDate() {
        return scanDate;
    }

    public TrivyScanVulnerabilitySummary getOpenVulnerabilities() {
        return vulnerabilitiesOpen;
    }
}
