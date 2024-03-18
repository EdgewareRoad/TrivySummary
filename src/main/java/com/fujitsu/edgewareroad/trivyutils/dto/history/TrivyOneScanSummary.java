package com.fujitsu.edgewareroad.trivyutils.dto.history;

import java.text.DateFormat;
import java.util.Date;

import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilitySummary;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanWhitelistedVulnerabilities;

public class TrivyOneScanSummary {
    private String title;
    private String artefactName;
    private String artefactType;
    private Date scanDate;
    private TrivyScanVulnerabilitySummary vulnerabilitiesOpen;
    private TrivyScanWhitelistedVulnerabilities vulnerabilitiesWhitelisted;

    public TrivyOneScanSummary(
        String title,
        String artefactName,
        String artefactType,
        Date scanDate,
        TrivyScanVulnerabilitySummary vulnerabilitiesOpen,
        TrivyScanWhitelistedVulnerabilities vulnerabilitiesWhitelisted) {

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
        this.vulnerabilitiesWhitelisted = vulnerabilitiesWhitelisted;
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

    public TrivyScanWhitelistedVulnerabilities getWhitelistedVulnerabilities() {
        return vulnerabilitiesWhitelisted;
    }
}
