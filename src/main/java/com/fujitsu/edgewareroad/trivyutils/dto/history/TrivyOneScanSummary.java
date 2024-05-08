package com.fujitsu.edgewareroad.trivyutils.dto.history;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;

import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanWhitelistedVulnerabilities;

public class TrivyOneScanSummary {
    private String title;
    private String artefactName;
    private String artefactType;
    private LocalDate scanDate;
    private TrivyScanVulnerabilities vulnerabilitiesOpen;
    private TrivyScanWhitelistedVulnerabilities vulnerabilitiesWhitelisted;

    public TrivyOneScanSummary(
        String title,
        String artefactName,
        String artefactType,
        LocalDate scanDate,
        TrivyScanVulnerabilities vulnerabilitiesOpen,
        TrivyScanWhitelistedVulnerabilities vulnerabilitiesWhitelisted) {

        if (title == null)
        {
            DateTimeFormatter formatter = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM);
            title = String.format("Artefact %s of type %s, scanned %s", artefactName, artefactType, scanDate.format(formatter));
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

    public LocalDate getScanDate() {
        return scanDate;
    }

    public TrivyScanVulnerabilities getOpenVulnerabilities() {
        return vulnerabilitiesOpen;
    }

    public TrivyScanWhitelistedVulnerabilities getWhitelistedVulnerabilities() {
        return vulnerabilitiesWhitelisted;
    }
}
