package com.fujitsu.edgewareroad.trivyutils.dto.history;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;

import org.springframework.util.StringUtils;

import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanWhitelistedVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.treatment.ReportedTreatment;

import lombok.Getter;
import lombok.Setter;

public class TrivyOneScanSummary {
    private final @Getter String title;
    private final @Getter String artefactName;
    private final @Getter String artefactType;
    private final @Getter LocalDate scanDate;
    private final @Getter TrivyScanVulnerabilities openVulnerabilities;
    private final @Getter TrivyScanWhitelistedVulnerabilities whitelistedVulnerabilities;
    private @Getter @Setter ReportedTreatment treatment = null;

    @SuppressWarnings("null")
    public TrivyOneScanSummary(
        String title,
        String artefactName,
        String artefactType,
        LocalDate scanDate,
        TrivyScanVulnerabilities openVulnerabilities,
        TrivyScanWhitelistedVulnerabilities whitelistedVulnerabilities) {

        if (title == null)
        {
            DateTimeFormatter formatter = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM);
            title = String.format("Artefact %s of type %s, scanned %s", artefactName.contains(":") ? StringUtils.split(artefactName, ":")[0] : artefactName, artefactType, scanDate.format(formatter));
        }

        this.title = title;
        this.artefactName = artefactName;
        this.artefactType = artefactType;
        this.scanDate = scanDate;
        this.openVulnerabilities = openVulnerabilities;
        this.whitelistedVulnerabilities = whitelistedVulnerabilities;
    }
}
