package com.fujitsu.edgewareroad.trivyutils.dto.history;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.List;

import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanWhitelistedVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.treatment.ReportedTreatment;

import lombok.Getter;
import lombok.Setter;

public class TrivyTwoScanComparison {
    private final @Getter String title;
    private final List<String> artefactNames;
    private final @Getter String artefactType;
    private boolean historyMayNotBeForSameArtefact = false;
    private final @Getter LocalDate fromScanDate;
    private final @Getter LocalDate toScanDate;
    private final @Getter TrivyScanVulnerabilities openVulnerabilities;
    private final @Getter TrivyScanVulnerabilities closedVulnerabilities;
    private final @Getter TrivyScanWhitelistedVulnerabilities whitelistedVulnerabilities;
    private @Getter @Setter ReportedTreatment treatment = null;

    public TrivyTwoScanComparison(
        String title,
        List<String> artefactNames,
        String artefactType,
        boolean historyMayNotBeForSameArtefact,
        LocalDate fromScanDate,
        LocalDate toScanDate,
        TrivyScanVulnerabilities openVulnerabilities,
        TrivyScanVulnerabilities closedVulnerabilities,
        TrivyScanWhitelistedVulnerabilities whitelistedVulnerabilities) {

        if (title == null)
        {
            if (artefactNames.size() >= 2)
            {
                DateTimeFormatter formatter = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM);
                if (artefactNames.get(0).equals(artefactNames.get(1)))
                {
                    // We're comparing the same artefact on different dates
                    title = String.format("Comparing scans of %s (%s to %s) of type %s", artefactNames.get(0), fromScanDate.format(formatter), toScanDate.format(formatter), artefactType);
                }
                else
                {
                    // We're comparing scans of different artefacts (expected to be different versions of the same logical component)
                    title = String.format("Comparing %s (scan %s) with %s (scan %s) of type %s", artefactNames.get(0), fromScanDate.format(formatter), artefactNames.get(1), toScanDate.format(formatter), artefactType);
                }
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
        this.openVulnerabilities = openVulnerabilities;
        this.closedVulnerabilities = closedVulnerabilities;
        this.whitelistedVulnerabilities = whitelistedVulnerabilities;
    }

    public String getEarlierArtefactName() {
        return artefactNames.get(0);
    }

    public String getLaterArtefactName() {
        return artefactNames.get(1);
    }

    public boolean historyMayNotBeForSameArtefact()
    {
        return historyMayNotBeForSameArtefact;
    }
}
