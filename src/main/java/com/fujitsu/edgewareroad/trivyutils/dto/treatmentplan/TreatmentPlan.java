package com.fujitsu.edgewareroad.trivyutils.dto.treatmentplan;

import java.util.Set;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.databind.annotation.JsonDeserialize;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TreatmentPlan {
    @Builder.Default
    @JsonDeserialize(contentAs = TreatmentPlanEntry.class)
    private @NonNull TreeSet<TreatmentPlanEntry> treatments = new TreeSet<>();
    @Builder.Default
    @JsonDeserialize(contentAs = Note.class)
    private @NonNull TreeSet<Note> notes = new TreeSet<>();
    private @NonNull String ticketSystemURLTemplate;
    private String defaultNoteText;

    public VulnerabilityTreatment getVulnerabilityTreatment(String artefact, Set<String> vulnerabilityIDs) {
        TreeSet<TreatmentPlanEntry> applicableTreatments = findTreatmentByArtefact(artefact);
        for (String vulnerabilityID : vulnerabilityIDs) {
            applicableTreatments.addAll(findTreatmentByVulnerabilityId(vulnerabilityID));
        }
        TreeSet<Note> applicableNotes = findNoteByArtefact(artefact);
        for (String vulnerabilityID : vulnerabilityIDs) {
            applicableNotes.addAll(findNoteByVulnerabilityId(vulnerabilityID));
        }
        
        // If the vulnerability isn't mentioned in any treatment plan entry or note, return null
        if (applicableTreatments.isEmpty() && applicableNotes.isEmpty()) {
            return null;
        }

        return new VulnerabilityTreatment(applicableTreatments, applicableNotes);
    }

    
    public TreatmentPlanEntry findTreatmentByTicketId(String ticketId)
    {
        for (TreatmentPlanEntry entry : treatments)
        {
            if (entry.getTicketId().equalsIgnoreCase(ticketId)) return entry;
        }
        return null;
    }

    public TreeSet<TreatmentPlanEntry> findTreatmentByVulnerabilityId(String vulnerabilityID)
    {
        TreeSet<TreatmentPlanEntry> result = new TreeSet<>();
        for (TreatmentPlanEntry entry : treatments)
        {
            if (entry.getVulnerabilityIDs().contains(vulnerabilityID)) result.add(entry);
        }
        return result;
    }

    public TreeSet<TreatmentPlanEntry> findTreatmentByArtefact(String artefact)
    {
        TreeSet<TreatmentPlanEntry> result = new TreeSet<>();
        for (TreatmentPlanEntry entry : treatments)
        {
            for (String entryArtefact : entry.getAffectedArtefacts()) {
                if (artefact.startsWith(entryArtefact)) {
                    result.add(entry);
                    break;
                }
            }
        }
        return result;
    }

    public TreeSet<Note> findNoteByVulnerabilityId(String vulnerabilityID)
    {
        TreeSet<Note> result = new TreeSet<>();
        for (Note entry : notes)
        {
            if (entry.getVulnerabilityIDs().contains(vulnerabilityID)) result.add(entry);
        }
        return result;
    }

    public TreeSet<Note> findNoteByArtefact(String artefact)
    {
        TreeSet<Note> result = new TreeSet<>();
        for (Note entry : notes)
        {
            for (String entryArtefact : entry.getAffectedArtefacts()) {
                if (artefact.startsWith(entryArtefact)) {
                    result.add(entry);
                    break;
                }
            }
        }
        return result;
    }

}

