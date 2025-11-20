package com.fujitsu.edgewareroad.trivyutils.dto.treatmentplan;

import java.util.Set;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TreatmentPlanEntry implements Comparable<TreatmentPlanEntry> {
    private @NonNull String ticketId;
    private @Setter(AccessLevel.NONE) final Set<String> vulnerabilityIDs = new TreeSet<>();
    private @Setter(AccessLevel.NONE) final Set<String> affectedArtefacts = new TreeSet<>();
    private@NonNull String description;

    public void setVulnerabilityIDs(Set<String> ids) {
        this.vulnerabilityIDs.clear();
        if (ids != null) {
            this.vulnerabilityIDs.addAll(ids);
        }
    }

    public void setAffectedArtefacts(Set<String> artefacts) {
        this.affectedArtefacts.clear();
        if (artefacts != null) {
            this.affectedArtefacts.addAll(artefacts);
        }
    }

    @Override
    public int compareTo(TreatmentPlanEntry o) {
        if (o == null) return 1;
        return ticketId.compareTo(o.ticketId);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) return false;
        if (!TreatmentPlanEntry.class.isInstance(obj)) return false;
        return ticketId.equals(((TreatmentPlanEntry)obj).ticketId);
    }

    @Override
    public int hashCode() {
        return ticketId.hashCode();
    }
}
