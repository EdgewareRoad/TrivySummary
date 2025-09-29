package com.fujitsu.edgewareroad.trivyutils.dto.treatmentplan;

import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TreatmentPlanEntry implements Comparable<TreatmentPlanEntry> {
    private @NonNull String ticketId;
    private @NonNull TreeSet<String> vulnerabilityIDs = new TreeSet<>();
    private @NonNull TreeSet<String> affectedArtefacts = new TreeSet<>();
    private@NonNull String description;

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
