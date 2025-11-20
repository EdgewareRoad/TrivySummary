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
public class Note implements Comparable<Note> {
    private @NonNull String noteText;
    private @Setter(AccessLevel.NONE) final Set<String> vulnerabilityIDs = new TreeSet<>();
    private @Setter(AccessLevel.NONE) final Set<String> affectedArtefacts = new TreeSet<>();

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
    public int compareTo(Note o) {
        if (o == null) return 1;
        int compareNote = noteText.compareTo(o.noteText);
        if (compareNote != 0) return compareNote;
        compareNote = vulnerabilityIDs.toString().compareTo(o.vulnerabilityIDs.toString());
        if (compareNote != 0) return compareNote;
        return affectedArtefacts.toString().compareTo(o.affectedArtefacts.toString());
    }
}
