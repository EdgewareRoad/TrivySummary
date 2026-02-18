package com.fujitsu.edgewareroad.trivyutils.dto.treatmentplan;

import java.util.Optional;
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
    // This field is not used for comparison, but it is included in the JSON output
    // It denotes if the note indicates that the vulnerability is accepted as unfixable, which can be useful for filtering and reporting purposes
    private Optional<Boolean> isAcceptedAsUnfixable = Optional.empty();
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

    public boolean isAcceptedAsUnfixable() {
        return isAcceptedAsUnfixable.isPresent() && isAcceptedAsUnfixable.get();
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
