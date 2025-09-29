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
public class Note implements Comparable<Note> {
    private @NonNull String noteText;
    private @NonNull TreeSet<String> vulnerabilityIDs = new TreeSet<>();
    private @NonNull TreeSet<String> affectedArtefacts = new TreeSet<>();

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
