package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.treatment;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TicketedEntry implements Comparable<TicketedEntry> {
    private @NonNull String ticketId;
    private @NonNull String ticketURI;
    private@NonNull String description;

    @Override
    public int compareTo(TicketedEntry o) {
        if (o == null) return 1;
        return ticketId.compareTo(o.ticketId);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) return false;
        if (!TicketedEntry.class.isInstance(obj)) return false;
        return ticketId.equals(((TicketedEntry)obj).ticketId);
    }

    @Override
    public int hashCode() {
        return ticketId.hashCode();
    }
}
