package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.treatment;

import java.net.URI;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;

@AllArgsConstructor
public class ReportedTreatment {
    private final @Getter @NonNull List<TicketedEntry> tickets;
    private final @Getter @NonNull List<String> notes;
    private final @Getter boolean isAcceptedAsUnfixable;
    private final @Getter URI searchURI;
}