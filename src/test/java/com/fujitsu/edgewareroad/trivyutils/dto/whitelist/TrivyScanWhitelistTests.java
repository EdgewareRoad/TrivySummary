package com.fujitsu.edgewareroad.trivyutils.dto.whitelist;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.LocalDate;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public class TrivyScanWhitelistTests {
    @Test
    public void testCreateWhitelistValid() throws JsonProcessingException
    {
        WhitelistEntries entries = new WhitelistEntries();

        entries.add(new WhitelistEntryBuilder()
            .setVulnerabilityID("CVE-2022-00001")
            .setReason("This base image contains the affected JAR but does not expose it in a manner that can be exploited by external consumers.")
            .setNextReviewDate(LocalDate.now().plusDays(90))
            .build());

        entries.add(new WhitelistEntryBuilder()
            .setVulnerabilityID("CVE-2022-00002")
            .setReason("Bob said it was OK.")
            .setNextReviewDate(LocalDate.now().plusDays(120))
            .setApprovalDate(LocalDate.now().minusDays(1))
            .setApprovedBy("Bob")
            .build());

        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        System.out.println(mapper.writeValueAsString(entries));
    }

    @Test
    public void testCreateWhitelistMissingID() throws JsonProcessingException
    {
        try {
            new WhitelistEntryBuilder()
                .setReason("This base image contains the affected JAR but does not expose it in a manner that can be exploited by external consumers.")
                .setNextReviewDate(LocalDate.now().plusDays(90))
                .build();
        } catch (IllegalArgumentException ex)
        {
            return;
        }

        fail();
    }

    @Test
    public void testCreateWhitelistMissingReason() throws JsonProcessingException
    {
        try {
            new WhitelistEntryBuilder()
                .setVulnerabilityID("CVE-2022-00001")
                .setNextReviewDate(LocalDate.now().plusDays(90))
                .build();
        } catch (IllegalArgumentException ex)
        {
            return;
        }

        fail();
    }

    @Test
    public void testCreateWhitelistMissingReviewDate() throws JsonProcessingException
    {
        try {
            new WhitelistEntryBuilder()
                .setVulnerabilityID("CVE-2022-00001")
                .setReason("This base image contains the affected JAR but does not expose it in a manner that can be exploited by external consumers.")
                .build();
        } catch (IllegalArgumentException ex)
        {
            return;
        }

        fail();
    }

    @Test
    public void testImportJsonDataValid() throws JsonMappingException, JsonProcessingException
    {
        String importData = """
            [ {
                "vulnerabilityID" : "CVE-2022-00001",
                "reason" : "This base image contains the affected JAR but does not expose it in a manner that can be exploited by external consumers.",
                "nextReviewDate" : "2024-06-13"
              }, {
                "vulnerabilityID" : "CVE-2022-00002",
                "reason" : "Bob said it was OK.",
                "nextReviewDate" : "2024-07-13",
                "approvalDate" : "2024-03-14",
                "approvedBy" : "Bob"
              } ]
                """;

        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

        WhitelistEntries entries = mapper.readValue(importData, WhitelistEntries.class);
        System.out.println(mapper.writeValueAsString(entries));
    }

    @Test
    public void testImportJsonDataInvalid() throws JsonMappingException, JsonProcessingException
    {
        // Note no vulnerability ID on the second entry.
        String importData = """
            [ {
                "vulnerabilityID" : "CVE-2022-00001",
                "reason" : "This base image contains the affected JAR but does not expose it in a manner that can be exploited by external consumers.",
                "nextReviewDate" : "2024-06-13"
              }, {
                "reason" : "Bob said it was OK.",
                "nextReviewDate" : "2024-07-13",
                "approvalDate" : "2024-03-14",
                "approvedBy" : "Bob"
              } ]
                """;

        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

        try {
            mapper.readValue(importData, WhitelistEntries.class);
        } catch (MismatchedInputException ex)
        {
            assertTrue(ex.getMessage().contains("Missing required creator property 'vulnerabilityID'"), "Wrong exception thrown");
            return;
        }

        // If we got this far, we've not hit that exception, so fail.
        fail("No exception thrown");
    }
}
