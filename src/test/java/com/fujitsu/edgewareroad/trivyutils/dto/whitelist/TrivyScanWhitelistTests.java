package com.fujitsu.edgewareroad.trivyutils.dto.whitelist;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.LocalDate;

import org.junit.jupiter.api.Test;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.exc.ValueInstantiationException;
import tools.jackson.databind.json.JsonMapper;

public class TrivyScanWhitelistTests {

    private final ObjectMapper mapper = JsonMapper.builder().build();
    
    @Test
    public void testCreateWhitelistValid() throws JacksonException
    {
        WhitelistEntries entries = new WhitelistEntries();

        entries.add(WhitelistEntry.builder()
            .vulnerabilityID("CVE-2022-00001")
            .reason("This base image contains the affected JAR but does not expose it in a manner that can be exploited by external consumers.")
            .nextReviewDate(LocalDate.now().plusDays(90))
            .build());

        entries.add(WhitelistEntry.builder()
            .vulnerabilityID("CVE-2022-00002")
            .reason("Bob said it was OK.")
            .nextReviewDate(LocalDate.now().plusDays(120))
            .approvalDate(LocalDate.now().minusDays(1))
            .approvedBy("Bob")
            .build());

        System.out.println(mapper.writeValueAsString(entries));
    }

    @Test
    public void testCreateWhitelistMissingID()
    {
        try {
            WhitelistEntry.builder()
                .reason("This base image contains the affected JAR but does not expose it in a manner that can be exploited by external consumers.")
                .nextReviewDate(LocalDate.now().plusDays(90))
                .build();
        } catch (NullPointerException ex)
        {
            return;
        }

        fail();
    }

    @Test
    public void testCreateWhitelistMissingReason()
    {
        try {
            WhitelistEntry.builder()
                .vulnerabilityID("CVE-2022-00001")
                .nextReviewDate(LocalDate.now().plusDays(90))
                .build();
        } catch (NullPointerException ex)
        {
            return;
        }

        fail();
    }

    @Test
    public void testCreateWhitelistMissingReviewDate() 
    {
        try {
            WhitelistEntry.builder()
                .vulnerabilityID("CVE-2022-00001")
                .reason("This base image contains the affected JAR but does not expose it in a manner that can be exploited by external consumers.")
                .build();
        } catch (NullPointerException ex)
        {
            return;
        }

        fail();
    }

    @Test
    public void testImportJsonDataValid() throws DatabindException, JacksonException
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

        WhitelistEntries entries = mapper.readValue(importData, WhitelistEntries.class);
        System.out.println(mapper.writeValueAsString(entries));
    }

    @Test
    public void testImportJsonDataInvalid() throws DatabindException, JacksonException
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

        try {
            mapper.readValue(importData, WhitelistEntries.class);
        } catch (ValueInstantiationException ex)
        {
            assertTrue(ex.getMessage().contains("vulnerabilityID is marked non-null but is null"), "Wrong exception thrown");
            return;
        }

        // If we got this far, we've not hit that exception, so fail.
        fail("No exception thrown");
    }
}
