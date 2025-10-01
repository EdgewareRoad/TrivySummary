package com.fujitsu.edgewareroad.trivyutils.dto.treatmentplan;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.io.InputStream;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public class TreatmentPlanTests {
    @Test
    public void testTreatmentPlan() throws JsonProcessingException {
        TreatmentPlan plan = TreatmentPlan.builder().
                ticketSystemURLTemplate("http://example.com/ticket/{ticketId}").
                defaultNoteText("This is a default note").
                build();
        TreeSet<TreatmentPlanEntry> treatments = plan.getTreatments();
        TreeSet<Note> notes = plan.getNotes();

        TreatmentPlanEntry entry1 = new TreatmentPlanEntry();
        entry1.setTicketId("TICKET-1");
        entry1.setDescription("First ticket");
        entry1.getVulnerabilityIDs().add("CVE-2023-0001");
        entry1.getVulnerabilityIDs().add("CVE-2023-0002");
        treatments.add(entry1);

        TreatmentPlanEntry entry2 = new TreatmentPlanEntry();
        entry2.setTicketId("TICKET-2");
        entry2.setDescription("Second ticket");
        entry2.getVulnerabilityIDs().add("CVE-2023-0003");
        treatments.add(entry2);

        TreatmentPlanEntry entry3 = new TreatmentPlanEntry();
        entry3.setTicketId("TICKET-3");
        entry3.setDescription("Third ticket");
        entry3.getAffectedArtefacts().add("mycomponent:");
        treatments.add(entry3);

        Note note1 = new Note();
        note1.setNoteText("This is a note for certain vulnerabilities and a component");
        note1.getVulnerabilityIDs().add("CVE-2023-0001");
        note1.getVulnerabilityIDs().add("CVE-2023-0004");
        note1.getAffectedArtefacts().add("mycomponent:");
        notes.add(note1);

        // Test findByTicketId
        assert plan.findTreatmentByTicketId("TICKET-1") == entry1;
        assert plan.findTreatmentByTicketId("TICKET-2") == entry2;
        assert plan.findTreatmentByTicketId("TICKET-3") == entry3;
        assert plan.findTreatmentByTicketId("TICKET-4") == null;

        // Test findByVulnerabilityId
        assert plan.findTreatmentByVulnerabilityId("CVE-2023-0001").contains(entry1);
        assert plan.findTreatmentByVulnerabilityId("CVE-2023-0002").contains(entry1);
        assert plan.findTreatmentByVulnerabilityId("CVE-2023-0003").contains(entry2);
        assert plan.findTreatmentByVulnerabilityId("CVE-2023-0004").isEmpty();

        // Test findTreatmentByArtefact
        assert plan.findTreatmentByArtefact("mycomponent:1.0.0").contains(entry3);
        assert plan.findTreatmentByArtefact("mycomponent:1").contains(entry3);
        assert plan.findTreatmentByArtefact("mycomponent:").contains(entry3);
        assert plan.findTreatmentByArtefact("othercomponent:2.0.0").isEmpty();        

        // Test findNoteByVulnerabilityId
        assert plan.findNoteByVulnerabilityId("CVE-2023-0001").contains(note1);
        assert plan.findNoteByVulnerabilityId("CVE-2023-0004").contains(note1);
        assert plan.findNoteByVulnerabilityId("CVE-2023-0002").isEmpty();

        // Test findNoteByArtefact
        assert plan.findNoteByArtefact("mycomponent:1.0.0").contains(note1);
        assert plan.findNoteByArtefact("mycomponent:1").contains(note1);
        assert plan.findNoteByArtefact("mycomponent:").contains(note1);
        assert plan.findNoteByArtefact("othercomponent:2.0.0").isEmpty();

        VulnerabilityTreatment treatment = plan.getVulnerabilityTreatment("mycomponent:", Set.of("CVE-2023-0002"));

        assert treatment != null;
        assert treatment.getTreatmentPlanEntries().size() == 2;
        assert treatment.getTreatmentPlanEntries().contains(entry1);
        assert treatment.getTreatmentPlanEntries().contains(entry3);
        assert treatment.getNotes().size() == 1;
        assert treatment.getNotes().contains(note1);

        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        String json = mapper.writeValueAsString(plan);
        assertNotNull(json);

        plan = mapper.readValue(json, TreatmentPlan.class);
        assertNotNull(plan);
    }

    @Test
    public void testVulnerabilityTreatmentLoadFromFile() throws StreamReadException, DatabindException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        InputStream inputStream = getClass().getResourceAsStream("/testapp/testAppTreatments1.json");
        TreatmentPlan plan = mapper.readValue(inputStream, TreatmentPlan.class);
        assertNotNull(plan);
        VulnerabilityTreatment treatment = plan.getVulnerabilityTreatment("artefactA", Set.of("CVE-2023-0001"));
        assertNotNull(treatment);
        assert treatment.getTreatmentPlanEntries().size() == 1;
    }
}           
