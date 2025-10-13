package com.fujitsu.edgewareroad.trivysummary;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fujitsu.edgewareroad.trivyutils.GenerateGraph;
import com.fujitsu.edgewareroad.trivyutils.RenderToPDF;
import com.fujitsu.edgewareroad.trivyutils.TrivyScanLoader;
import com.fujitsu.edgewareroad.trivyutils.TrivySummaryStringUtils;
import com.fujitsu.edgewareroad.trivyutils.dto.firstapiv1.EPSSData;
import com.fujitsu.edgewareroad.trivyutils.dto.firstapiv1.EPSSResponse;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyOneScanSummary;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory.TrivyScanHistoryMustBeForSameArtefactType;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistoryNotDeepEnoughException;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyTwoScanComparison;
import com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel.PriorityModel;
import com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel.VulnerabilityPriority;
import com.fujitsu.edgewareroad.trivyutils.dto.treatmentplan.TreatmentPlan;
import com.fujitsu.edgewareroad.trivyutils.dto.treatmentplan.VulnerabilityTreatment;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScan;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerability;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanWhitelistedVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.treatment.ReportedTreatment;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.treatment.TicketedEntry;
import com.fujitsu.edgewareroad.trivyutils.dto.whitelist.WhitelistEntries;

import lombok.Getter;
import lombok.Setter;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

public class TrivySummary {
    public static class Configuration {
        private Path outputFile = Paths.get(System.getProperty("user.dir"), "output.pdf");
	    private boolean offlineMode = false;
	    private boolean useTodayForEPSSQuery = false;
	    private @Getter @Setter PriorityModel priorityModel = new PriorityModel();
		private @Getter @Setter TreatmentPlan treatmentPlan = null;
        private VulnerabilityPriority failPriorityThreshold = null;
        private String appVersion = "UNKNOWN_VERSION";

        public Path getOutputFile() {
            return outputFile;
        }

		public void setDefaultOutputPathFromInputFile(Path inputFile)
		{
			String fileName = inputFile.getFileName().toString();
			if (fileName.endsWith(".json"))
			{
				fileName = fileName.substring(0, fileName.length() - ".json".length()) + ".pdf";
			}
			else
			{
				fileName = fileName + ".pdf";
			}
			this.outputFile = inputFile.getParent().resolve(fileName);
		}

        public void setOutputFile(Path outputFile) {
            this.outputFile = outputFile;
        }

        public boolean isOfflineMode() {
            return offlineMode;
        }


        public void setOfflineMode(boolean offlineMode) {
            this.offlineMode = offlineMode;
        }


        public boolean isUseTodayForEPSSQuery() {
            return useTodayForEPSSQuery;
        }


        public void setUseTodayForEPSSQuery(boolean useTodayForEPSSQuery) {
            this.useTodayForEPSSQuery = useTodayForEPSSQuery;
        }

        public VulnerabilityPriority getFailPriorityThreshold() {
            return failPriorityThreshold;
        }


        public void setFailPriorityThreshold(VulnerabilityPriority failPriorityThreshold) {
            this.failPriorityThreshold = failPriorityThreshold;
        }

        public String getAppVersion()
        {
            return appVersion;
        }

        public void setAppVersion(String version)
        {
            this.appVersion = version;
        }

        public Configuration() {

        }
    }

    private Configuration configuration;
    private TrivyScanHistory history = new TrivyScanHistory();
    private static HttpClient client = HttpClient.newHttpClient();
    private static ObjectMapper mapper = JsonMapper.builder()
						.configure(SerializationFeature.INDENT_OUTPUT, true)
						.build();

    public TrivySummary(Configuration configuration)
    {
        this.configuration = configuration;
    }

    public void addWhitelistEntries(WhitelistEntries entries)
    {
        history.getWhitelistEntries().addAll(entries);
    }

	public boolean summariseTrivyHistory(String title) throws IOException, TrivyScanHistoryNotDeepEnoughException, TrivyScanCouldNotRetrieveEPSSScoresException
	{
		String statusMessage = null;
		boolean statusIsWarning = false;
		TrivyScanVulnerabilities openVulnerabilities;

		if (configuration.isOfflineMode())
		{
			statusMessage = "Offline mode. No EPSS or prioritisation applied";
		}

		if (history.getScanHistory().size() == 2)
		{
			// We have some meaningful history
			TrivyTwoScanComparison comparison = null;
			comparison = history.compareLatestScanWithPrevious(title);
			openVulnerabilities = comparison.getOpenVulnerabilities();
			TrivyScanWhitelistedVulnerabilities whitelistedVulnerabilities = comparison.getWhitelistedVulnerabilities();
			TrivyScanVulnerabilities closedVulnerabilities = comparison.getClosedVulnerabilities();
			if (!configuration.isOfflineMode())
			{
                LocalDate epssQueryDate = configuration.isUseTodayForEPSSQuery() || comparison.getToScanDate().equals(LocalDate.now()) ? null : comparison.getToScanDate();

				// Try to update EPSS scores for open vulnerabilities. If they fail, we set
				// offline mode to be true.
				try {
					updateEPSSScores(openVulnerabilities, false, epssQueryDate);
					openVulnerabilities.prioritiseForRemediation(configuration.getPriorityModel());
				} catch (Exception e) {
					throw new TrivyScanCouldNotRetrieveEPSSScoresException(String.format("Could not retrieve EPSS scores for open vulnerabilities; Cannot create graph or prioritise vulnerabilities. Please check connectivity to %s or re-run TrivySummary with --offline.", BASE_EPSS_API_URL), e);
				}
				// Now update EPSS scores for closed vulnerabilities.
				try {
					updateEPSSScores(closedVulnerabilities, false, epssQueryDate);
					closedVulnerabilities.prioritiseForRemediation(configuration.getPriorityModel());
				} catch (Exception e) {
					String warning = "Could not retrieve EPSS scores for closed vulnerabilties; these will be prioritised only by vendor severity.";
					if (statusMessage != null) {
						statusMessage = String.format("%s  %s", statusMessage, warning);
					} else {
						statusMessage = warning;
					}
					statusIsWarning = true;
				}
				// Now update EPSS scores for whitelisted vulnerabilities.
				try {
					updateEPSSScores(whitelistedVulnerabilities, false, epssQueryDate);
					whitelistedVulnerabilities.prioritiseForRemediation(configuration.getPriorityModel());
				} catch (Exception e) {
					String warning = "Could not retrieve EPSS scores for whitelisted vulnerabilties; these will be prioritised only by vendor severity.";
					if (statusMessage != null) {
						statusMessage = String.format("%s  %s", statusMessage, warning);
					} else {
						statusMessage = warning;
					}
					statusIsWarning = true;
				}
			}
			if (configuration.getTreatmentPlan() != null && comparison.getOpenVulnerabilities().size() > 0)
			{
				comparison.setTreatment(createReportedTreatment(configuration.getTreatmentPlan().getTicketSystemURLTemplate(), configuration.getTreatmentPlan().getVulnerabilityTreatment(
												comparison.getLaterArtefactName(),
												comparison.getOpenVulnerabilities().getAllVulnerabilityIDs())));
			}
	
			if (configuration.getOutputFile().toString().endsWith(".pdf"))
			{
				Map<String, Object> variables = new HashMap<>();
				variables.put("title", comparison.getTitle());
				variables.put("earlierArtefactName", comparison.getEarlierArtefactName());
				variables.put("laterArtefactName", comparison.getLaterArtefactName());
				variables.put("artefactType", comparison.getArtefactType());
				variables.put("comparisonMayNotBeForSameArtefact", comparison.historyMayNotBeForSameArtefact());
				variables.put("fromDate", comparison.getFromScanDate());
				variables.put("toDate", comparison.getToScanDate());
				variables.put("openVulnerabilities", comparison.getOpenVulnerabilities());
				variables.put("closedVulnerabilities", comparison.getClosedVulnerabilities());
				variables.put("whitelistedVulnerabilities", comparison.getWhitelistedVulnerabilities());
				variables.put("trivySummaryVersion", configuration.getAppVersion());
				variables.put("stringUtils", new TrivySummaryStringUtils());
				variables.put("svgGraph", configuration.isOfflineMode() ? "" : GenerateGraph.GetSVG(comparison.getOpenVulnerabilities(), configuration));
				variables.put("statusMessage", statusMessage);
				variables.put("statusIsWarning", statusIsWarning);
				variables.put("useTodayForEPSSQuery", configuration.isUseTodayForEPSSQuery());
                variables.put("priorityModel", configuration.getPriorityModel());
				variables.put("treatment", comparison.getTreatment());
                variables.put("isOffline", configuration.isOfflineMode());
                variables.put("priorityThresholdForFailure", configuration.getFailPriorityThreshold());
                variables.put("scanRepresentsFailureCondition", resultIsFailure(openVulnerabilities));

				new RenderToPDF().renderToPDF(variables, "compareTrivyScans", configuration.getOutputFile());
			}
			else
			{
				Files.writeString(configuration.getOutputFile(), mapper.writeValueAsString(comparison));
			}
		}
		else if (history.getScanHistory().size() == 1)
		{
			// We have some meaningful history
			TrivyOneScanSummary summary = null;
			summary = history.getLatestScanSummary(title);
			openVulnerabilities = summary.getOpenVulnerabilities();
			TrivyScanWhitelistedVulnerabilities whitelistedVulnerabilities = summary.getWhitelistedVulnerabilities();
			if (!configuration.isOfflineMode()) {
                LocalDate epssQueryDate = configuration.isUseTodayForEPSSQuery() || summary.getScanDate().equals(LocalDate.now()) ? null : summary.getScanDate();

				// Try to update EPSS scores for open vulnerabilities. If they fail, we set
				// offline mode to be true.
				try {
					updateEPSSScores(openVulnerabilities, false, epssQueryDate);
					openVulnerabilities.prioritiseForRemediation(configuration.getPriorityModel());
				} catch (Exception e) {
					throw new TrivyScanCouldNotRetrieveEPSSScoresException(String.format("Could not retrieve EPSS scores for open vulnerabilities; Cannot create graph or prioritise vulnerabilities. Please check connectivity to %s or re-run TrivySummary with --offline.", BASE_EPSS_API_URL), e);
				}
				// Now update EPSS scores for whitelisted vulnerabilities.
				try {
					updateEPSSScores(whitelistedVulnerabilities, false, epssQueryDate);
					whitelistedVulnerabilities.prioritiseForRemediation(configuration.getPriorityModel());
				} catch (Exception e) {
					String warning = "Could not retrieve EPSS scores for whitelisted vulnerabilties; these will be prioritised only by vendor severity.";
					if (statusMessage != null) {
						statusMessage = String.format("%s  %s", statusMessage, warning);
					} else {
						statusMessage = warning;
					}
					statusIsWarning = true;
				}
			}
			if (configuration.getTreatmentPlan() != null && summary.getOpenVulnerabilities().size() > 0)
			{
				summary.setTreatment(createReportedTreatment(configuration.getTreatmentPlan().getTicketSystemURLTemplate(), configuration.getTreatmentPlan().getVulnerabilityTreatment(
												summary.getArtefactName(),
												summary.getOpenVulnerabilities().getAllVulnerabilityIDs())));

				for (TrivyScanVulnerability trivyScanVulnerability : summary.getOpenVulnerabilities()) {
					trivyScanVulnerability.setTreatment(createReportedTreatment(configuration.getTreatmentPlan().getTicketSystemURLTemplate(), configuration.getTreatmentPlan().getVulnerabilityTreatment(
												summary.getArtefactName(),
												Set.of(trivyScanVulnerability.getVulnerabilityID()))));
				}
			}

			if (configuration.getOutputFile().toString().endsWith(".pdf"))
			{
				Map<String, Object> variables = new HashMap<>();
				variables.put("title", summary.getTitle());
				variables.put("artefactName", summary.getArtefactName());
				variables.put("artefactType", summary.getArtefactType());
				variables.put("scanDate", summary.getScanDate());
				variables.put("openVulnerabilities", summary.getOpenVulnerabilities());
				variables.put("whitelistedVulnerabilities", summary.getWhitelistedVulnerabilities());
				variables.put("trivySummaryVersion", configuration.getAppVersion());
				variables.put("stringUtils", new TrivySummaryStringUtils());
				variables.put("svgGraph", configuration.isOfflineMode() ? "" : GenerateGraph.GetSVG(summary.getOpenVulnerabilities(), configuration));
				variables.put("statusMessage", statusMessage);
				variables.put("statusIsWarning", statusIsWarning);
				variables.put("useTodayForEPSSQuery", configuration.isUseTodayForEPSSQuery());
                variables.put("priorityModel", configuration.getPriorityModel());
				variables.put("treatment", summary.getTreatment());
                variables.put("isOffline", configuration.isOfflineMode());
                variables.put("priorityThresholdForFailure", configuration.getFailPriorityThreshold());
                variables.put("scanRepresentsFailureCondition", resultIsFailure(openVulnerabilities));

				new RenderToPDF().renderToPDF(variables, "summariseTrivyScan", configuration.getOutputFile());
			}
			else
			{
				Files.writeString(configuration.getOutputFile(), mapper.writeValueAsString(summary));
			}
		}
		else
		{
			throw new TrivyScanHistoryNotDeepEnoughException("No scans in history");
		}

		// Now we look at the most recent scan results and examine the severity of open vulnerabilities, returning true if there are vulnerabilities above the fail threshold
        return resultIsFailure(openVulnerabilities);
	}

    private boolean resultIsFailure(TrivyScanVulnerabilities openVulnerabilities)
    {
		if (configuration.getFailPriorityThreshold() != null)
		{
			for (VulnerabilityPriority priority : VulnerabilityPriority.values())
			{
				if (priority.ordinal() < configuration.getFailPriorityThreshold().ordinal()) continue; // Below the threshold

				Integer countVulns = openVulnerabilities.getVulnerabilitiesAtPriority(priority).size();

				if (countVulns != null && countVulns.intValue() > 0) return true;
			}
		}
		// We've got this far, so we've no open vulnerabilities above the threshold.
		return false;
    }

	public void addTrivyScanFileToHistory(Path inputScan) throws IOException, TrivyScanHistoryMustBeForSameArtefactType
	{
		try (InputStream in = Files.newInputStream(inputScan))
		{
			TrivyScan scan = TrivyScanLoader.loadTrivyScan(in);

			LocalDate dateOfScan = LocalDate.ofInstant(Files.getLastModifiedTime(inputScan).toInstant(), ZoneId.systemDefault());
			if (scan.getCreatedAt() != null)
			{
				dateOfScan = scan.getCreatedAt().toLocalDate();
			}

			history.addScan(dateOfScan, scan);
		}
	}

    private final int MAX_BATCH_SIZE_FOR_EPSS_API = 50;

    private void updateEPSSScores(Collection<? extends TrivyScanVulnerability> vulnerabilities, boolean force, LocalDate queryDate) throws IOException, InterruptedException, TrivyScanCouldNotRetrieveEPSSScoresException
    {
        TrivyScanVulnerabilities vulnerabilitiesRequiringLPSSScores = new TrivyScanVulnerabilities();

        for (TrivyScanVulnerability vulnerability : vulnerabilities)
        {
            if (force || vulnerability.getEpssScore() == null)
            {
                vulnerabilitiesRequiringLPSSScores.add(vulnerability);

                if (vulnerabilitiesRequiringLPSSScores.size() >= MAX_BATCH_SIZE_FOR_EPSS_API)
                {
                    retrieveEPSSScores(vulnerabilitiesRequiringLPSSScores, queryDate);
                    vulnerabilitiesRequiringLPSSScores = new TrivyScanVulnerabilities();
                }
            }
        }

        if (vulnerabilitiesRequiringLPSSScores.size() > 0)
        {
            retrieveEPSSScores(vulnerabilitiesRequiringLPSSScores, queryDate);
        }
    }

	private static final String BASE_EPSS_API_URL = "https://api.first.org/data/v1/epss";

    private void retrieveEPSSScores(TrivyScanVulnerabilities vulnerabilities, LocalDate queryDate) throws IOException, InterruptedException, TrivyScanCouldNotRetrieveEPSSScoresException
    {
        StringBuffer urlString = null;
        for (TrivyScanVulnerability vulnerability : vulnerabilities)
        {
            if (urlString == null)
            {
                urlString = new StringBuffer(BASE_EPSS_API_URL + "?cve=");
                urlString.append(vulnerability.getVulnerabilityID());
            }
            else
            {
                urlString.append(",");
                urlString.append(vulnerability.getVulnerabilityID());
            }
        }

        if (urlString == null) return;

		if (queryDate != null)
	    {
		    urlString.append(String.format("&date=%s", queryDate.toString()));
		}

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(urlString.toString()))
            .build();

		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		String responseBody = response.body();
		if (response.statusCode() != 200)
		{
			// An error occurred.
			throw new TrivyScanCouldNotRetrieveEPSSScoresException(String.format("Error returned from EPSS service. Response = %s", responseBody), null);
		}
	
		EPSSResponse epssResponse = mapper.readValue(responseBody, EPSSResponse.class);

		for (EPSSData epssData : epssResponse.getData())
		{
			// We find the corresponding TrivyScanVulnerability and update the EPSS score
			for (TrivyScanVulnerability vulnerability : vulnerabilities)
			{
				if (vulnerability.getVulnerabilityID().equalsIgnoreCase(epssData.getVulnerabilityID()))
				{
					vulnerability.setEpssScore(epssData.getEpssScore());
					break;
				}
			}
		}
    }

	private ReportedTreatment createReportedTreatment(String ticketURITemplate, VulnerabilityTreatment treatment)
	{
		if (treatment == null) return new ReportedTreatment(new java.util.ArrayList<>(), List.of(configuration.getTreatmentPlan().getDefaultNoteText()));

		java.util.List<TicketedEntry> tickets = new java.util.ArrayList<>();
		for (var entry : treatment.getTreatmentPlanEntries())
		{
			String ticketURI = null;
			if (entry.getTicketId() != null && ticketURITemplate != null)
			{
				ticketURI = ticketURITemplate.replace("{ticketId}", entry.getTicketId());
			}
			tickets.add(new TicketedEntry(entry.getTicketId(), ticketURI, entry.getDescription()));
		}
		List<String> notes = new java.util.ArrayList<>();
		for (var entry : treatment.getNotes())
		{
			notes.add(entry.getNoteText());
		}

		return new ReportedTreatment(tickets, notes);
	}
}
