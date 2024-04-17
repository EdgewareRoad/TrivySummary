package com.fujitsu.edgewareroad.trivysummary;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.ExitCodeGenerator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fujitsu.edgewareroad.trivyutils.GenerateGraph;
import com.fujitsu.edgewareroad.trivyutils.RenderToPDF;
import com.fujitsu.edgewareroad.trivyutils.TrivyScanLoader;
import com.fujitsu.edgewareroad.trivyutils.TrivySummaryStringUtils;
import com.fujitsu.edgewareroad.trivyutils.dto.VulnerabilityScorePriorityThresholds;
import com.fujitsu.edgewareroad.trivyutils.dto.firstapiv1.EPSSData;
import com.fujitsu.edgewareroad.trivyutils.dto.firstapiv1.EPSSResponse;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyOneScanSummary;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyTwoScanComparison;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory.TrivyScanHistoryMustBeForSameArtefactType;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory.TrivyScanHistoryNotDeepEnoughException;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScan;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerability;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.VulnerabilitySeverity;
import com.fujitsu.edgewareroad.trivyutils.dto.whitelist.WhitelistEntries;
import com.openhtmltopdf.slf4j.Slf4jLogger;
import com.openhtmltopdf.util.XRLog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.ZoneId;

@SpringBootApplication
public class TrivySummaryApp implements ApplicationRunner, ExitCodeGenerator {

	private int exitCode; // initialised with 0

	public static void main(String[] args) {
		// Suppress logging and banner output that otherwise we can't control
		System.setProperty("spring.main.banner-mode", "off");
		XRLog.setLoggerImpl(new Slf4jLogger());

		System.exit(SpringApplication.exit(SpringApplication.run(TrivySummaryApp.class, args)));
	}

	@Autowired
	private TrivySummaryConfiguration config;

    private static HttpClient client = HttpClient.newHttpClient();
	private boolean offlineMode = false;

	@Override
	public void run(ApplicationArguments args) {
		Path workingDirectory = Path.of(System.getProperty("user.dir"));
		Path outputFile = Paths.get(System.getProperty("user.dir"), "output.json");
		Double minimumCVSSToPrioritise = null, minimumEPSSToPrioritise = null;

		VulnerabilitySeverity failSeverityThreshold = null;

		if (args.containsOption("help"))
		{
			displayHelp();
			return;
		}

		if (args.containsOption("version"))
		{
			output(config.getVersion());
			return;
		}

		if (args.containsOption("offline"))
		{
			offlineMode = true;
			return;
		}

		if (args.containsOption("outputFile"))
		{
			List<String> inputValues = args.getOptionValues("outputFile");
			if (inputValues.size() == 0)
			{
				output("ERROR: outputFile option specified with empty path");
				output("");
				displayHelp();
				this.exitCode = -1;
				return;
			}
			if (inputValues.size() > 1)
			{
				output("ERROR: outputFile option specified with multiple paths");
				output("");
				displayHelp();
				this.exitCode = -1;
				return;
			}
			outputFile = workingDirectory.resolve(inputValues.iterator().next());
			Path outputDir = outputFile.getParent();
			if (!Files.isDirectory(outputDir) || !Files.isReadable(outputDir))
			{
				output("ERROR: outputFile %s is not in a readable folder", outputFile.toString());
				output("");
				displayHelp();
				this.exitCode = -1;
				return;
			}
		}

		if (args.containsOption("minimumCVSSToPrioritise"))
		{
			List<String> inputValues = args.getOptionValues("minimumCVSSToPrioritise");
			if (inputValues.size() > 1)
			{
				output("ERROR: minimumCVSSToPrioritise option specified multiple times. Only one value is permitted");
				output("");
				displayHelp();
				this.exitCode = -1;
				return;
			}
			if (inputValues.size() == 1)
			{
				try {
					minimumCVSSToPrioritise = Double.parseDouble(inputValues.iterator().next());
					if (minimumCVSSToPrioritise < 0.0d || minimumCVSSToPrioritise > 10.0d) throw new IllegalArgumentException();
				}
				catch(Exception e)
				{
					// Wasn't a valid string
					output("ERROR: minimumCVSSToPrioritise value was not a valid decimal number between 0 and 10.");
					output("");
					displayHelp();
					this.exitCode = -1;
					return;
				}
			}
		}

		if (args.containsOption("minimumEPSSToPrioritise"))
		{
			List<String> inputValues = args.getOptionValues("minimumEPSSToPrioritise");
			if (inputValues.size() > 1)
			{
				output("ERROR: minimumEPSSToPrioritise option specified multiple times. Only one value is permitted");
				output("");
				displayHelp();
				this.exitCode = -1;
				return;
			}
			if (inputValues.size() == 1)
			{
				try {
					minimumEPSSToPrioritise = Double.parseDouble(inputValues.iterator().next());
					if (minimumEPSSToPrioritise < 0.0d || minimumEPSSToPrioritise > 1.0d) throw new IllegalArgumentException();
				}
				catch(Exception e)
				{
					// Wasn't a valid string
					output("ERROR: minimumEPSSToPrioritise value was not a valid decimal number between 0 and 1");
					output("");
					displayHelp();
					this.exitCode = -1;
					return;
				}
			}
		}

		List<String> inputFiles = args.getNonOptionArgs();
		if (inputFiles.size() == 0)
		{
			output("ERROR: no input files specified");
			displayHelp();
			this.exitCode = -1;
			return;
		}
		if (inputFiles.size() > 2)
		{
			output("ERROR: too many input files specified");
			displayHelp();
			this.exitCode = -1;
			return;
		}

		String title = null;
		List<String> inputValues = args.getOptionValues("title");
		if (inputValues != null && inputValues.size() > 0)
		{
			title = inputValues.iterator().next();
		}

		List<String> intendedfailSeverityThresholdAsStrings = args.getOptionValues("failSeverityThreshold");
		if (intendedfailSeverityThresholdAsStrings != null && intendedfailSeverityThresholdAsStrings.size() > 0)
		{
			try {
				failSeverityThreshold = VulnerabilitySeverity.valueOf(intendedfailSeverityThresholdAsStrings.iterator().next());
			}
			catch (IllegalArgumentException e)
			{
				output("ERROR: unknown vulnerability severity %s. Must be one of LOW, MEDIUM, HIGH or CRITICAL.");
				displayHelp();
				this.exitCode = -1;
				return;
			}
		}

		VulnerabilityScorePriorityThresholds priorityThresholds
			= new VulnerabilityScorePriorityThresholds(minimumCVSSToPrioritise, minimumEPSSToPrioritise);
			
		TrivyScanHistory history = new TrivyScanHistory();

		List<String> whitelistFileNames = args.getOptionValues("whitelist");
		if (whitelistFileNames != null && whitelistFileNames.size() > 0)
		{
			// We must create our whitelist
			for (String whiteListFileName : whitelistFileNames)
			{
				Path whiteListFilePath = workingDirectory.resolve(whiteListFileName);

				ObjectMapper mapper = new ObjectMapper();
		        mapper.registerModule(new JavaTimeModule());
	            try {
					WhitelistEntries newEntries = mapper.readValue(whiteListFilePath.toFile(), WhitelistEntries.class);
					history.getWhitelistEntries().addAll(newEntries);
				} catch (StreamReadException e) {
					output("ERROR: JSON Parsing exception for whitelist file %s: %s", whiteListFilePath.toString(), e.getMessage());
				} catch (DatabindException e) {
					output("ERROR: JSON Mapping exception for whitelist file %s: %s", whiteListFilePath.toString(), e.getMessage());
				} catch (IOException e) {
					output("ERROR: File IO exception for whitelist file %s", whiteListFilePath.toString());
				}
			}
		}

		List<Path> paths = new ArrayList<>();
		for (String inputFileName : inputFiles) {
			Path filePath = workingDirectory.resolve(inputFileName);
			paths.add(filePath);

			try {
				addTrivyScanFileToHistory(history, filePath);
			} catch (IOException e) {
				output("ERROR: Could not read input file %s", filePath.toString());
				output("");
				displayHelp();
				this.exitCode = -1;
				return;
			} catch (TrivyScanHistoryMustBeForSameArtefactType e) {
				output("ERROR: %s", e.getMessage());
				output("");
				displayHelp();
				this.exitCode = -1;
				return;
			}
		}

		try {
			boolean thereAreOutstandingVulnerabilitiesAboveThreshold = summariseTrivyHistory(title, history, outputFile, failSeverityThreshold, priorityThresholds);

			if (thereAreOutstandingVulnerabilitiesAboveThreshold)
			{
				this.exitCode = -1;
			}
		} catch (IOException e) {
			output("ERROR: Could not write output file %s", outputFile.toString());
			output("");
			displayHelp();
			this.exitCode = -1;
			return;
		} catch (TrivyScanHistoryNotDeepEnoughException e) {
			output("ERROR: System error - Trivy Scan History not deep enough - should never reach this");
			this.exitCode = -1;
			return;
		}
	}

	@Override
	public int getExitCode() {
		return this.exitCode;
	}

	private void displayHelp()
	{
		String title = String.format("TrivySummary %s", config.getVersion());
		output(title);
		// String of equals signs used to underline the above title
		output(IntStream.range(0, title.length()).mapToObj(index -> "=").collect(Collectors.joining()));
		output("");
		output("Either:");
		output("  trivysummary <trivyScanOutput>.json <args>");
		output("    --- Processes a single Trivy scan JSON output");
		output("        Produces a summarised view of the Trivy scan tailored for easier");
		output("        reading and reporting.");
		output("Or:");
		output("  trivysummary <previousTrivyOutput>.json <latestTrivyOutput>.json <args>");
		output("    --- Processes two Trivy scans (from each scan's JSON output), a previous");
		output("        scan and the current one. Similar to the simple summary above, and");
		output("        allows a view to be taken of improvements made, & what's left to fix.");

		output("");
		output("Note that, on Windows, trivysummary.bat should be used as the command.");

		output("");
		output("For scan dates, this application relies on the createdAt property added by");
		output("later versions of Trivy (since v0.48.0).");

		output("");
		output("Arguments");
		output("=========");
		output("");
		output("  --help");
		output("    Displays this help message");
		output("");
		output("  --title=...");
		output("    Sets a report title. If unset, a default title is used containing");
		output("    the input file path(s) provided");
		output("");
		output("  --outputFile=...");
		output("    The required output file name. If the filename ends in .pdf then the");
		output("    output is a PDF report. If not, a JSON format is used. Defaults to");
		output("    \"trivysummary.pdf\" in the current working directory.");
		output("");
		output("  --failSeverityThreshold=...");
		output("    The severity threshold at or above which any open vulnerabilities");
		output("    will cause this app to return an error (returns -1, rather than 0).");
		output("    Must be one of LOW, MEDIUM, HIGH or CRITICAL.");
		output("    If unset, an error won't be returned for any set minimum severity");
		output("    but, if prioritisation is in use (see below), any open high priority");
		output("    vulnerabilities will generate an error.");
		output("");
		output("  --whitelist=...");
		output("    If set, one or more files in JSON format listing CVEs which should be");
		output("    whitelisted in the output. You can specify this argument multiple times");
		output("    if you wish to load multiple whitelists");
		output("");
		output("  --offline");
		output("    If set, TrivySummary will not attempt to access EPSS scores to assess");
		output("    the exploitability of CVEs. This will bypass graphing and prioritisation");
		output("    but is useful if using this tool from airgapped environments.");
		output("");
		output("  --minimumCVSSToPrioritise");
		output("    If this is set, TrivySummary will categorise CVEs into high priority and");
		output("    lower priority bands. This should be a CVE CVSSv3 score, i.e. between");
		output("    0.0 and 10.0.");
		output("    If this isn't set but --minimumEPSSToPrioritise is set, then defaults to 0.0");
		output("");
		output("  --minimumEPSSToPrioritise");
		output("    If this is set, TrivySummary will categorise CVEs into high priority and");
		output("    lower priority bands. This should be an EPSS score, i.e. between");
		output("    0.0 and 1.0.");
		output("    If this isn't set but --minimumCVSSToPrioritise is set, then defaults to 0.0");
	}

	private boolean summariseTrivyHistory(String title, TrivyScanHistory history, Path outputFile, VulnerabilitySeverity severityfailSeverityThreshold, VulnerabilityScorePriorityThresholds priorityThresholds) throws IOException, TrivyScanHistoryNotDeepEnoughException
	{
		String statusMessage = null;
		boolean statusIsWarning = false;

		TrivyOneScanSummary summary = null;
		summary = history.getLatestScanSummary(title);
		if (offlineMode)
		{
			statusMessage = "Offline mode. No EPSS or prioritisation applied";
		}
		else
		{
			TrivyScanVulnerabilities openVulnerabilities = summary.getOpenVulnerabilities().getVulnerabilities();
			try {
				updateEPSSScores(openVulnerabilities, false);
				openVulnerabilities.prioritiseForRemediation(priorityThresholds);
			} catch (Exception e)
			{
				statusMessage = "Could not retrieve EPSS scores. No graph or prioritisation applied.";
				statusIsWarning = true;
				offlineMode = true;	// Set this flag so we don't work with incomplete data
			}
		}

		if (history.getScanHistory().size() == 2)
		{
			// We have some meaningful history
			TrivyTwoScanComparison comparison = null;
			comparison = history.compareLatestScanWithPrevious(title);
			if (!offlineMode)
			{
				TrivyScanVulnerabilities openVulnerabilities = comparison.getOpenVulnerabilities().getVulnerabilities();
				try {
					updateEPSSScores(openVulnerabilities, false);
					openVulnerabilities.prioritiseForRemediation(priorityThresholds);
				} catch (Exception e)
				{
					statusMessage = "Could not retrieve EPSS scores. No graph or prioritisation applied.";
					statusIsWarning = true;
					offlineMode = true;	// Set this flag so we don't work with incomplete data
				}
			}
	
			if (outputFile.toString().endsWith(".pdf"))
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
				variables.put("trivySummaryVersion", config.getVersion());
				variables.put("stringUtils", new TrivySummaryStringUtils());
				variables.put("hasPriorityBands", !offlineMode && priorityThresholds.supportsDeprioritisation());
				variables.put("svgGraph", offlineMode ? "" : GenerateGraph.GetSVG(comparison.getOpenVulnerabilities().getVulnerabilities(), priorityThresholds));
				variables.put("statusMessage", statusMessage);
				variables.put("statusIsWarning", statusIsWarning);

				new RenderToPDF().renderToPDF(variables, "compareTrivyScans", outputFile);
			}
			else
			{
				ObjectMapper mapper = new ObjectMapper()
				.configure(SerializationFeature.INDENT_OUTPUT, true)
				.configure(SerializationFeature.WRITE_ENUMS_USING_INDEX, false)
				.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
				.configure(SerializationFeature.WRITE_DATES_WITH_CONTEXT_TIME_ZONE, true)
				.setSerializationInclusion(Include.NON_NULL);

				Files.writeString(outputFile, mapper.writeValueAsString(comparison));
			}
		}
		if (history.getScanHistory().size() == 1)
		{
			// We have some meaningful history

			if (outputFile.toString().endsWith(".pdf"))
			{
				Map<String, Object> variables = new HashMap<>();
				variables.put("title", summary.getTitle());
				variables.put("artefactName", summary.getArtefactName());
				variables.put("artefactType", summary.getArtefactType());
				variables.put("scanDate", summary.getScanDate());
				variables.put("openVulnerabilities", summary.getOpenVulnerabilities());
				variables.put("whitelistedVulnerabilities", summary.getWhitelistedVulnerabilities());
				variables.put("trivySummaryVersion", config.getVersion());
				variables.put("stringUtils", new TrivySummaryStringUtils());
				variables.put("hasPriorityBands", !offlineMode && priorityThresholds.supportsDeprioritisation());
				variables.put("svgGraph", offlineMode ? "" : GenerateGraph.GetSVG(summary.getOpenVulnerabilities().getVulnerabilities(), priorityThresholds));
				variables.put("statusMessage", statusMessage);
				variables.put("statusIsWarning", statusIsWarning);

				new RenderToPDF().renderToPDF(variables, "summariseTrivyScan", outputFile);
			}
			else
			{
				ObjectMapper mapper = new ObjectMapper()
				.configure(SerializationFeature.INDENT_OUTPUT, true)
				.configure(SerializationFeature.WRITE_ENUMS_USING_INDEX, false)
				.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
				.configure(SerializationFeature.WRITE_DATES_WITH_CONTEXT_TIME_ZONE, true)
				.setSerializationInclusion(Include.NON_NULL);

				Files.writeString(outputFile, mapper.writeValueAsString(summary));
			}
		}

		// Now we look at the most recent scan results and examine the severity of open vulnerabilities, returning true if there are vulnerabilities above the fail threshold
		if (severityfailSeverityThreshold != null)
		{
			for (VulnerabilitySeverity severity : VulnerabilitySeverity.values())
			{
				if (severity.ordinal() < severityfailSeverityThreshold.ordinal()) continue; // Below the threshold

				Integer countVulns = summary.getOpenVulnerabilities().getCountOfVulnerabilitiesAtSeverity(severity, null);

				if (countVulns != null && countVulns.intValue() > 0) return true;
			}
		}
		else if (priorityThresholds.supportsDeprioritisation())
		{
			// If we support prioritisation, and haven't specified a severity fail threshold then we should fail if there are any high priority
			// vulnerabilities to fix
			for (TrivyScanVulnerability vulnerability : summary.getOpenVulnerabilities().getVulnerabilities())
			{
				if (vulnerability.getIsPriorityForRemediation()) return true;
			}
		}
		// We've got this far, so we've no open vulnerabilities above the threshold.
		return false;
	}

	private void addTrivyScanFileToHistory(TrivyScanHistory history, Path inputScan) throws IOException, TrivyScanHistoryMustBeForSameArtefactType
	{
		try (InputStream in = Files.newInputStream(inputScan))
		{
			TrivyScan scan = TrivyScanLoader.loadTrivyScan(in);

			LocalDate dateOfScan = LocalDate.ofInstant(Files.getLastModifiedTime(inputScan).toInstant(), ZoneId.systemDefault());
			if (scan.getCreatedAt() != null)
			{
				dateOfScan = LocalDate.ofInstant(scan.getCreatedAt().toInstant(), ZoneId.systemDefault());
			}

			history.addScan(dateOfScan, scan);
		}
	}

    private final int MAX_BATCH_SIZE_FOR_EPSS_API = 50;

    private void updateEPSSScores(TrivyScanVulnerabilities vulnerabilities, boolean force) throws IOException, InterruptedException
    {
        TrivyScanVulnerabilities vulnerabilitiesRequiringLPSSScores = new TrivyScanVulnerabilities();

        for (TrivyScanVulnerability vulnerability : vulnerabilities)
        {
            if (force || vulnerability.getEPSSScore() == null)
            {
                vulnerabilitiesRequiringLPSSScores.add(vulnerability);

                if (vulnerabilitiesRequiringLPSSScores.size() >= MAX_BATCH_SIZE_FOR_EPSS_API)
                {
                    retrieveEPSSScores(vulnerabilitiesRequiringLPSSScores);
                    vulnerabilitiesRequiringLPSSScores = new TrivyScanVulnerabilities();
                }
            }
        }

        if (vulnerabilitiesRequiringLPSSScores.size() > 0)
        {
            retrieveEPSSScores(vulnerabilitiesRequiringLPSSScores);
        }
    }

    private void retrieveEPSSScores(TrivyScanVulnerabilities vulnerabilities) throws IOException, InterruptedException
    {
        StringBuffer urlString = null;
        for (TrivyScanVulnerability vulnerability : vulnerabilities)
        {
            if (urlString == null)
            {
                urlString = new StringBuffer("https://api.first.org/data/v1/epss?cve=");
                urlString.append(vulnerability.getVulnerabilityID());
            }
            else
            {
                urlString.append(",");
                urlString.append(vulnerability.getVulnerabilityID());
            }
        }

        if (urlString == null) return;

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(urlString.toString()))
            .build();

		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		String responseBody = response.body();
	
		ObjectMapper mapper = new ObjectMapper();
		mapper.registerModule(new JavaTimeModule());
		EPSSResponse epssResponse = mapper.readValue(responseBody, EPSSResponse.class);

		for (EPSSData epssData : epssResponse.getData())
		{
			// We find the corresponding TrivyScanVulnerability and update the EPSS score
			for (TrivyScanVulnerability vulnerability : vulnerabilities)
			{
				if (vulnerability.getVulnerabilityID().equalsIgnoreCase(epssData.getVulnerabilityID()))
				{
					vulnerability.setEPSSScore(epssData.getEpssScore());
					break;
				}
			}
		}
    }

	private void output(String messageTemplate, Object... args)
	{
		String message = String.format(messageTemplate, args);
		System.out.println(message);
	}
}
