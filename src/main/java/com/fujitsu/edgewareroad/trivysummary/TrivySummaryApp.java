package com.fujitsu.edgewareroad.trivysummary;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fujitsu.edgewareroad.trivyutils.RenderToPDF;
import com.fujitsu.edgewareroad.trivyutils.TrivyScanLoader;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyOneScanSummary;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyTwoScanComparison;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory.TrivyScanHistoryMustBeForSameArtefactType;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory.TrivyScanHistoryNotDeepEnoughException;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScan;
import com.openhtmltopdf.slf4j.Slf4jLogger;
import com.openhtmltopdf.util.XRLog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.ZoneId;

@SpringBootApplication
public class TrivySummaryApp implements ApplicationRunner {

	public static void main(String[] args) {
		// Suppress logging and banner output that otherwise we can't control
		System.setProperty("spring.main.banner-mode", "off");
		XRLog.setLoggerImpl(new Slf4jLogger());

		SpringApplication.run(TrivySummaryApp.class, args);
	}

	@Override
	public void run(ApplicationArguments args) {
		Path workingDirectory = Path.of(System.getProperty("user.dir"));
		Path outputFile = Paths.get(System.getProperty("user.dir"), "output.json");

		if (args.containsOption("help"))
		{
			displayHelp();
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
				return;
			}
			if (inputValues.size() > 1)
			{
				output("ERROR: outputFile option specified with multiple paths");
				output("");
				displayHelp();
				return;
			}
			outputFile = workingDirectory.resolve(inputValues.getFirst());
			Path outputDir = outputFile.getParent();
			if (!Files.isDirectory(outputDir) || !Files.isReadable(outputDir))
			{
				output("ERROR: outputFile %s is not in a readable folder", outputFile.toString());
				output("");
				displayHelp();
				return;
			}
		}

		List<String> inputFiles = args.getNonOptionArgs();
		if (inputFiles.size() == 0)
		{
			output("ERROR: no input files specified");
			return;
		}
		if (inputFiles.size() > 2)
		{
			output("ERROR: too many input files specified");
			return;
		}

		String title = null;
		List<String> inputValues = args.getOptionValues("title");
		if (inputValues != null && inputValues.size() > 0)
		{
			title = inputValues.getFirst();
		}
/* 		else if (inputFiles.size() == 2)
		{
			title = String.format("Comparing %s with %s", inputFiles.get(0), inputFiles.get(1));
		}
		else
		{
			title = String.format("Summary of %s", inputFiles.get(0));
		}
*/

		TrivyScanHistory history = new TrivyScanHistory();
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
			} catch (TrivyScanHistoryMustBeForSameArtefactType e) {
				output("ERROR: %s", e.getMessage());
				output("");
				displayHelp();
			}
		}

		try {
			summariseTrivyHistory(title, history, outputFile);
		} catch (IOException e) {
			output("ERROR: Could not write output file %s", outputFile.toString());
			output("");
			displayHelp();
		} catch (TrivyScanHistoryNotDeepEnoughException e) {
			output("ERROR: System error - Trivy Scan History not deep enough - should never reach this");
		}
	}

	private void displayHelp()
	{
		output("TrivySummary usage");
		output("==================");
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
		output("For scan dates, this application uses the createdAt property added by");
		output("later versions of Trivy (since v0.48.0). If this property is not present,");
		output("the file last modified timestamp will be used (so be careful if copying");
		output("JSON files between systems before running this app).");

		output("");
		output("Arguments");
		output("=========");
		output("");
		output("  --help");
		output("    Displays this help message");
		output("");
		output("  --title");
		output("    Sets a report title. If unset, a default title is used containing");
		output("    the input file path(s) provided");
		output("");
		output("  --outputFile");
		output("    The required output file name. If the filename ends in .pdf then the");
		output("    output is a PDF report. If not, a JSON format is used. Defaults to");
		output("    \"trivysummary.pdf\" in the current working directory.");
	}

	private void summariseTrivyHistory(String title, TrivyScanHistory history, Path outputFile) throws IOException, TrivyScanHistoryNotDeepEnoughException
	{
		if (history.getScanHistory().size() == 2)
		{
			// We have some meaningful history
			TrivyTwoScanComparison comparison = null;
			comparison = history.compareLatestScanWithPrevious(title);

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
			TrivyOneScanSummary summary = null;
			summary = history.getLatestScanSummary(title);

			if (outputFile.toString().endsWith(".pdf"))
			{
				Map<String, Object> variables = new HashMap<>();
				variables.put("title", summary.getTitle());
				variables.put("artefactName", summary.getArtefactName());
				variables.put("artefactType", summary.getArtefactType());
				variables.put("scanDate", summary.getScanDate());
				variables.put("openVulnerabilities", summary.getOpenVulnerabilities());

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

	private void output(String messageTemplate, Object... args)
	{
		String message = String.format(messageTemplate, args);
		System.out.println(message);
	}
}
