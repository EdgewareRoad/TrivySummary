package com.fujitsu.edgewareroad.trivysummary;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.ExitCodeGenerator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory.TrivyScanHistoryMustBeForSameArtefactType;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistoryNotDeepEnoughException;
import com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel.PriorityModel;
import com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel.VulnerabilityPriority;
import com.fujitsu.edgewareroad.trivyutils.dto.treatmentplan.TreatmentPlan;
import com.fujitsu.edgewareroad.trivyutils.dto.whitelist.WhitelistEntries;
import com.openhtmltopdf.slf4j.Slf4jLogger;
import com.openhtmltopdf.util.XRLog;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@SpringBootApplication
public class TrivySummaryApp implements ApplicationRunner, ExitCodeGenerator {

	private int exitCode; // initialised with 0

	private ObjectMapper mapper = JsonMapper.builder().build();

	public static void main(String[] args) {
		// Suppress logging and banner output that otherwise we can't control
		System.setProperty("spring.main.banner-mode", "off");

		if (System.getProperty("java.home") == null)
		{
			System.setProperty("java.home", TrivySummaryApp.class.getProtectionDomain().getCodeSource().getLocation().getPath());
		}

		XRLog.setLoggerImpl(new Slf4jLogger());

		System.exit(SpringApplication.exit(SpringApplication.run(TrivySummaryApp.class, args)));
	}

	@Autowired
	private TrivySummaryAppProperties appProperties;

	@Autowired
	private TrivySummary worker;

	@Override
	public void run(ApplicationArguments args) {
		Path workingDirectory = Path.of(System.getProperty("user.dir"));

		TrivySummary.Configuration configuration = worker.getConfiguration();

		configuration.setAppVersion(appProperties.getVersion());

		if (args.containsOption("help"))
		{
			displayHelp();
			return;
		}

		if (args.containsOption("version"))
		{
			output(appProperties.getVersion());
			return;
		}

		if (args.containsOption("offline"))
		{
			configuration.setOfflineMode(true);;
		}

		if (args.containsOption("useTodayForEPSSQuery"))
		{
			configuration.setUseTodayForEPSSQuery(true);;
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
			configuration.setOutputFile(workingDirectory.resolve(inputValues.iterator().next()));
			Path outputDir = configuration.getOutputFile().getParent();
			if (!Files.isDirectory(outputDir) || !Files.isReadable(outputDir))
			{
				output("ERROR: outputFile %s is not in a readable folder", configuration.getOutputFile().toString());
				output("");
				displayHelp();
				this.exitCode = -1;
				return;
			}
		}
		else if (inputFiles.size() == 1)
		{
			// If we've not set an explicit output file and we have a single input file, then derive
			// an output file from this name
			configuration.setDefaultOutputPathFromInputFile(workingDirectory.resolve(inputFiles.get(0)));
		}

		String title = null;
		List<String> inputValues = args.getOptionValues("title");
		if (inputValues != null && inputValues.size() > 0)
		{
			title = inputValues.iterator().next();
		}

		List<String> intendedfailPriorityThresholdAsStrings = args.getOptionValues("failPriorityThreshold");
		if (intendedfailPriorityThresholdAsStrings != null && intendedfailPriorityThresholdAsStrings.size() > 0)
		{
			try {
				configuration.setFailPriorityThreshold(VulnerabilityPriority.valueOf(intendedfailPriorityThresholdAsStrings.iterator().next()));
			}
			catch (IllegalArgumentException e)
			{
				output("ERROR: unknown vulnerability severity %s. Must be one of LOW, MEDIUM, HIGH or CRITICAL.");
				displayHelp();
				this.exitCode = -1;
				return;
			}
		}

		if (args.containsOption("priorityModel"))
		{
			if (configuration.isOfflineMode()) {
				output("WARNING: priorityModel option specified when in offline mode. Will default to SEVERITYONLY");
			} else {
				List<String> priorityModelValues = args.getOptionValues("priorityModel");
				if (priorityModelValues.size() > 1) {
					output("ERROR: priorityModel option specified multiple times. Only zero or one value is permitted");
					output("");
					displayHelp();
					this.exitCode = -1;
					return;
				}
				if (priorityModelValues.size() == 1) {
					Path priorityModelPath = workingDirectory.resolve(priorityModelValues.iterator().next());

					if (!Files.exists(priorityModelPath)) {
						output("ERROR: Priority model not found %s", priorityModelPath.toString());
						output("");
						displayHelp();
						this.exitCode = -1;
						return;
					}
					if (!Files.isReadable(priorityModelPath)) {
						output("ERROR: Priority model file %s is not readable", priorityModelPath.toString());
						output("");
						displayHelp();
						this.exitCode = -1;
						return;
					}

					try {
						configuration.setPriorityModel(mapper.readValue(priorityModelPath.toFile(), PriorityModel.class));
					} catch (StreamReadException e) {
						output("ERROR: JSON Parsing exception for priority model %s: %s", priorityModelPath.toString(),
								e.getMessage());
						output("");
						displayHelp();
						this.exitCode = -1;
						return;
					} catch (DatabindException e) {
						output("ERROR: JSON Mapping exception for priority model %s: %s", priorityModelPath.toString(),
								e.getMessage());
						output("");
						displayHelp();
						this.exitCode = -1;
						return;
					}
				}
			}
		}

		List<String> whitelistFileNames = args.getOptionValues("whitelist");
		if (whitelistFileNames != null && whitelistFileNames.size() > 0)
		{
			// We must create our whitelist
			for (String whiteListFileName : whitelistFileNames)
			{
				Path whiteListFilePath = workingDirectory.resolve(whiteListFileName);

				if (!Files.exists(whiteListFilePath)) {
					output("ERROR: Whitelist file not found %s", whiteListFilePath.toString());
					output("");
					displayHelp();
					this.exitCode = -1;
					return;
				}
				if (!Files.isReadable(whiteListFilePath)) {
					output("ERROR: Whitelist file file %s is not readable", whiteListFilePath.toString());
					output("");
					displayHelp();
					this.exitCode = -1;
					return;
				}

				ObjectMapper mapper = new ObjectMapper();
	            try {
					WhitelistEntries newEntries = mapper.readValue(whiteListFilePath.toFile(), WhitelistEntries.class);
					worker.addWhitelistEntries(newEntries);
				} catch (StreamReadException e) {
					output("ERROR: JSON Parsing exception for whitelist file %s: %s", whiteListFilePath.toString(), e.getMessage());
					output("");
					displayHelp();
					this.exitCode = -1;
					return;
				} catch (DatabindException e) {
					output("ERROR: JSON Mapping exception for whitelist file %s: %s", whiteListFilePath.toString(), e.getMessage());
					output("");
					displayHelp();
					this.exitCode = -1;
					return;
				}
			}
		}

		if (args.containsOption("treatmentPlan"))
		{
			List<String> treatmentPlanValues = args.getOptionValues("treatmentPlan");
			if (treatmentPlanValues.size() > 1) {
				output("ERROR: treatmentPlan option specified multiple times. Only zero or one value is permitted");
				output("");
				displayHelp();
				this.exitCode = -1;
				return;
			}
			if (treatmentPlanValues.size() == 1) {
				Path treatmentPlanPath = workingDirectory.resolve(treatmentPlanValues.iterator().next());

				if (!Files.exists(treatmentPlanPath)) {
					output("ERROR: Treatment plan not found %s", treatmentPlanPath.toString());
					output("");
					displayHelp();
					this.exitCode = -1;
					return;
				}
				if (!Files.isReadable(treatmentPlanPath)) {
					output("ERROR: Treatment plan file %s is not readable", treatmentPlanPath.toString());
					output("");
					displayHelp();
					this.exitCode = -1;
					return;
				}

				ObjectMapper mapper = new ObjectMapper();
				try {
					configuration.setTreatmentPlan(mapper.readValue(treatmentPlanPath.toFile(), TreatmentPlan.class));
				} catch (StreamReadException e) {
					output("ERROR: JSON Parsing exception for treatment plan %s: %s", treatmentPlanPath.toString(),
							e.getMessage());
					output("");
					displayHelp();
					this.exitCode = -1;
					return;
				} catch (DatabindException e) {
					output("ERROR: JSON Mapping exception for treatment plan %s: %s", treatmentPlanPath.toString(),
							e.getMessage());
					output("");
					displayHelp();
					this.exitCode = -1;
					return;
				}
			}
		}

		List<Path> paths = new ArrayList<>();
		for (String inputFileName : inputFiles) {
			Path filePath = workingDirectory.resolve(inputFileName);
			paths.add(filePath);

			try {
				worker.addTrivyScanFileToHistory(filePath);
			} catch (FileNotFoundException e) {
				output("ERROR: Could not find input file %s", filePath.toString());
				output("");
				displayHelp();
				this.exitCode = -1;
				return;
			} catch (IOException e) {
				output("ERROR: Could not read (%s) input file %s", e.getMessage(), filePath.toString());
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
			boolean thereAreOutstandingVulnerabilitiesAboveThreshold = worker.summariseTrivyHistory(title);

			if (thereAreOutstandingVulnerabilitiesAboveThreshold)
			{
				this.exitCode = -1;
			}
		} catch (IOException e) {
			output("ERROR: Could not write (%s) output file %s", e.getMessage(), configuration.getOutputFile().toString());
			output("");
			displayHelp();
			this.exitCode = -1;
			return;
		} catch (TrivyScanHistoryNotDeepEnoughException e) {
			output("ERROR: System error - Trivy Scan History not deep enough - should never reach this");
			this.exitCode = -1;
			return;
		} catch (TrivyScanCouldNotRetrieveEPSSScoresException e) {
			output("ERROR: %s", e.getMessage());
			output("Cause of EPSS score retrieval failure: %s: %s", e.getCause().getClass().getName(), e.getCause().getMessage());
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
		String title = String.format("TrivySummary %s", appProperties.getVersion());
		output(title);
		// String of equals signs used to underline the above title
		output(IntStream.range(0, title.length()).mapToObj(_ -> "=").collect(Collectors.joining()));
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
		output("  --failPriorityThreshold=...");
		output("    The priority threshold at or above which any open vulnerabilities");
		output("    will cause this app to return an error (returns -1, rather than 0).");
		output("    Must be one of LOW, MEDIUM, HIGH or CRITICAL.");
		output("    If unset, an error won't be returned for any set minimum priority.");
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
		output("  --priorityModel=...");
		output("    If this is set, TrivySummary will load the specified priority model");
		output("    JSON file.");
		output("    If this isn't set, the model defaults to SEVERITYONLY, i.e. that");
		output("    the priority is the same as the vendor severity.");
		output("");
		output("  --useTodayForEPSSQuery");
		output("    If this is set, TrivySummary will request EPSS scores for today and");
		output("    not for the date of the scan (the default).");
		output("    Is ignored if in offline mode");
	}

	private void output(String messageTemplate, Object... args)
	{
		String message = String.format(messageTemplate, args);
		System.out.println(message);
	}
}
