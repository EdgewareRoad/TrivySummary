package com.fujitsu.edgewareroad.trivysummary;

import java.util.List;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.util.ArrayList;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.CleanupMode;
import org.junit.jupiter.api.io.TempDir;

import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory.TrivyScanHistoryMustBeForSameArtefactType;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistoryNotDeepEnoughException;
import com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel.PriorityModel;
import com.fujitsu.edgewareroad.trivyutils.dto.whitelist.WhitelistEntries;

import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.DatabindException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

class TrivySummaryAppTests {

	public static void main(String[] args) throws Exception
	{
		TrivySummaryAppTests tests = new TrivySummaryAppTests();
		tests.contextLoads(java.nio.file.Files.createTempDirectory("trivysummary_", (FileAttribute<?>[])null));
	}

	static final ObjectMapper mapper = JsonMapper.builder().build();
	static ClassLoader classLoader = TrivySummaryAppTests.class.getClassLoader();

	public TrivySummaryAppTests() {
	}

	public class TestScenario {
		private final String name;
		private final List<Path> paths;

		public TestScenario(String name, List<Path> paths)
		{
			this.name = name;
			this.paths = paths;
		}

		public String getName()
		{
			return this.name;
		}

		public List<Path> getPaths()
		{
			return this.paths;
		}
	}

	@Test
	void contextLoads(@TempDir(cleanup = CleanupMode.NEVER) Path tempDir) throws URISyntaxException, StreamReadException, DatabindException, IOException, TrivyScanHistoryMustBeForSameArtefactType, TrivyScanHistoryNotDeepEnoughException, TrivyScanCouldNotRetrieveEPSSScoresException {
		PriorityModel priorityModelElliptical, priorityModelRectangular, priorityModelSeverityOnly;
		try(InputStream stream = classLoader.getResourceAsStream("samplePriorityModelElliptical.json"))
		{
			priorityModelElliptical = mapper.readValue(stream, PriorityModel.class);
		}
		try(InputStream stream = classLoader.getResourceAsStream("samplePriorityModelRectangular.json"))
		{
			priorityModelRectangular = mapper.readValue(stream, PriorityModel.class);
		}
		try(InputStream stream = classLoader.getResourceAsStream("samplePriorityModelSeverityOnly.json"))
		{
			priorityModelSeverityOnly = mapper.readValue(stream, PriorityModel.class);
		}

		WhitelistEntries whitelistEntries1, whitelistEntries2;
		try(InputStream stream = classLoader.getResourceAsStream("sampleWhitelist1.json"))
		{
			whitelistEntries1 = mapper.readValue(stream, WhitelistEntries.class);
		}
		try(InputStream stream = classLoader.getResourceAsStream("sampleWhitelist2.json"))
		{
			whitelistEntries2 = mapper.readValue(stream, WhitelistEntries.class);
		}

		final List<Boolean> booleans = Arrays.asList(Boolean.TRUE, Boolean.FALSE);
		final List<PriorityModel> priorityModels = Arrays.asList(priorityModelElliptical, priorityModelRectangular, priorityModelSeverityOnly);

		Path pathTestApp001Scan = Path.of(tempDir.toString(), "testapp-0.0.1.json");
		try(InputStream stream = classLoader.getResourceAsStream("testapp/testapp-0.0.1.json"))
		{
			Files.copy(stream, pathTestApp001Scan);
		}
		Path pathTestApp002Scan = Path.of(tempDir.toString(), "testapp-0.0.2.json");
		try(InputStream stream = classLoader.getResourceAsStream("testapp/testapp-0.0.2.json"))
		{
			Files.copy(stream, pathTestApp002Scan);
		}
		Path pathTestApp003Scan = Path.of(tempDir.toString(), "testapp-0.0.3.json");
		try(InputStream stream = classLoader.getResourceAsStream("testapp/testapp-0.0.3.json"))
		{
			Files.copy(stream, pathTestApp003Scan);
		}

		ArrayList<TestScenario> scenarios = new ArrayList<>();
		scenarios.add(new TestScenario("SINGLEFILE_TEST001", Arrays.asList(pathTestApp001Scan)));
		scenarios.add(new TestScenario("SINGLEFILE_TEST002", Arrays.asList(pathTestApp002Scan)));
		scenarios.add(new TestScenario("SINGLEFILE_TEST003", Arrays.asList(pathTestApp003Scan)));
		scenarios.add(new TestScenario("COMPARE_TEST001_TEST002", Arrays.asList(pathTestApp001Scan, pathTestApp002Scan)));
		scenarios.add(new TestScenario("COMPARE_TEST002_TEST003", Arrays.asList(pathTestApp002Scan, pathTestApp003Scan)));
		scenarios.add(new TestScenario("COMPARE_TEST001_TEST003", Arrays.asList(pathTestApp001Scan, pathTestApp003Scan)));

		for (TestScenario scenario : scenarios)
		{
			for (Boolean useTodayForEPSSQuery : booleans)
			{
				for (PriorityModel priorityModel : priorityModels)
				{
					TrivySummary worker = new TrivySummary();
					TrivySummary.Configuration configuration = worker.getConfiguration();

					configuration.setAppVersion("x.y.z");
					configuration.setUseTodayForEPSSQuery(useTodayForEPSSQuery.booleanValue());
					configuration.setPriorityModel(priorityModel);

					String fileName = String.format("trivysummary-test-%s-%s-%s.pdf", scenario.getName(), priorityModel.getType().name(), useTodayForEPSSQuery ? "EPSSTODAY" : "EPSSSCANDATE");
					Path outputFilePath = tempDir.resolve(fileName);

					configuration.setOutputFile(outputFilePath);
					
					for (Path inputPath : scenario.getPaths())
					{
						worker.addTrivyScanFileToHistory(inputPath);
					}
					worker.addWhitelistEntries(whitelistEntries1);
					worker.addWhitelistEntries(whitelistEntries2);

					worker.summariseTrivyHistory(scenario.getName());
				}
				TrivySummary worker = new TrivySummary();
				TrivySummary.Configuration configuration = worker.getConfiguration();

				configuration.setAppVersion("x.y.z");
				configuration.setOfflineMode(true);

				String fileName = String.format("trivysummary-test-%s-OFFLINE.pdf", scenario.getName());
				Path outputFilePath = tempDir.resolve(fileName);

				configuration.setOutputFile(outputFilePath);
				
				for (Path inputPath : scenario.getPaths())
				{
					worker.addTrivyScanFileToHistory(inputPath);
				}
				worker.addWhitelistEntries(whitelistEntries1);
				worker.addWhitelistEntries(whitelistEntries2);

				worker.summariseTrivyHistory(scenario.getName());
			}
		}
	}
}
