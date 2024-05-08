package com.fujitsu.edgewareroad.trivysummary;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.CleanupMode;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;

import com.fasterxml.jackson.core.exc.StreamReadException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory.TrivyScanHistoryMustBeForSameArtefactType;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistoryNotDeepEnoughException;
import com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel.PriorityModel;
import com.fujitsu.edgewareroad.trivyutils.dto.whitelist.WhitelistEntries;

@SpringBootTest
class TrivySummaryAppTests {

	static ObjectMapper mapper = new ObjectMapper();
	static ClassLoader classLoader = TrivySummaryAppTests.class.getClassLoader();
	static Path pathTestApp001Scan, pathTestApp002Scan, pathTestApp003Scan;

	static {
		try {
			pathTestApp001Scan = Path.of(classLoader.getResource("testapp/testapp-0.0.1.json").toURI());
			pathTestApp002Scan = Path.of(classLoader.getResource("testapp/testapp-0.0.2.json").toURI());
			pathTestApp003Scan = Path.of(classLoader.getResource("testapp/testapp-0.0.3.json").toURI());
			}
		catch(Exception e){
			assertTrue(false, e.getMessage());
		}
	}

	public TrivySummaryAppTests() {
	    mapper.registerModule(new JavaTimeModule());
	}

	public enum TestScenario {
		SINGLEFILE_TEST001(Arrays.asList(pathTestApp001Scan)),
		SINGLEFILE_TEST002(Arrays.asList(pathTestApp002Scan)),
		SINGLEFILE_TEST003(Arrays.asList(pathTestApp003Scan)),
		COMPARE_TEST001_TEST002(Arrays.asList(pathTestApp001Scan, pathTestApp002Scan)),
		COMPARE_TEST002_TEST003(Arrays.asList(pathTestApp002Scan, pathTestApp003Scan)),
		COMPARE_TEST001_TEST003(Arrays.asList(pathTestApp001Scan, pathTestApp003Scan));

		private final List<Path> paths;

		private TestScenario(List<Path> paths)
		{
			this.paths = paths;
		}

		public List<Path> getPaths()
		{
			return this.paths;
		}
	}

	@Test
	void contextLoads(@TempDir(cleanup = CleanupMode.NEVER) Path tempDir) throws URISyntaxException, StreamReadException, DatabindException, IOException, TrivyScanHistoryMustBeForSameArtefactType, TrivyScanHistoryNotDeepEnoughException {
		PriorityModel priorityModelElliptical = mapper.readValue(Path.of(classLoader.getResource("samplePriorityModelElliptical.json").toURI()).toFile(), PriorityModel.class);
		PriorityModel priorityModelRectangular = mapper.readValue(Path.of(classLoader.getResource("samplePriorityModelRectangular.json").toURI()).toFile(), PriorityModel.class);
		PriorityModel priorityModelSeverityOnly = mapper.readValue(Path.of(classLoader.getResource("samplePriorityModelSeverityOnly.json").toURI()).toFile(), PriorityModel.class);
		WhitelistEntries whitelistEntries1 = mapper.readValue(Path.of(classLoader.getResource("sampleWhitelist1.json").toURI()).toFile(), WhitelistEntries.class);
		WhitelistEntries whitelistEntries2 = mapper.readValue(Path.of(classLoader.getResource("sampleWhitelist2.json").toURI()).toFile(), WhitelistEntries.class);

		final List<Boolean> booleans = Arrays.asList(Boolean.TRUE, Boolean.FALSE);
		final List<PriorityModel> priorityModels = Arrays.asList(priorityModelElliptical, priorityModelRectangular, priorityModelSeverityOnly);
		for (TestScenario scenario : TestScenario.values())
		{
			for (Boolean useTodayForEPSSQuery : booleans)
			{
				for (PriorityModel priorityModel : priorityModels)
				{
					TrivySummary.Configuration configuration = new TrivySummary.Configuration();

					configuration.setAppVersion("x.y.z");
					configuration.setUseTodayForEPSSQuery(useTodayForEPSSQuery.booleanValue());
					configuration.setPriorityModel(priorityModel);

					String fileName = String.format("trivysummary-test-%s-%s-%s.pdf", scenario.name(), priorityModel.getType().name(), useTodayForEPSSQuery ? "EPSSTODAY" : "EPSSSCANDATE");
					Path outputFilePath = tempDir.resolve(fileName);

					configuration.setOutputFile(outputFilePath);
					
					TrivySummary worker = new TrivySummary(configuration);
					for (Path inputPath : scenario.getPaths())
					{
						worker.addTrivyScanFileToHistory(inputPath);
					}
					worker.addWhitelistEntries(whitelistEntries1);
					worker.addWhitelistEntries(whitelistEntries2);

					worker.summariseTrivyHistory(scenario.name());
				}
				TrivySummary.Configuration configuration = new TrivySummary.Configuration();

				configuration.setAppVersion("x.y.z");
				configuration.setOfflineMode(true);

				String fileName = String.format("trivysummary-test-%s-OFFLINE.pdf", scenario.name());
				Path outputFilePath = tempDir.resolve(fileName);

				configuration.setOutputFile(outputFilePath);
				
				TrivySummary worker = new TrivySummary(configuration);
				for (Path inputPath : scenario.getPaths())
				{
					worker.addTrivyScanFileToHistory(inputPath);
				}
				worker.addWhitelistEntries(whitelistEntries1);
				worker.addWhitelistEntries(whitelistEntries2);

				worker.summariseTrivyHistory(scenario.name());
			}
		}
	}
}
