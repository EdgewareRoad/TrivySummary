package com.fujitsu.edgewareroad.trivyutils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDate;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyTwoScanComparison;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistory.TrivyScanHistoryMustBeForSameArtefactType;
import com.fujitsu.edgewareroad.trivyutils.dto.history.TrivyScanHistoryNotDeepEnoughException;
import com.fujitsu.edgewareroad.trivyutils.dto.prioritymodel.VulnerabilityPriority;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScan;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerabilities;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.TrivyScanVulnerability;
import com.fujitsu.edgewareroad.trivyutils.dto.trivyscan.VulnerabilitySeverity;

class TrivyScanLoaderTests {

	@Test
	void testTrivyTestAppScanLoad() throws IOException, TrivyScanHistoryNotDeepEnoughException, TrivyScanHistoryMustBeForSameArtefactType {
		Logger logger = LoggerFactory.getLogger(TrivyScanLoaderTests.class);

		TrivyScanHistory history = new TrivyScanHistory();
		try (InputStream is = getClass().getClassLoader().getResourceAsStream("testapp/testapp-0.0.1.json"))
		{
			TrivyScan scanResults = TrivyScanLoader.loadTrivyScan(is);
			assertEquals(511, scanResults.getAllPackageVulnerabilities().size());
			assertEquals(0, scanResults.getAllPackageVulnerabilities().getPackageVulnerabilitiesAtSeverity(VulnerabilitySeverity.UNKNOWN).size());
			assertEquals(17, scanResults.getAllPackageVulnerabilities().getPackageVulnerabilitiesAtSeverity(VulnerabilitySeverity.CRITICAL).size());
			assertEquals(226, scanResults.getAllPackageVulnerabilities().getPackageVulnerabilitiesAtSeverity(VulnerabilitySeverity.HIGH).size());
			assertEquals(243, scanResults.getAllPackageVulnerabilities().getPackageVulnerabilitiesAtSeverityOrHigher(VulnerabilitySeverity.HIGH).size());

			TrivyScanVulnerabilities vulnerabilitiesWithoutPackages = scanResults.getAllPackageVulnerabilities().getVulnerabilitiesWithoutPackages();
			assertEquals(398, vulnerabilitiesWithoutPackages.size());
			assertEquals(17, vulnerabilitiesWithoutPackages.getVulnerabilitiesAtPriority(VulnerabilityPriority.CRITICAL).size());
			assertEquals(213, vulnerabilitiesWithoutPackages.getVulnerabilitiesAtPriority(VulnerabilityPriority.HIGH).size());

			for (TrivyScanVulnerability vuln : vulnerabilitiesWithoutPackages)
			{
				logger.debug("testapp-0.0.1.json has vuln {}", vuln.getVulnerabilityID());
			}

			history.addScan(LocalDate.of(2023, 1, 1), scanResults);
		}
		try (InputStream is = getClass().getClassLoader().getResourceAsStream("testapp/testapp-0.0.2.json"))
		{
			TrivyScan scanResults = TrivyScanLoader.loadTrivyScan(is);
			assertEquals(148, scanResults.getAllPackageVulnerabilities().size());
			assertEquals(0, scanResults.getAllPackageVulnerabilities().getPackageVulnerabilitiesAtSeverity(VulnerabilitySeverity.UNKNOWN).size());
			assertEquals(2, scanResults.getAllPackageVulnerabilities().getPackageVulnerabilitiesAtSeverity(VulnerabilitySeverity.CRITICAL).size());
			assertEquals(48, scanResults.getAllPackageVulnerabilities().getPackageVulnerabilitiesAtSeverity(VulnerabilitySeverity.HIGH).size());
			assertEquals(50, scanResults.getAllPackageVulnerabilities().getPackageVulnerabilitiesAtSeverityOrHigher(VulnerabilitySeverity.HIGH).size());

			TrivyScanVulnerabilities vulnerabilitiesWithoutPackages = scanResults.getAllPackageVulnerabilities().getVulnerabilitiesWithoutPackages();
			assertEquals(94, vulnerabilitiesWithoutPackages.size());
			assertEquals(2, vulnerabilitiesWithoutPackages.getVulnerabilitiesAtPriority(VulnerabilityPriority.CRITICAL).size());
			assertEquals(33, vulnerabilitiesWithoutPackages.getVulnerabilitiesAtPriority(VulnerabilityPriority.HIGH).size());

			for (TrivyScanVulnerability vuln : vulnerabilitiesWithoutPackages)
			{
				logger.debug("testapp-0.0.2.json has vuln {}", vuln.getVulnerabilityID());
			}
			
			history.addScan(LocalDate.of(2023, 6, 1), scanResults);

			TrivyTwoScanComparison comparison = history.compareLatestScanWithPrevious("");
			assertEquals(305, comparison.getClosedVulnerabilities().size());
			assertEquals(94, comparison.getOpenVulnerabilities().size());
		}
		try (InputStream is = getClass().getClassLoader().getResourceAsStream("testapp/testapp-0.0.3.json"))
		{
			TrivyScan scanResults = TrivyScanLoader.loadTrivyScan(is);
			assertEquals(0, scanResults.getAllPackageVulnerabilities().size());

			history.addScan(LocalDate.of(2024, 1, 1), scanResults);
		}
	}

}
