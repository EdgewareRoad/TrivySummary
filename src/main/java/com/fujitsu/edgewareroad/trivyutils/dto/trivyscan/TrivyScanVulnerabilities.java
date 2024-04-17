package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import java.util.Collection;
import java.util.TreeSet;
import java.util.HashSet;

import com.fujitsu.edgewareroad.trivyutils.dto.VulnerabilityScorePriorityThresholds;

public class TrivyScanVulnerabilities extends HashSet<TrivyScanVulnerability> {

    public TrivyScanVulnerabilities()
    {
        super();
    }

    public TrivyScanVulnerabilities(Collection<TrivyScanVulnerability> collection)
    {
        this(collection, null);
    }
    
    public TrivyScanVulnerabilities(Collection<TrivyScanVulnerability> collection, Boolean inPreviousScan)
    {
        super(collection);
        if (inPreviousScan != null)
        {
            for (TrivyScanVulnerability vuln : this)
            {
                vuln.setWasInPreviousScan(inPreviousScan);
            }
        }
    }

    public TrivyScanVulnerabilities(TrivyScanPackageVulnerabilities packageVulnerabilities) {
        super();
        for (TrivyScanPackageVulnerability packageVulnerability : packageVulnerabilities)
        {
            TrivyScanVulnerability vulnNew = new TrivyScanVulnerability(packageVulnerability);
            boolean found = false;
            for (TrivyScanVulnerability vuln : this)
            {
                if (vuln.equals(vulnNew))
                {
                    // We've already got this vulnerability
                    found = true;
                    vuln.addPackageVulnerability(packageVulnerability);
                    break;
                }
            }
            if (!found)
            {
                // We've not got this vulnerability in our list so we need to add it.
                this.add(vulnNew);
            }
        }
    }

    public void prioritiseForRemediation(VulnerabilityScorePriorityThresholds priorityThresholds)
    {
        for (TrivyScanVulnerability vulnerability : this)
        {
            vulnerability.prioritiseForRemediation(priorityThresholds);
        }
    }

    /**
     * Gets vulnerabilities filtered by chosen severity
     * @param severity The target severity to filter by
     * @param priorityFilter Optional priority filter. If true, returns only those vulnerabilities marked as priority for remediation; if false, returns only those which are not. If null, no priority filter is applied
     * @return Vulnerabilities at the chosen severity
     */
    public TrivyScanVulnerabilities getVulnerabilitiesAtSeverity(VulnerabilitySeverity severity, Boolean priorityFilter)
    {
        TrivyScanVulnerabilities vulnerabilitiesToReturn = new TrivyScanVulnerabilities();

        for(TrivyScanVulnerability vulnerability : this)
        {
            if (vulnerability.getSeverity().equals(severity) && (priorityFilter == null || vulnerability.getIsPriorityForRemediation() == priorityFilter.booleanValue()))
            {
                vulnerabilitiesToReturn.add(vulnerability);
            }
        }

        return vulnerabilitiesToReturn;
    }    

    /**
     * Gets vulnerabilities filtered by chosen severity or higher than the chosen severity
     * @return Vulnerabilities at the chosen severity or higher than the chosen severity
     */
    public TrivyScanVulnerabilities getVulnerabilitiesAtSeverityOrHigher(VulnerabilitySeverity severity)
    {
        TrivyScanVulnerabilities vulnerabilitiesToReturn = new TrivyScanVulnerabilities();

        for(TrivyScanVulnerability vulnerability : this)
        {
            if (vulnerability.getSeverity().compareTo(severity) >= 0)
            {
                vulnerabilitiesToReturn.add(vulnerability);
            }
        }

        return vulnerabilitiesToReturn;
    }

    public TreeSet<TrivyScanVulnerability> getSorted()
    {
        TreeSet<TrivyScanVulnerability> sortedSet = new TreeSet<>();
        for(TrivyScanVulnerability vuln : this)
        {
            sortedSet.add(new TrivyScanVulnerability(vuln));
        }
        return sortedSet;
    }
}
