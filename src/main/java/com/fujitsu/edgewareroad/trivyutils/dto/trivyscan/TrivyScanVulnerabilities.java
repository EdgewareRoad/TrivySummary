package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import java.util.Collection;
import java.util.TreeSet;

public class TrivyScanVulnerabilities extends TreeSet<TrivyScanVulnerability> {
    protected TrivyScanVulnerabilities()
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

    /**
     * Gets vulnerabilities filtered by chosen severity
     * @return Vulnerabilities at the chosen severity
     */
    public TrivyScanVulnerabilities getVulnerabilitiesAtSeverity(VulnerabilitySeverity severity)
    {
        TrivyScanVulnerabilities vulnerabilitiesToReturn = new TrivyScanVulnerabilities();

        for(TrivyScanVulnerability vulnerability : this)
        {
            if (vulnerability.getSeverity().equals(severity))
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
}
