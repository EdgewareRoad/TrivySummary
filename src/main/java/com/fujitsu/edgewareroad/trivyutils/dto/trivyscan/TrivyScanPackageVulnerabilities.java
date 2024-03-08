package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import java.util.Collection;
import java.util.TreeSet;

public class TrivyScanPackageVulnerabilities extends TreeSet<TrivyScanPackageVulnerability> {
    public TrivyScanPackageVulnerabilities() {
        super();
    }

    public TrivyScanPackageVulnerabilities(Collection<TrivyScanPackageVulnerability> vulnerabilities) {
        super(vulnerabilities);
    }

    /**
     * Gets vulnerabilities filtered by chosen severity
     * @return Vulnerabilities at the chosen severity
     */
    public TrivyScanPackageVulnerabilities getPackageVulnerabilitiesAtSeverity(VulnerabilitySeverity severity)
    {
        TrivyScanPackageVulnerabilities vulnerabilitiesToReturn = new TrivyScanPackageVulnerabilities();

        for(TrivyScanPackageVulnerability vulnerability : this)
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
    public TrivyScanPackageVulnerabilities getPackageVulnerabilitiesAtSeverityOrHigher(VulnerabilitySeverity severity)
    {
        TrivyScanPackageVulnerabilities vulnerabilitiesToReturn = new TrivyScanPackageVulnerabilities();

        for(TrivyScanPackageVulnerability vulnerability : this)
        {
            if (vulnerability.getSeverity().compareTo(severity) >= 0)
            {
                vulnerabilitiesToReturn.add(vulnerability);
            }
        }

        return vulnerabilitiesToReturn;
    }

    public TrivyScanVulnerabilities getVulnerabilitiesWithoutPackages()
    {
        return new TrivyScanVulnerabilities(this);
    }
}
