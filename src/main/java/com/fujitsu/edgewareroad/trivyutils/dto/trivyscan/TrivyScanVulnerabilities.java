package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;

public class TrivyScanVulnerabilities extends TrivyScanVulnerabilitySet<TrivyScanVulnerability> {

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

    public Set<String> getAllVulnerabilityIDs()
    {
        Set<String> vulnIDs = new TreeSet<>();
        for (TrivyScanVulnerability vuln : this)
        {
            vulnIDs.add(vuln.getVulnerabilityID());
        }
        return vulnIDs;
    }
}
