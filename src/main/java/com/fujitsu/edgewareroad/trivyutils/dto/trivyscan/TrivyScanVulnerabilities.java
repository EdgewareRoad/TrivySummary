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
        buildCVEListCommaSeparated();
    }
    
    public TrivyScanVulnerabilities(Collection<TrivyScanVulnerability> collection, Boolean inPreviousScan)
    {
        super(collection);
        buildCVEListCommaSeparated();
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

    @Override
    public boolean add(TrivyScanVulnerability vulnerability)
    {
        boolean changed = false;
        if (vulnerability != null)
        {
            changed = super.add(vulnerability);
            if (changed) 
            {
                addCVEToCommaSeparatedList(vulnerability);
            }
        }
        return changed;
    }

    @Override
    public boolean addAll(Collection<? extends TrivyScanVulnerability> vulnerabilities)
    {
        boolean changed = false;
        if (vulnerabilities != null)
        {
            for (TrivyScanVulnerability vulnerability : vulnerabilities)
            {
                changed = changed | this.add(vulnerability);
            }
        }
        return changed;
    }

    @Override
    public boolean remove(Object vulnerability)
    {
        boolean changed = false;
        if (vulnerability != null)
        {
            changed = super.remove(vulnerability);
            if (changed) {
                cveListCommaSeparated = null;
                buildCVEListCommaSeparated();
            }
        }
        return changed;
    }

    @Override
    public boolean removeAll(Collection<? extends Object> vulnerabilities)
    {
        boolean changed = super.removeAll(vulnerabilities);
        if (changed) {
            cveListCommaSeparated = null;
            buildCVEListCommaSeparated();
        }
        return changed;
    }

    private StringBuilder cveListCommaSeparated = null;

    private void addCVEToCommaSeparatedList(TrivyScanVulnerability vulnerability)
    {
        String cve = vulnerability.getVulnerabilityID();
        if (cveListCommaSeparated == null || cveListCommaSeparated.isEmpty())
        {
            cveListCommaSeparated = new StringBuilder(cve);
        }
        else
        {
            cveListCommaSeparated = cveListCommaSeparated.append(",").append(cve);
        }
    }

    private void buildCVEListCommaSeparated()
    {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (TrivyScanVulnerability vuln : this)
        {
            if (!first)
            {
                sb.append(",");
            }
            sb.append(vuln.getVulnerabilityID());
            first = false;
        }
        cveListCommaSeparated = sb;
    }

    public int getCVEListCommaSeparatedLength()
    {
        if (cveListCommaSeparated == null)
        {
            return 0;
        }
        return cveListCommaSeparated.length();
    }

    public String getCVEListCommaSeparated()
    {
        if (cveListCommaSeparated == null)
        {
            return "";
        }
        return cveListCommaSeparated.toString();
    }
}
