package com.fujitsu.edgewareroad.trivyutils.dto.trivyscan;

import java.util.TreeSet;

import com.fujitsu.edgewareroad.trivyutils.dto.whitelist.WhitelistEntries;
import com.fujitsu.edgewareroad.trivyutils.dto.whitelist.WhitelistEntry;

public class TrivyScanWhitelistedVulnerabilities extends TreeSet<TrivyScanWhitelistedVulnerability> {
    public TrivyScanVulnerabilities filterWhitelistedVulnerabilities(TrivyScanVulnerabilities unfilteredVulnerabilities, WhitelistEntries whitelistEntries)
    {
        TrivyScanVulnerabilities filteredVulnerabilities = new TrivyScanVulnerabilities();

        for (TrivyScanVulnerability vulnerability : unfilteredVulnerabilities)
        {
            WhitelistEntry whitelistEntry = whitelistEntries.findByVulnerabilityID(vulnerability.getVulnerabilityID());

            if (whitelistEntry != null)
            {
                // This needs to be a whitelisted vulnerability and added to this list
                this.add(new TrivyScanWhitelistedVulnerability(vulnerability, whitelistEntry));
            }
            else
            {
                // This is in our filter set
                filteredVulnerabilities.add(vulnerability);
            }
        }
        return filteredVulnerabilities;
    }
}
