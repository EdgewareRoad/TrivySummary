package com.fujitsu.edgewareroad.trivyutils.dto.whitelist;

import java.util.Collection;
import java.util.TreeSet;

public class WhitelistEntries extends TreeSet<WhitelistEntry> {
    public WhitelistEntries()
    {
        super();
    }

    public WhitelistEntries(Collection<WhitelistEntry> collection)
    {
        super(collection);
    }

    public WhitelistEntry findByVulnerabilityID(String vulnerabilityID)
    {
        for (WhitelistEntry entry : this)
        {
            if (entry.getVulnerabilityID().equalsIgnoreCase(vulnerabilityID)) return entry;
        }
        return null;
    }
}
