package com.fujitsu.edgewareroad.nativeutils;

import java.io.File;
import sun.awt.FontConfiguration;

import com.oracle.svm.core.annotate.Alias;
import com.oracle.svm.core.annotate.Substitute;
import com.oracle.svm.core.annotate.TargetClass;

@TargetClass(FontConfiguration.class)
public final class Target_sun_awt_FontConfiguration {

    @Alias
    private File fontConfigFile;
    @Alias
    private boolean foundOsSpecificFile;
    @Alias
    private String javaLib;
    
    @Substitute
    private void findFontConfigFile() {

        String javaHome = System.getProperty("java.home");
        if (javaHome == null) {
          foundOsSpecificFile = false;
          fontConfigFile = null;
          return;
        }
        foundOsSpecificFile = true;
        javaLib = javaHome + File.separator + "lib";
        String javaConfFonts = javaHome +
                               File.separator + "conf" +
                               File.separator + "fonts";
        String userConfigFile = System.getProperty("sun.awt.fontconfig");
        if (userConfigFile != null) {
            fontConfigFile = new File(userConfigFile);
        } else {
            fontConfigFile = findFontConfigFile(javaConfFonts);
            if (fontConfigFile == null) {
                fontConfigFile = findFontConfigFile(javaLib);
            }
        }
    }

    @Alias
    private File findFontConfigFile(String dir) {
        return null;
    }
}
