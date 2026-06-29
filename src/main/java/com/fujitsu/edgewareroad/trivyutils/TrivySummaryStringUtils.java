package com.fujitsu.edgewareroad.trivyutils;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.regex.Pattern;

import org.springframework.util.StringUtils;

public class TrivySummaryStringUtils {
    private static final Pattern whitespaceSplitter = Pattern.compile("\s+");
    private static final Pattern longWordSplitter = Pattern.compile("(?<!(^|[A-Z]))(?=[A-Z])|(?<!^)(?=[A-Z][a-z])|(?<!^)(?=[:\\-/.])");
    private static final int WORD_LEN_BEFORE_HYPHENATE = 18;
    private static final DateTimeFormatter dateFormatter = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM);

    public static String getShortArtefactNameWithTag(String artefactNameWithTag)
    {
        if (artefactNameWithTag == null) return null;

        int lastSlashIndex = artefactNameWithTag.lastIndexOf('/');
        if (lastSlashIndex >= 0 && lastSlashIndex < artefactNameWithTag.length() - 1)
        {
            return artefactNameWithTag.substring(lastSlashIndex + 1);
        }
        else
        {
            return artefactNameWithTag;
        }
    }

    public static String getHyphenated(String input)
    {
        if (input == null) return null;

        StringBuilder builder = new StringBuilder();
        boolean first = true;
        for (String word : whitespaceSplitter.split(input))
        {
            if (!first) builder.append(" ");
            first = false;
            if (word.length() < WORD_LEN_BEFORE_HYPHENATE)
            {
                builder.append(word);
            }
            else
            {
                // We need to be able to break this word anywhere after the max word length per line
                boolean firstInWord = true;
                for (String subWord : longWordSplitter.split(word))
                {
                    if (!firstInWord) builder.append((char)0x00AD);    // Silent hyphen
                    firstInWord = false;
                    if (subWord.length() < WORD_LEN_BEFORE_HYPHENATE)
                    {
                        builder.append(subWord);
                    }
                    else
                    {
                        // Well we have no choice but to split the subword in an ugly way.
                        builder.append(subWord.substring(0, WORD_LEN_BEFORE_HYPHENATE - 1));
                        subWord.substring(WORD_LEN_BEFORE_HYPHENATE - 1).chars().forEach(c -> {
                            builder.append((char)0x00AD);
                            builder.append((char)c);
                        });
                    }
                }
            }
        }

        return builder.toString();
    }

    public static String displayDate(LocalDate value)
    {
        return value != null ? value.format(dateFormatter) : "<no date specified>";
    }

    public static String displayTodaysDate()
    {
        return LocalDate.now().format(dateFormatter);
    }

    public static String displayDouble(Double value)
    {
        return String.format("%f", value);
    }

    public static String toUpperCamelCase(String input)
    {
        StringBuilder builder = new StringBuilder();
        for (String word : input.split("/s"))
        {
            builder.append(StringUtils.capitalize(word.toLowerCase()));
        }
        return builder.toString();
    }

    public static String textWithDefaultOnNullOrEmpty(String text, String defaultText)
    {
        return StringUtils.hasText(text) ? text : defaultText;
    }
}
