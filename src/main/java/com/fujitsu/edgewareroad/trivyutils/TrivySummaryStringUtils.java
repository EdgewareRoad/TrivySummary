package com.fujitsu.edgewareroad.trivyutils;

import java.util.regex.Pattern;

public class TrivySummaryStringUtils {
    private final Pattern whitespaceSplitter = Pattern.compile("\s+");
    private final Pattern longWordSplitter = Pattern.compile("(?<!(^|[A-Z]))(?=[A-Z])|(?<!^)(?=[A-Z][a-z])|(?<!^)(?=[:\\-/.])");
    private final int WORD_LEN_BEFORE_HYPHENATE = 18;

    public String getHyphenated(String input)
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
}
