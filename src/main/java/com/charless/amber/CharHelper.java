package com.charless.amber;

public class CharHelper {

    public static boolean isBlankChar(char ch) {
        return Character.isWhitespace(ch) || Character.isSpaceChar(ch);
    }
}
