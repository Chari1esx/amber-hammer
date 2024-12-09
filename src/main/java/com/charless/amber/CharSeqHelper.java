package com.charless.amber;

/**
 * 字符序列 帮助类 -> 简化 字符序列 的使用
 */
public class CharSeqHelper {

    public static boolean isEmpty(String str) {
        return str == null || str.isEmpty();
    }

    public static boolean isBlankStr(String str) {
        if (isEmpty(str)) {
            return true;
        }
        for (int i = 0; i < str.length(); i++) {
            if (!CharHelper.isBlankChar(str.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
