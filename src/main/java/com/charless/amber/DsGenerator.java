package com.charless.amber;

import com.charless.amber.model.ResponseCode;
import com.charless.amber.model.ResponseEntity;

import java.util.HashMap;
import java.util.Map;

/**
 * 通用数据结构 生成器 -> 消除 new 关键字
 * { ResponseCode ResponseEntity }
 */
public class DsGenerator {

    /**
     * 生成 HashMap
     *
     * @return HashMap
     */
    public static Map<String, Object> generateHashMap() {
        return new HashMap<>();
    }

    /**
     * 生成 响应体
     *
     * @param responseCode 响应码
     * @return 响应体
     */
    public static ResponseEntity<?> generateResponseEntity(ResponseCode responseCode) {
        return new ResponseEntity<>(responseCode);
    }

    /**
     * 生成 响应体
     *
     * @param responseCode 响应码
     * @param data         响应数据
     * @param <T>          响应数据的类型
     * @return 响应体
     */
    public static <T> ResponseEntity<T> generateResponseEntity(ResponseCode responseCode, T data) {
        return new ResponseEntity<>(responseCode, data);
    }

    /**
     * 生成 响应体
     *
     * @param responseCode 响应码
     * @param detail       响应码详情
     * @return 响应体
     */
    public static ResponseEntity<?> generateResponseEntity(ResponseCode responseCode, String detail) {
        return new ResponseEntity<>(responseCode, detail);
    }

    /**
     * 生成 响应体
     *
     * @param code   响应码
     * @param msg    响应码简讯
     * @param detail 响应码详情
     * @return 响应体
     */
    public static ResponseEntity<?> generateResponseEntity(int code, String msg, String detail) {
        return new ResponseEntity<>(code, msg, detail);
    }
}
