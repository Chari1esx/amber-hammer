package com.charless.hammer;

import com.charless.amber.DsGenerator;
import com.charless.amber.model.ResponseCode;
import com.charless.amber.model.ResponseEntity;

/**
 * 响应 工具类 -> 快速构造响应体
 * { DsGenerator ResponseCode ResponseEntity }
 */
public class ResponseUtil {

    /**
     * 请求成功
     *
     * @return 响应体
     */
    public static ResponseEntity<?> success() {
        return DsGenerator.generateResponseEntity(ResponseCode.SUCCESS);
    }

    /**
     * 请求成功并返回数据
     *
     * @param data 响应数据
     * @param <T>  响应数据的类型
     * @return 响应体
     */
    public static <T> ResponseEntity<T> success(T data) {
        return DsGenerator.generateResponseEntity(ResponseCode.SUCCESS, data);
    }

    /**
     * 系统错误, 请求失败
     *
     * @return 响应体
     */
    public static ResponseEntity<?> fail() {
        return DsGenerator.generateResponseEntity(ResponseCode.SYSTEM_ERROR);
    }

    /**
     * 请求失败
     *
     * @param responseCode 错误码
     * @return 响应体
     */
    public static ResponseEntity<?> fail(ResponseCode responseCode) {
        return DsGenerator.generateResponseEntity(responseCode);
    }

    /**
     * 请求失败
     *
     * @param responseCode 错误码
     * @param detail       错误码详情
     * @return 响应体
     */
    public static ResponseEntity<?> fail(ResponseCode responseCode, String detail) {
        return DsGenerator.generateResponseEntity(responseCode, detail);
    }

    /**
     * 请求失败
     *
     * @param code   错误码
     * @param msg    错误码简讯
     * @param detail 错误码详情
     * @return 响应体
     */
    public static ResponseEntity<?> fail(int code, String msg, String detail) {
        return DsGenerator.generateResponseEntity(code, msg, detail);
    }
}
