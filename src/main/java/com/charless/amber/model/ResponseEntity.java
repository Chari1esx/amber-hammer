package com.charless.amber.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

/**
 * 响应体
 * 响应码 + 响应码简讯 + 响应码详情 + 响应数据
 * { lombok }
 *
 * @param <T> 响应数据的类型
 */
@Data
@AllArgsConstructor
public class ResponseEntity<T> implements Serializable {

    private final int code;
    private final String msg;
    private final String detail;
    private final T data;

    public ResponseEntity(int code, String msg, String detail) {
        this(code, msg, detail, null);
    }

    public ResponseEntity(ResponseCode responseCode) {
        this(responseCode.getCode(), responseCode.getMsg(), null);
    }

    public ResponseEntity(ResponseCode responseCode, String detail) {
        this(responseCode.getCode(), responseCode.getMsg(), detail);
    }

    public ResponseEntity(ResponseCode responseCode, T data) {
        this(responseCode.getCode(), responseCode.getMsg(), null, data);
    }
}
