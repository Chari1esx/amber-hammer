package com.charless.ammer.amber;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

/**
 * HTTP 响应体
 * 状态码 + 描述 + 详情 + 数据
 * { lombok }
 *
 * @param <T> 数据类型
 * @author charix
 * @version 1.0
 */
@Data
@AllArgsConstructor
public class HttpResponseBody<T> implements Serializable {

    private final int code;
    private final String msg;
    private final String detail;
    private final T data;

    public HttpResponseBody(int code, String msg, String detail) {
        this(code, msg, detail, null);
    }

    public HttpResponseBody(HttpStatusCode httpStatusCode) {
        this(httpStatusCode.getCode(), httpStatusCode.getMsg(), null);
    }

    public HttpResponseBody(HttpStatusCode httpStatusCode, String detail) {
        this(httpStatusCode.getCode(), httpStatusCode.getMsg(), detail);
    }

    public HttpResponseBody(HttpStatusCode httpStatusCode, T data) {
        this(httpStatusCode.getCode(), httpStatusCode.getMsg(), null, data);
    }

}
