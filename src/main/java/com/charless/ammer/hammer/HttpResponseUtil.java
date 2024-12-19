package com.charless.ammer.hammer;

import com.charless.ammer.amber.HttpResponseBody;
import com.charless.ammer.amber.HttpStatusCode;

/**
 * 构造 HTTP 响应 (工具类)
 * { HttpStatusCode HttpResponseBody }
 *
 * @author charix
 * @version 1.0
 */
public class HttpResponseUtil {

    /**
     * 请求成功
     *
     * @return HTTP 响应体
     */
    public static HttpResponseBody<?> success() {
        return new HttpResponseBody<>(HttpStatusCode.SUCCESS);
    }

    /**
     * 请求成功并返回数据
     *
     * @param data 数据
     * @param <T>  数据类型
     * @return HTTP 响应体
     */
    public static <T> HttpResponseBody<T> success(T data) {
        return new HttpResponseBody<>(HttpStatusCode.SUCCESS, data);
    }

    /**
     * 系统错误, 请求失败
     *
     * @return HTTP 响应体
     */
    public static HttpResponseBody<?> fail() {
        return new HttpResponseBody<>(HttpStatusCode.SYSTEM_ERROR);
    }

    /**
     * 请求失败
     *
     * @param httpStatusCode 状态码 (错误描述)
     * @return HTTP 响应体
     */
    public static HttpResponseBody<?> fail(HttpStatusCode httpStatusCode) {
        return new HttpResponseBody<>(httpStatusCode);
    }

    /**
     * 请求失败
     *
     * @param httpStatusCode 状态码 (错误描述)
     * @param detail         详情
     * @return HTTP 响应体
     */
    public static HttpResponseBody<?> fail(HttpStatusCode httpStatusCode, String detail) {
        return new HttpResponseBody<>(httpStatusCode, detail);
    }

    /**
     * 请求失败
     *
     * @param code   状态码
     * @param msg    错误描述
     * @param detail 错误详情
     * @return HTTP 响应体
     */
    public static HttpResponseBody<?> fail(int code, String msg, String detail) {
        return new HttpResponseBody<>(code, msg, detail);
    }

}
