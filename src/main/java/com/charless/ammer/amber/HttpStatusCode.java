package com.charless.ammer.amber;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * HTTP 状态码 (枚举)
 * 状态码 + 描述
 * { lombok }
 *
 * @author charix
 * @version 1.0
 */
@Getter
@AllArgsConstructor
public enum HttpStatusCode {

    SUCCESS(20000, "请求成功"),
    PARAM_ERROR(40000, "请求参数错误"),
    NOT_LOGIN(40100, "用户未登陆"),
    NOT_AUTH(40101, "用户无权限"),
    NOT_ALLOW(40102, "用户被封禁"),
    NOT_EXIST(40103, "用户不存在"),
    FORBIDDEN(40300, "资源禁止访问"),
    NOT_FOUND(40400, "资源不存在"),
    SYSTEM_ERROR(50000, "系统错误");

    private final int code;
    private final String msg;
    
}
