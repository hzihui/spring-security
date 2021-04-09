package org.springframework.security.demo.enums;

/**
 * 自定义登录类型枚举
 *
 * @author HZI.HUI
 * @since 2021/4/8
 */

public enum LoginTypeEnum {

	/** 原始登录方式. */
	FORM,

	/** Json 提交. */
	JSON,

	/** 验证码. */

	CAPTCHA;
}
