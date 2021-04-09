package org.springframework.security.demo.service;

import org.springframework.security.demo.enums.LoginTypeEnum;

import javax.servlet.ServletRequest;

/**
 * @author HZI.HUI
 * @since 2021/4/8
 */
public interface LoginPostProcessor {

	/**
	 * 获取登录类型
	 * @return
	 */
	LoginTypeEnum getLoginTypeEnum();

	/**
	 * 获取用户名
	 * @param request
	 * @return
	 */
	String obtainUsername(ServletRequest request);


	/**
	 * 获取密码
	 * @param request
	 * @return
	 */
	String obtainPassword(ServletRequest request);
}
