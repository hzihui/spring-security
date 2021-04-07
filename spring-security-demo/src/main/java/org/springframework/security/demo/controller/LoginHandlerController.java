package org.springframework.security.demo.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * spring security 认证登录后处理
 * @author HZI.HUI
 * @since 2021/4/7
 */
@RestController
@RequestMapping("/login")
public class LoginHandlerController {


	/**
	 * 表单登录成功后跳转于此
	 * @return
	 */
	@PostMapping("/success")
	public Object loginSuccess(){
		Object Object = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		return Object;
	}


	/**
	 * 表单登录失败跳转于此
	 * @return
	 */
	@PostMapping("/failure")
	public String loginFailure(){
		return "小老弟登录失败";
	}



}
