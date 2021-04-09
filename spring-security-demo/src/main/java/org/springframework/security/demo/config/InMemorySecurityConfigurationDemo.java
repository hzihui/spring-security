package org.springframework.security.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.demo.filter.PreLoginFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author HZI.HUI
 * @since 2021/4/7
 */
@Configuration
public class InMemorySecurityConfigurationDemo extends WebSecurityConfigurerAdapter {

	/**
	 * 安全过滤器
	 * @param http
	 * @throws Exception
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().cors()
				.and()
				.authorizeRequests().anyRequest().authenticated()
				.and()
				.formLogin()
				.loginProcessingUrl("/processingUrl")
				.successForwardUrl("/login/success")
				.failureForwardUrl("/login/failure")
				.and()
				.addFilterBefore(
						new PreLoginFilter("/processingUrl",null),
						UsernamePasswordAuthenticationFilter.class);
	}


	/**
	 * 认证管理器
	 * @param auth
	 * @throws Exception
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// 当withUser 未设置roles 时报错  nested exception is java.lang.IllegalArgumentException: Cannot pass a null GrantedAuthority collection
		auth.inMemoryAuthentication()
				.withUser("hzihui")
				.password(new BCryptPasswordEncoder().encode("123456"))
				.roles("admin");
	}


	/**
	 *
	 * 自定义 AuthenticationManagerBuilder 需注入 PasswordEncoder，否则会报异常
	 * There is no PasswordEncoder mapped for the id "null"
	 * @return
	 */
	@Bean
	public static PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
}
