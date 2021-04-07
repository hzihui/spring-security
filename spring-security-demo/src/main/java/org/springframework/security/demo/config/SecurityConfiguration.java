package org.springframework.security.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author HZI.HUI
 * @since 2021/4/7
 */
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().cors()
				.and()
				.authorizeRequests().anyRequest().authenticated()
				.and()
				.formLogin()
				.loginProcessingUrl("/processingUrl")
				.successForwardUrl("/login/success")
				.failureForwardUrl("/login/failure");
	}
}
