/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.web.builders;

import java.io.Serializable;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.Assert;
import org.springframework.web.filter.CorsFilter;

/**
 * An internal use only {@link Comparator} that sorts the Security {@link Filter}
 * instances to ensure they are in the correct order.
 *
 * @author Rob Winch
 * @since 3.2
 */

@SuppressWarnings("serial")
final class FilterComparator implements Comparator<Filter>, Serializable {

	private static final int INITIAL_ORDER = 100;

	private static final int ORDER_STEP = 100;

	private final Map<String, Integer> filterToOrder = new HashMap<>();

	FilterComparator() {
		Step order = new Step(INITIAL_ORDER, ORDER_STEP);
		// 请求协议是否合法过滤器：https http
		put(ChannelProcessingFilter.class, order.next());
		order.next(); // gh-8105
		// 异步管理器 用于集成SecurityContext到Spring异步执行机制中的
		put(WebAsyncManagerIntegrationFilter.class, order.next());
		// 主要控制 SecurityContext 的在一次请求中的生命周期
		put(SecurityContextPersistenceFilter.class, order.next());
		// HeaderWriterFilter 用来给 http 响应添加一些 Header
		put(HeaderWriterFilter.class, order.next());
		// 跨域相关
		put(CorsFilter.class, order.next());
		// CSRF 相关
		put(CsrfFilter.class, order.next());
		// 退出登录相关
		put(LogoutFilter.class, order.next());
		// 需要依赖 spring-scurity-oauth2 相关的模块。该过滤器是处理 OAuth2 请求首选重定向相关逻辑的
		this.filterToOrder.put(
				"org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter",
				order.next());
		// 需要用到 Spring Security SAML 模块，这是一个基于 SMAL 的 SSO 单点登录请求认证过滤器。
		this.filterToOrder.put(
				"org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationRequestFilter",
				order.next());
		// X509 认证过滤器
		put(X509AuthenticationFilter.class, order.next());
		// 处理经过预先认证的身份验证请求的过滤器的基类，其中认证主体已经由外部系统进行了身份验证。 目的只是从传入请求中提取主体上的必要信息
		put(AbstractPreAuthenticatedProcessingFilter.class, order.next());
		// CAS 单点登录认证过滤器 。依赖 Spring Security CAS 模块
		this.filterToOrder.put("org.springframework.security.cas.web.CasAuthenticationFilter", order.next());
		// 需要依赖 spring-scurity-oauth2 相关的模块。 OAuth2 登录认证过滤器。处理通过 OAuth2进行认证登录的逻辑
		this.filterToOrder.put("org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter",
				order.next());
		// 这个需要用到 Spring Security SAML 模块，这是一个基于 SMAL 的 SSO 单点登录认证过滤器。
		this.filterToOrder.put(
				"org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter",
				order.next());
		// 认证请求提交的 username 和 password ，被封装成 token 进行一系列的认证，便是主要通过这个过滤器完成的，在表单认证的方法中，这是最最关键的过滤器
		put(UsernamePasswordAuthenticationFilter.class, order.next());
		order.next(); // gh-8105
		// 基于 OpenID 认证协议的认证过滤器
		this.filterToOrder.put("org.springframework.security.openid.OpenIDAuthenticationFilter", order.next());
		// 默认登录页面生成过滤器  /login
		put(DefaultLoginPageGeneratingFilter.class, order.next());
		// 默认登录退出页面生成过滤器  /logout
		put(DefaultLogoutPageGeneratingFilter.class, order.next());
		// 当前Session 状态过滤器
		put(ConcurrentSessionFilter.class, order.next());
		// 摘要认证过滤器
		put(DigestAuthenticationFilter.class, order.next());
		// 令牌认证过滤器
		this.filterToOrder.put(
				"org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter",
				order.next());
		/**
		 * 和 Digest 身份验证一样都是 Web 应用程序中流行的可选的身份验证机制 。
		 * BasicAuthenticationFilter 负责处理 HTTP 头中显示的基本身份验证凭据。
		 * 这个 Spring Security的 Spring Boot 自动配置默认是启用的
		 */
		put(BasicAuthenticationFilter.class, order.next());
		/**
		 * 用于用户认证成功后，重新恢复因为登录被打断的请求。当匿名访问一个需要授权的资源时。会跳转到
		 * 认证处理逻辑，此时请求被缓存。在认证逻辑处理完毕后，从缓存中获取最开始的资源请求进行再次请
		 * 求
		 */
		put(RequestCacheAwareFilter.class, order.next());
		/**
		 * 用来 实现 j2ee 中 Servlet Api 一些接口方法, 比如 getRemoteUser 方法、 isUserInRole 方法，
		 * 在使用 Spring Security 时其实就是通过这个过滤器来实现的。
		 * SecurityContextHolderAwareRequestFilter 通过 HttpSecurity.servletApi() 及相关方法引
		 * 入其配置对象 ServletApiConfigurer 来进行配置。
		 */
		put(SecurityContextHolderAwareRequestFilter.class, order.next());
		/**
		 * 适用于 JAAS （ Java 认证授权服务）。 如果 SecurityContextHolder 中拥有的
		 * Authentication 是一个 JaasAuthenticationToken ，那么该 JaasApiIntegrationFilter 将使
		 * 用包含在 JaasAuthenticationToken 中的 Subject 继续执行 FilterChain 。
		 */
		put(JaasApiIntegrationFilter.class, order.next());
		// 处理 记住我 功能的过滤器
		put(RememberMeAuthenticationFilter.class, order.next());
		// 匿名认证过滤器对于 Spring Security 来说，所有对资源的访问都是有 Authentication 的。对
		//于无需登录（ UsernamePasswordAuthenticationFilter ）直接可以访问的资源，会授予其匿名用
		//户身份。
		put(AnonymousAuthenticationFilter.class, order.next());
		// 需要依赖 spring-scurity-oauth2 相关的模块。 OAuth2 登录认证过滤器。处理通过 OAuth2 授权码授权顾虑
		this.filterToOrder.put("org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter",
				order.next());
		// Session 管理器过滤器，内部维护了一个 SessionAuthenticationStrategy 用于管理 Session
		put(SessionManagementFilter.class, order.next());
		// 主要来传输异常事件
		put(ExceptionTranslationFilter.class, order.next());
		// 这个过滤器决定了访问特定路径应该具备的权限，访问的用户的角色，权限是什么？访问的路径需要什么样的角色和权限？这些判断和处理都是由该类进行的。
		put(FilterSecurityInterceptor.class, order.next());
		// 授权认证过滤器
		put(AuthorizationFilter.class, order.next());
		// SwitchUserFilter 是用来做账户切换的。默认的切换账号的 url 为 /login/impersonate ，默认注
		//销切换账号的 url 为 /logout/impersonate ，默认的账号参数为 username 。
		put(SwitchUserFilter.class, order.next());
	}

	@Override
	public int compare(Filter lhs, Filter rhs) {
		Integer left = getOrder(lhs.getClass());
		Integer right = getOrder(rhs.getClass());
		return left - right;
	}

	/**
	 * Determines if a particular {@link Filter} is registered to be sorted
	 * @param filter
	 * @return
	 */
	boolean isRegistered(Class<? extends Filter> filter) {
		return getOrder(filter) != null;
	}

	/**
	 * Registers a {@link Filter} to exist after a particular {@link Filter} that is
	 * already registered.
	 * @param filter the {@link Filter} to register
	 * @param afterFilter the {@link Filter} that is already registered and that
	 * {@code filter} should be placed after.
	 */
	void registerAfter(Class<? extends Filter> filter, Class<? extends Filter> afterFilter) {
		Integer position = getOrder(afterFilter);
		Assert.notNull(position, () -> "Cannot register after unregistered Filter " + afterFilter);
		put(filter, position + 1);
	}

	/**
	 * Registers a {@link Filter} to exist at a particular {@link Filter} position
	 * @param filter the {@link Filter} to register
	 * @param atFilter the {@link Filter} that is already registered and that
	 * {@code filter} should be placed at.
	 */
	void registerAt(Class<? extends Filter> filter, Class<? extends Filter> atFilter) {
		Integer position = getOrder(atFilter);
		Assert.notNull(position, () -> "Cannot register after unregistered Filter " + atFilter);
		put(filter, position);
	}

	/**
	 * Registers a {@link Filter} to exist before a particular {@link Filter} that is
	 * already registered.
	 * @param filter the {@link Filter} to register
	 * @param beforeFilter the {@link Filter} that is already registered and that
	 * {@code filter} should be placed before.
	 */
	void registerBefore(Class<? extends Filter> filter, Class<? extends Filter> beforeFilter) {
		Integer position = getOrder(beforeFilter);
		Assert.notNull(position, () -> "Cannot register after unregistered Filter " + beforeFilter);
		put(filter, position - 1);
	}

	private void put(Class<? extends Filter> filter, int position) {
		String className = filter.getName();
		this.filterToOrder.put(className, position);
	}

	/**
	 * Gets the order of a particular {@link Filter} class taking into consideration
	 * superclasses.
	 * @param clazz the {@link Filter} class to determine the sort order
	 * @return the sort order or null if not defined
	 */
	private Integer getOrder(Class<?> clazz) {
		while (clazz != null) {
			Integer result = this.filterToOrder.get(clazz.getName());
			if (result != null) {
				return result;
			}
			clazz = clazz.getSuperclass();
		}
		return null;
	}

	private static class Step {

		private int value;

		private final int stepSize;

		Step(int initialValue, int stepSize) {
			this.value = initialValue;
			this.stepSize = stepSize;
		}

		int next() {
			int value = this.value;
			this.value += this.stepSize;
			return value;
		}

	}

}
