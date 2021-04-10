/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.context.request.async;

import java.io.IOException;
import java.util.concurrent.Callable;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.context.request.async.WebAsyncManager;
import org.springframework.web.context.request.async.WebAsyncUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Provides integration between the {@link SecurityContext} and Spring Web's
 * {@link WebAsyncManager} by using the
 * {@link SecurityContextCallableProcessingInterceptor#beforeConcurrentHandling(org.springframework.web.context.request.NativeWebRequest, Callable)}
 * to populate the {@link SecurityContext} on the {@link Callable}.
 *
 * @author Rob Winch
 * @see SecurityContextCallableProcessingInterceptor
 *
 * WebAsyncManagerIntegrationFilter 用于集成SecurityContext到Spring异步执行机制中的
 * WebAsyncManager。用来处理异步请求的安全上下文。具体逻辑为：
 * 1. 从请求属性上获取所绑定的 WebAsyncManager ，如果尚未绑定，先做绑定。
 * 2. 从 asyncManager 中获取 key 为 CALLABLE_INTERCEPTOR_KEY 的安全上下文多线程处理器
 * SecurityContextCallableProcessingInterceptor , 如果获取到的为 null ，
 * 新建一个 SecurityContextCallableProcessingInterceptor 并绑定
 * CALLABLE_INTERCEPTOR_KEY 注册到 asyncManager 中
 *
 *
 *
 */
public final class WebAsyncManagerIntegrationFilter extends OncePerRequestFilter {

	private static final Object CALLABLE_INTERCEPTOR_KEY = new Object();

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		WebAsyncManager asyncManager = WebAsyncUtils.getAsyncManager(request);
		SecurityContextCallableProcessingInterceptor securityProcessingInterceptor = (SecurityContextCallableProcessingInterceptor) asyncManager
				.getCallableInterceptor(CALLABLE_INTERCEPTOR_KEY);
		if (securityProcessingInterceptor == null) {
			asyncManager.registerCallableInterceptor(CALLABLE_INTERCEPTOR_KEY,
					new SecurityContextCallableProcessingInterceptor());
		}
		filterChain.doFilter(request, response);
	}

}
