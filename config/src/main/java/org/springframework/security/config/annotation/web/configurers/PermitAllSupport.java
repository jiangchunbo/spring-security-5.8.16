/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractConfigAttributeRequestMatcherRegistry.UrlMapping;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Configures non-null URL's to grant access to every URL
 *
 * @author Rob Winch
 * @since 3.2
 */
final class PermitAllSupport {

	private PermitAllSupport() {
	}

	static void permitAll(HttpSecurityBuilder<? extends HttpSecurityBuilder<?>> http, String... urls) {
		for (String url : urls) {
			if (url != null) {
				// 构建一个精准匹配器，甚至连 query 都可以匹配
				permitAll(http, new ExactUrlRequestMatcher(url));
			}
		}
	}

	@SuppressWarnings("unchecked")
	static void permitAll(HttpSecurityBuilder<? extends HttpSecurityBuilder<?>> http,
			RequestMatcher... requestMatchers) {
		// ExpressionUrlAuthorizationConfigurer 似乎计划淘汰
		ExpressionUrlAuthorizationConfigurer<?> configurer = http
			.getConfigurer(ExpressionUrlAuthorizationConfigurer.class);
		// AuthorizeHttpRequestsConfigurer 更为现代的方式
		AuthorizeHttpRequestsConfigurer<?> httpConfigurer = http.getConfigurer(AuthorizeHttpRequestsConfigurer.class);

		// 两者取其一
		boolean oneConfigurerPresent = configurer == null ^ httpConfigurer == null;
		Assert.state(oneConfigurerPresent,
				"permitAll only works with either HttpSecurity.authorizeRequests() or HttpSecurity.authorizeHttpRequests(). "
						+ "Please define one or the other but not both.");

		for (RequestMatcher matcher : requestMatchers) {
			if (matcher != null) {
				// 将 permitAll 添加到 ExpressionUrlAuthorizationConfigurer OR AuthorizeHttpRequestsConfigurer
				if (configurer != null) {
					configurer.getRegistry()
						.addMapping(0, new UrlMapping(matcher,
								SecurityConfig.createList(ExpressionUrlAuthorizationConfigurer.permitAll)));
				}
				else {
					httpConfigurer.addFirst(matcher, AuthorizeHttpRequestsConfigurer.permitAllAuthorizationManager);
				}
			}
		}
	}

	/**
	 * 私有类，只是用于精确匹配，不支持 /** 等
	 */
	private static final class ExactUrlRequestMatcher implements RequestMatcher {

		/**
		 * 更应该是一个 final 不可变字符串
		 */
		private String processUrl;

		private ExactUrlRequestMatcher(String processUrl) {
			this.processUrl = processUrl;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			// 请求不带主机名和端口的 URI，例如 /logout
			String uri = request.getRequestURI();

			// 获取查询字符串，如果存在，则拼接到 uri 后面
			String query = request.getQueryString();
			if (query != null) {
				uri += "?" + query;
			}

			// 如果没有配置 context path，直接比较 uri 和 processUrl
			if ("".equals(request.getContextPath())) {
				return uri.equals(this.processUrl);
			}

			// 前缀增加 context path 再比较
			return uri.equals(request.getContextPath() + this.processUrl);
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			sb.append("ExactUrl [processUrl='").append(this.processUrl).append("']");
			return sb.toString();
		}

	}

}
