/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import javax.servlet.http.HttpSession;

import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.DelegatingLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Adds logout support. Other {@link SecurityConfigurer} instances may invoke
 * {@link #addLogoutHandler(LogoutHandler)} in the {@link #init(HttpSecurityBuilder)}
 * phase.
 *
 * <h2>Security Filters</h2>
 * <p>
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link LogoutFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 * <p>
 * No shared Objects are created
 *
 * <h2>Shared Objects Used</h2>
 * <p>
 * No shared objects are used.
 *
 * @author Rob Winch
 * @author Onur Kagan Ozcan
 * @see RememberMeConfigurer
 * @since 3.2
 */
public final class LogoutConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<LogoutConfigurer<H>, H> {

	/**
	 * 一系列处理器，用于处理注销时的逻辑
	 */
	private List<LogoutHandler> logoutHandlers = new ArrayList<>();

	/**
	 * 一种特定的 LogoutHandler
	 */
	private SecurityContextLogoutHandler contextLogoutHandler = new SecurityContextLogoutHandler();

	private String logoutSuccessUrl = "/login?logout";

	/**
	 * 注销成功处理器。可能自己设置，也可能使用一个默认的(在获取时)。
	 */
	private LogoutSuccessHandler logoutSuccessHandler;

	private String logoutUrl = "/logout";

	private RequestMatcher logoutRequestMatcher;

	/**
	 * 是否允许所有用户(包括已认证和未认证) 访问
	 */
	private boolean permitAll;

	/**
	 * 是否自定义了 logout success 的方式
	 */
	private boolean customLogoutSuccess;

	private LinkedHashMap<RequestMatcher, LogoutSuccessHandler> defaultLogoutSuccessHandlerMappings = new LinkedHashMap<>();

	/**
	 * Creates a new instance
	 *
	 * @see HttpSecurity#logout()
	 */
	public LogoutConfigurer() {
	}

	/**
	 * Adds a {@link LogoutHandler}. {@link SecurityContextLogoutHandler} and
	 * {@link LogoutSuccessEventPublishingLogoutHandler} are added as last
	 * {@link LogoutHandler} instances by default.
	 *
	 * @param logoutHandler the {@link LogoutHandler} to add
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> addLogoutHandler(LogoutHandler logoutHandler) {
		Assert.notNull(logoutHandler, "logoutHandler cannot be null");
		this.logoutHandlers.add(logoutHandler);
		return this;
	}

	/**
	 * Specifies if {@link SecurityContextLogoutHandler} should clear the
	 * {@link Authentication} at the time of logout.
	 *
	 * @param clearAuthentication true {@link SecurityContextLogoutHandler} should clear
	 *                            the {@link Authentication} (default), or false otherwise.
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> clearAuthentication(boolean clearAuthentication) {
		this.contextLogoutHandler.setClearAuthentication(clearAuthentication);
		return this;
	}

	/**
	 * Configures {@link SecurityContextLogoutHandler} to invalidate the
	 * {@link HttpSession} at the time of logout.
	 *
	 * @param invalidateHttpSession true if the {@link HttpSession} should be invalidated
	 *                              (default), or false otherwise.
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> invalidateHttpSession(boolean invalidateHttpSession) {
		this.contextLogoutHandler.setInvalidateHttpSession(invalidateHttpSession);
		return this;
	}

	/**
	 * The URL that triggers log out to occur (default is "/logout"). If CSRF protection
	 * is enabled (default), then the request must also be a POST. This means that by
	 * default POST "/logout" is required to trigger a log out. If CSRF protection is
	 * disabled, then any HTTP method is allowed.
	 *
	 * <p>
	 * It is considered best practice to use an HTTP POST on any action that changes state
	 * (i.e. log out) to protect against
	 * <a href="https://en.wikipedia.org/wiki/Cross-site_request_forgery">CSRF
	 * attacks</a>. If you really want to use an HTTP GET, you can use
	 * <code>logoutRequestMatcher(new AntPathRequestMatcher(logoutUrl, "GET"));</code>
	 * </p>
	 *
	 * @param logoutUrl the URL that will invoke logout.
	 * @return the {@link LogoutConfigurer} for further customization
	 * @see #logoutRequestMatcher(RequestMatcher)
	 * @see HttpSecurity#csrf()
	 */
	public LogoutConfigurer<H> logoutUrl(String logoutUrl) {
		this.logoutRequestMatcher = null;
		this.logoutUrl = logoutUrl;
		return this;
	}

	/**
	 * The RequestMatcher that triggers log out to occur. In most circumstances users will
	 * use {@link #logoutUrl(String)} which helps enforce good practices.
	 *
	 * @param logoutRequestMatcher the RequestMatcher used to determine if logout should
	 *                             occur.
	 * @return the {@link LogoutConfigurer} for further customization
	 * @see #logoutUrl(String)
	 */
	public LogoutConfigurer<H> logoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
		this.logoutRequestMatcher = logoutRequestMatcher;
		return this;
	}

	/**
	 * The URL to redirect to after logout has occurred. The default is "/login?logout".
	 * This is a shortcut for invoking {@link #logoutSuccessHandler(LogoutSuccessHandler)}
	 * with a {@link SimpleUrlLogoutSuccessHandler}.
	 *
	 * @param logoutSuccessUrl the URL to redirect to after logout occurred
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> logoutSuccessUrl(String logoutSuccessUrl) {
		this.customLogoutSuccess = true; // 自定义 logoutSuccessUrl
		this.logoutSuccessUrl = logoutSuccessUrl;
		return this;
	}

	/**
	 * A shortcut for {@link #permitAll(boolean)} with <code>true</code> as an argument.
	 *
	 * @return the {@link LogoutConfigurer} for further customizations
	 */
	public LogoutConfigurer<H> permitAll() {
		return permitAll(true);
	}

	/**
	 * Allows specifying the names of cookies to be removed on logout success. This is a
	 * shortcut to easily invoke {@link #addLogoutHandler(LogoutHandler)} with a
	 * {@link CookieClearingLogoutHandler}.
	 *
	 * @param cookieNamesToClear the names of cookies to be removed on logout success.
	 * @return the {@link LogoutConfigurer} for further customization
	 */
	public LogoutConfigurer<H> deleteCookies(String... cookieNamesToClear) {
		return addLogoutHandler(new CookieClearingLogoutHandler(cookieNamesToClear));
	}

	/**
	 * Sets the {@link LogoutSuccessHandler} to use. If this is specified,
	 * {@link #logoutSuccessUrl(String)} is ignored.
	 *
	 * @param logoutSuccessHandler the {@link LogoutSuccessHandler} to use after a user
	 *                             has been logged out.
	 * @return the {@link LogoutConfigurer} for further customizations
	 */
	public LogoutConfigurer<H> logoutSuccessHandler(LogoutSuccessHandler logoutSuccessHandler) {
		this.logoutSuccessUrl = null;
		this.customLogoutSuccess = true; // 自定义 logoutSuccessHandler
		this.logoutSuccessHandler = logoutSuccessHandler;
		return this;
	}

	/**
	 * Sets a default {@link LogoutSuccessHandler} to be used which prefers being invoked
	 * for the provided {@link RequestMatcher}. If no {@link LogoutSuccessHandler} is
	 * specified a {@link SimpleUrlLogoutSuccessHandler} will be used. If any default
	 * {@link LogoutSuccessHandler} instances are configured, then a
	 * {@link DelegatingLogoutSuccessHandler} will be used that defaults to a
	 * {@link SimpleUrlLogoutSuccessHandler}.
	 *
	 * @param handler          the {@link LogoutSuccessHandler} to use
	 * @param preferredMatcher the {@link RequestMatcher} for this default
	 *                         {@link LogoutSuccessHandler}
	 * @return the {@link LogoutConfigurer} for further customizations
	 */
	public LogoutConfigurer<H> defaultLogoutSuccessHandlerFor(LogoutSuccessHandler handler,
			RequestMatcher preferredMatcher) {
		Assert.notNull(handler, "handler cannot be null");
		Assert.notNull(preferredMatcher, "preferredMatcher cannot be null");
		this.defaultLogoutSuccessHandlerMappings.put(preferredMatcher, handler);
		return this;
	}

	/**
	 * Grants access to the {@link #logoutSuccessUrl(String)} and the
	 * {@link #logoutUrl(String)} for every user.
	 *
	 * @param permitAll if true grants access, else nothing is done
	 * @return the {@link LogoutConfigurer} for further customization.
	 */
	public LogoutConfigurer<H> permitAll(boolean permitAll) {
		this.permitAll = permitAll;
		return this;
	}

	/**
	 * Gets the {@link LogoutSuccessHandler} if not null, otherwise creates a new
	 * {@link SimpleUrlLogoutSuccessHandler} using the {@link #logoutSuccessUrl(String)}.
	 *
	 * @return the {@link LogoutSuccessHandler} to use
	 */
	public LogoutSuccessHandler getLogoutSuccessHandler() {
		// 获取注销成功处理器，如果没有配置，那么使用一个默认的
		LogoutSuccessHandler handler = this.logoutSuccessHandler;
		if (handler == null) {
			handler = createDefaultSuccessHandler();
			this.logoutSuccessHandler = handler;
		}
		return handler;
	}

	private LogoutSuccessHandler createDefaultSuccessHandler() {
		// 默认使用重定向 logoutSuccessHandler
		SimpleUrlLogoutSuccessHandler urlLogoutHandler = new SimpleUrlLogoutSuccessHandler();
		urlLogoutHandler.setDefaultTargetUrl(this.logoutSuccessUrl);

		// 若
		if (this.defaultLogoutSuccessHandlerMappings.isEmpty()) {
			return urlLogoutHandler;
		}
		DelegatingLogoutSuccessHandler successHandler = new DelegatingLogoutSuccessHandler(
				this.defaultLogoutSuccessHandlerMappings);
		successHandler.setDefaultLogoutSuccessHandler(urlLogoutHandler);
		return successHandler;
	}

	@Override
	public void init(H http) {
		// 总结下来就是，默认情况下，又是前后端分离开发，下面基本不会有作用

		// permitAll 是否允许任何人访问 url
		// 默认是 false，所以基本不会走进去
		if (this.permitAll) {
			// 任何人都可以访问 /logout?logout
			PermitAllSupport.permitAll(http, this.logoutSuccessUrl);
			// 任何人都可以访问 /logout
			PermitAllSupport.permitAll(http, this.getLogoutRequestMatcher(http));
		}

		// 生成登录页面，但是如果你自定义了 logout success 方式就没用
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter != null && !isCustomLogoutSuccess()) {
			loginPageGeneratingFilter.setLogoutSuccessUrl(getLogoutSuccessUrl());
		}
	}

	@Override
	public void configure(H http) throws Exception {
		// 创建 logout
		LogoutFilter logoutFilter = createLogoutFilter(http);
		http.addFilter(logoutFilter);
	}

	/**
	 * Returns true if the logout success has been customized via
	 * {@link #logoutSuccessUrl(String)} or
	 * {@link #logoutSuccessHandler(LogoutSuccessHandler)}.
	 *
	 * @return true if logout success handling has been customized, else false
	 */
	boolean isCustomLogoutSuccess() {
		return this.customLogoutSuccess;
	}

	/**
	 * Gets the logoutSuccesUrl or null if a
	 * {@link #logoutSuccessHandler(LogoutSuccessHandler)} was configured.
	 *
	 * @return the logoutSuccessUrl
	 */
	private String getLogoutSuccessUrl() {
		return this.logoutSuccessUrl;
	}

	/**
	 * Gets the {@link LogoutHandler} instances that will be used.
	 *
	 * @return the {@link LogoutHandler} instances. Cannot be null.
	 */
	public List<LogoutHandler> getLogoutHandlers() {
		return this.logoutHandlers;
	}

	/**
	 * Creates the {@link LogoutFilter} using the {@link LogoutHandler} instances, the
	 * {@link #logoutSuccessHandler(LogoutSuccessHandler)} and the
	 * {@link #logoutUrl(String)}.
	 *
	 * @param http the builder to use
	 * @return the {@link LogoutFilter} to use.
	 */
	private LogoutFilter createLogoutFilter(H http) {
		// 配置 logout handler
		this.contextLogoutHandler.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		this.contextLogoutHandler.setSecurityContextRepository(getSecurityContextRepository(http));

		// 添加到 logoutHandlers
		this.logoutHandlers.add(this.contextLogoutHandler);

		// 发布事件
		this.logoutHandlers.add(postProcess(new LogoutSuccessEventPublishingLogoutHandler()));

		LogoutHandler[] handlers = this.logoutHandlers.toArray(new LogoutHandler[0]);

		// 不管怎么样，这一切的触发还是通过 LogoutFilter
		LogoutFilter result = new LogoutFilter(getLogoutSuccessHandler(), handlers);
		result.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		result.setLogoutRequestMatcher(getLogoutRequestMatcher(http));
		result = postProcess(result);
		return result;
	}

	private SecurityContextRepository getSecurityContextRepository(H http) {
		SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
		if (securityContextRepository == null) {
			securityContextRepository = new HttpSessionSecurityContextRepository();
		}
		return securityContextRepository;
	}

	private RequestMatcher getLogoutRequestMatcher(H http) {
		if (this.logoutRequestMatcher != null) {
			return this.logoutRequestMatcher;
		}
		this.logoutRequestMatcher = createLogoutRequestMatcher(http);
		return this.logoutRequestMatcher;
	}

	/**
	 * 创建一个 logout 的请求匹配器
	 * <p>
	 * 可以参考这种思想，我们也可以起名为 createXyzRequestMatcher
	 */
	@SuppressWarnings("unchecked")
	private RequestMatcher createLogoutRequestMatcher(H http) {
		// 默认情况下 POST 请求方法的 /logout 一定是可以的
		RequestMatcher post = createLogoutRequestMatcher("POST");
		if (http.getConfigurer(CsrfConfigurer.class) != null) {
			return post;
		}

		// 如果程序没有配置 CSRF，那么也允许 GET PUT DELETE

		RequestMatcher get = createLogoutRequestMatcher("GET");
		RequestMatcher put = createLogoutRequestMatcher("PUT");
		RequestMatcher delete = createLogoutRequestMatcher("DELETE");
		return new OrRequestMatcher(get, post, put, delete);
	}

	private RequestMatcher createLogoutRequestMatcher(String httpMethod) {
		return new AntPathRequestMatcher(this.logoutUrl, httpMethod);
	}

}
