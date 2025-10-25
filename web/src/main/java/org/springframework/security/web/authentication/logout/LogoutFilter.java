/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.authentication.logout;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Logs a principal out.
 * <p>
 * Polls a series of {@link LogoutHandler}s. The handlers should be specified in the order
 * they are required. Generally you will want to call logout handlers
 * <code>TokenBasedRememberMeServices</code> and <code>SecurityContextLogoutHandler</code>
 * (in that order).
 * <p>
 * After logout, a redirect will be performed to the URL determined by either the
 * configured <tt>LogoutSuccessHandler</tt> or the <tt>logoutSuccessUrl</tt>, depending on
 * which constructor was used.
 *
 * @author Ben Alex
 * @author Eddú Meléndez
 */
public class LogoutFilter extends GenericFilterBean {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private RequestMatcher logoutRequestMatcher;

	/**
	 * 类型你直接写 CompositeLogoutHandler 算了
	 */
	private final LogoutHandler handler;

	/**
	 * 注销成功处理器，还有注销处理器。处理器还不少~~。请注意区别
	 */
	private final LogoutSuccessHandler logoutSuccessHandler;

	/**
	 * Constructor which takes a <tt>LogoutSuccessHandler</tt> instance to determine the
	 * target destination after logging out. The list of <tt>LogoutHandler</tt>s are
	 * intended to perform the actual logout functionality (such as clearing the security
	 * context, invalidating the session, etc.).
	 *
	 * @param logoutSuccessHandler 使用自定义的方式处理 logout 请求
	 * @param handlers             多个 logoutHandler，最终会被组合到 CompositeLogoutHandler
	 */
	public LogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler... handlers) {
		this.handler = new CompositeLogoutHandler(handlers);
		Assert.notNull(logoutSuccessHandler, "logoutSuccessHandler cannot be null");
		this.logoutSuccessHandler = logoutSuccessHandler;
		setFilterProcessesUrl("/logout");
	}

	/**
	 * @param handlers @param handlers 多个 logoutHandler，最终会被组合到 CompositeLogoutHandler
	 */
	public LogoutFilter(String logoutSuccessUrl, LogoutHandler... handlers) {
		this.handler = new CompositeLogoutHandler(handlers);
		Assert.isTrue(!StringUtils.hasLength(logoutSuccessUrl) || UrlUtils.isValidRedirectUrl(logoutSuccessUrl),
				() -> logoutSuccessUrl + " isn't a valid redirect URL");
		SimpleUrlLogoutSuccessHandler urlLogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
		if (StringUtils.hasText(logoutSuccessUrl)) {
			urlLogoutSuccessHandler.setDefaultTargetUrl(logoutSuccessUrl);
		}
		this.logoutSuccessHandler = urlLogoutSuccessHandler;
		setFilterProcessesUrl("/logout");
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// 检查是不是 logout 请求
		if (requiresLogout(request, response)) {
			// 从 context 拿 authentication
			Authentication auth = this.securityContextHolderStrategy.getContext().getAuthentication();
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Logging out [%s]", auth));
			}

			// 双 handler 调用

			// 调用 logout handler 进行注销。其中包括了 Session 的无效化
			this.handler.logout(request, response, auth);

			// logout success 处理器
			this.logoutSuccessHandler.onLogoutSuccess(request, response, auth);
			return;
		}
		chain.doFilter(request, response);
	}

	/**
	 * Allow subclasses to modify when a logout should take place.
	 *
	 * @param request  the request
	 * @param response the response
	 * @return <code>true</code> if logout should occur, <code>false</code> otherwise
	 */
	protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
		if (this.logoutRequestMatcher.matches(request)) {
			return true;
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Did not match request to %s", this.logoutRequestMatcher));
		}
		return false;
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	public void setLogoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
		Assert.notNull(logoutRequestMatcher, "logoutRequestMatcher cannot be null");
		this.logoutRequestMatcher = logoutRequestMatcher;
	}

	public void setFilterProcessesUrl(String filterProcessesUrl) {
		this.logoutRequestMatcher = new AntPathRequestMatcher(filterProcessesUrl);
	}

}
