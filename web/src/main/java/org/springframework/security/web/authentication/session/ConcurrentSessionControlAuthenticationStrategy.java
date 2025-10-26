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

package org.springframework.security.web.authentication.session;

import java.util.Comparator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.Assert;

/**
 * Strategy which handles concurrent session-control.
 *
 * <p>
 * When invoked following an authentication, it will check whether the user in question
 * should be allowed to proceed, by comparing the number of sessions they already have
 * active with the configured <tt>maximumSessions</tt> value. The {@link SessionRegistry}
 * is used as the source of data on authenticated users and session data.
 * </p>
 * <p>
 * If a user has reached the maximum number of permitted sessions, the behaviour depends
 * on the <tt>exceptionIfMaxExceeded</tt> property. The default behaviour is to expire any
 * sessions that exceed the maximum number of permitted sessions, starting with the least
 * recently used sessions. The expired sessions will be invalidated by the
 * {@link ConcurrentSessionFilter} if accessed again. If <tt>exceptionIfMaxExceeded</tt>
 * is set to <tt>true</tt>, however, the user will be prevented from starting a new
 * authenticated session.
 * </p>
 * <p>
 * This strategy can be injected into both the {@link SessionManagementFilter} and
 * instances of {@link AbstractAuthenticationProcessingFilter} (typically
 * {@link UsernamePasswordAuthenticationFilter}), but is typically combined with
 * {@link RegisterSessionAuthenticationStrategy} using
 * {@link CompositeSessionAuthenticationStrategy}.
 * </p>
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.2
 * @see CompositeSessionAuthenticationStrategy
 */
public class ConcurrentSessionControlAuthenticationStrategy
		implements MessageSourceAware, SessionAuthenticationStrategy {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private final SessionRegistry sessionRegistry;

	private boolean exceptionIfMaximumExceeded = false;

	private int maximumSessions = 1;

	/**
	 * @param sessionRegistry the session registry which should be updated when the
	 * authenticated session is changed.
	 */
	public ConcurrentSessionControlAuthenticationStrategy(SessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "The sessionRegistry cannot be null");
		this.sessionRegistry = sessionRegistry;
	}

	/**
	 * In addition to the steps from the superclass, the sessionRegistry will be updated
	 * with the new session information.
	 */
	@Override
	public void onAuthentication(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response) {
		// 获得这个用户最大允许的会话。其实这里就是取配的一个固定值，看起来传入了一个 authentication 实际上没有用。
		int allowedSessions = getMaximumSessionsForThisUser(authentication);

		// 如果是 -1，则不管
		if (allowedSessions == -1) {
			// We permit unlimited logins
			return;
		}

		// 从 Session 注册表，获取所有 Session (不包含过期的会话)
		List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(authentication.getPrincipal(), false);

		// 获取数量
		int sessionCount = sessions.size();

		// 如果当前数量小于 allowedSessions，即使再 + 1，也没达到最大值，所以没有关系
		if (sessionCount < allowedSessions) {
			// They haven't got too many login sessions running at present
			return;
		}

		// 如果已经达到最大值
		if (sessionCount == allowedSessions) {
			// 获取 SessionId 比对是不是已经存在了，可能使用相同的 SessionId 登录
			HttpSession session = request.getSession(false);
			if (session != null) {
				// Only permit it though if this request is associated with one of the
				// already registered sessions
				for (SessionInformation si : sessions) {
					if (si.getSessionId().equals(session.getId())) {
						return;
					}
				}
			}
			// If the session is null, a new one will be created by the parent class,
			// exceeding the allowed number
		}


		allowableSessionsExceeded(sessions, allowedSessions, this.sessionRegistry);
	}

	/**
	 * Method intended for use by subclasses to override the maximum number of sessions
	 * that are permitted for a particular authentication. The default implementation
	 * simply returns the <code>maximumSessions</code> value for the bean.
	 * @param authentication to determine the maximum sessions for
	 * @return either -1 meaning unlimited, or a positive integer to limit (never zero)
	 */
	protected int getMaximumSessionsForThisUser(Authentication authentication) {
		return this.maximumSessions;
	}

	/**
	 * Allows subclasses to customise behaviour when too many sessions are detected.
	 * @param sessions either <code>null</code> or all unexpired sessions associated with
	 * the principal
	 * @param allowableSessions the number of concurrent sessions the user is allowed to
	 * have
	 * @param registry an instance of the <code>SessionRegistry</code> for subclass use
	 *
	 */
	protected void allowableSessionsExceeded(List<SessionInformation> sessions, int allowableSessions,
			SessionRegistry registry) throws SessionAuthenticationException {
		// 如果 exceptionIfMaximumExceeded ，意味着达到最大会话数就会抛出异常，无法登录
		if (this.exceptionIfMaximumExceeded || (sessions == null)) {
			throw new SessionAuthenticationException(
					this.messages.getMessage("ConcurrentSessionControlAuthenticationStrategy.exceededAllowed",
							new Object[] { allowableSessions }, "Maximum sessions of {0} for this principal exceeded"));
		}
		// Determine least recently used sessions, and mark them for invalidation
		// 按照最后一次访问，排序，最后一个就是最新访问的。会话
		sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));

		// 溢出了多少个 Session
		int maximumSessionsExceededBy = sessions.size() - allowableSessions + 1;

		// 取出旧的几个，调用他们的过期方法
		// 思考一下：标记为过期，但是还没有注销这个会话，会话的注销在 ConcurrentSessionFilter
		List<SessionInformation> sessionsToBeExpired = sessions.subList(0, maximumSessionsExceededBy);
		for (SessionInformation session : sessionsToBeExpired) {
			session.expireNow();
		}
	}

	/**
	 * Sets the <tt>exceptionIfMaximumExceeded</tt> property, which determines whether the
	 * user should be prevented from opening more sessions than allowed. If set to
	 * <tt>true</tt>, a <tt>SessionAuthenticationException</tt> will be raised which means
	 * the user authenticating will be prevented from authenticating. if set to
	 * <tt>false</tt>, the user that has already authenticated will be forcibly logged
	 * out.
	 * @param exceptionIfMaximumExceeded defaults to <tt>false</tt>.
	 */
	public void setExceptionIfMaximumExceeded(boolean exceptionIfMaximumExceeded) {
		this.exceptionIfMaximumExceeded = exceptionIfMaximumExceeded;
	}

	/**
	 * Sets the <tt>maxSessions</tt> property. The default value is 1. Use -1 for
	 * unlimited sessions.
	 * @param maximumSessions the maximimum number of permitted sessions a user can have
	 * open simultaneously.
	 */
	public void setMaximumSessions(int maximumSessions) {
		Assert.isTrue(maximumSessions != 0,
				"MaximumLogins must be either -1 to allow unlimited logins, or a positive integer to specify a maximum");
		this.maximumSessions = maximumSessions;
	}

	/**
	 * Sets the {@link MessageSource} used for reporting errors back to the user when the
	 * user has exceeded the maximum number of authentications.
	 */
	@Override
	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "messageSource cannot be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}

}
