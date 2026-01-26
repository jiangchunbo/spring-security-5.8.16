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

package org.springframework.security.oauth2.server.resource.web;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.util.StringUtils;

/**
 * The default {@link BearerTokenResolver} implementation based on RFC 6750.
 * <p>
 * 默认的 BearerTokenResolver 实现，能够从 HttpServletRequest 中解析出 token
 * <p>
 * token 可能来自于 Authorization 或者 parameter
 *
 * @author Vedran Pavic
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-2" target="_blank">RFC 6750
 * Section 2: Authenticated Requests</a>
 * @since 5.1
 */
public final class DefaultBearerTokenResolver implements BearerTokenResolver {

	/**
	 * 这个正则表达式表示：必须以 Bearer 开头；将 token 捕获到 token 组里，并且支持大写字母、小写字母、数字、- . _ ~ + / 这些字符正好对应 base64 常见字符
	 */
	private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$",
			Pattern.CASE_INSENSITIVE);

	private boolean allowFormEncodedBodyParameter = false;

	private boolean allowUriQueryParameter = false;

	private String bearerTokenHeaderName = HttpHeaders.AUTHORIZATION;

	@Override
	public String resolve(final HttpServletRequest request) {
		// 校验并捕获 token 值 (没有 bearer 开头)
		final String authorizationHeaderToken = resolveFromAuthorizationHeader(request);

		// ps: 从 Servlet getParameter("access_token") 获取 token
		final String parameterToken = isParameterTokenSupportedForRequest(request)
				? resolveFromRequestParameters(request) : null;

		// 1. 优先使用 header 里面的 token，并且不能同时存在 parameter token
		if (authorizationHeaderToken != null) {
			if (parameterToken != null) {
				final BearerTokenError error = BearerTokenErrors
						.invalidRequest("Found multiple bearer tokens in the request");
				throw new OAuth2AuthenticationException(error);
			}
			return authorizationHeaderToken;
		}

		// 2. 当 header 不存在，而且允许使用 parameter 的 token，那么返回 token (不允许使用也不会报错)
		if (parameterToken != null && isParameterTokenEnabledForRequest(request)) {
			return parameterToken;
		}
		return null;
	}

	/**
	 * Set if transport of access token using form-encoded body parameter is supported.
	 * Defaults to {@code false}.
	 *
	 * @param allowFormEncodedBodyParameter if the form-encoded body parameter is
	 *                                      supported
	 */
	public void setAllowFormEncodedBodyParameter(boolean allowFormEncodedBodyParameter) {
		this.allowFormEncodedBodyParameter = allowFormEncodedBodyParameter;
	}

	/**
	 * Set if transport of access token using URI query parameter is supported. Defaults
	 * to {@code false}.
	 * <p>
	 * The spec recommends against using this mechanism for sending bearer tokens, and
	 * even goes as far as stating that it was only included for completeness.
	 *
	 * @param allowUriQueryParameter if the URI query parameter is supported
	 */
	public void setAllowUriQueryParameter(boolean allowUriQueryParameter) {
		this.allowUriQueryParameter = allowUriQueryParameter;
	}

	/**
	 * Set this value to configure what header is checked when resolving a Bearer Token.
	 * This value is defaulted to {@link HttpHeaders#AUTHORIZATION}.
	 * <p>
	 * This allows other headers to be used as the Bearer Token source such as
	 * {@link HttpHeaders#PROXY_AUTHORIZATION}
	 *
	 * @param bearerTokenHeaderName the header to check when retrieving the Bearer Token.
	 * @since 5.4
	 */
	public void setBearerTokenHeaderName(String bearerTokenHeaderName) {
		this.bearerTokenHeaderName = bearerTokenHeaderName;
	}

	private String resolveFromAuthorizationHeader(HttpServletRequest request) {
		// 获取 Authorization 头的值，并且期望以 bearer 开头
		String authorization = request.getHeader(this.bearerTokenHeaderName);
		if (!StringUtils.startsWithIgnoreCase(authorization, "bearer")) {
			return null;
		}

		// 使用 pattern 匹配 Authorization 的值 (既然开头一定是 bearer，那么就看后面的字符是否存在非法字符)
		Matcher matcher = authorizationPattern.matcher(authorization);
		if (!matcher.matches()) {
			BearerTokenError error = BearerTokenErrors.invalidToken("Bearer token is malformed");
			throw new OAuth2AuthenticationException(error);
		}

		// pattern 使用了命名捕获组，把 token 捕获到 "token" 组里，然后取出来
		return matcher.group("token");
	}

	private static String resolveFromRequestParameters(HttpServletRequest request) {
		String[] values = request.getParameterValues("access_token");
		if (values == null || values.length == 0) {
			return null;
		}
		if (values.length == 1) {
			return values[0];
		}
		BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
		throw new OAuth2AuthenticationException(error);
	}

	/**
	 * POST + application/x-www-form-urlencoded 或者 GET
	 */
	private boolean isParameterTokenSupportedForRequest(final HttpServletRequest request) {
		return (("POST".equals(request.getMethod())
				&& MediaType.APPLICATION_FORM_URLENCODED_VALUE.equals(request.getContentType()))
				|| "GET".equals(request.getMethod()));
	}

	private boolean isParameterTokenEnabledForRequest(final HttpServletRequest request) {
		return ((this.allowFormEncodedBodyParameter && "POST".equals(request.getMethod())
				&& MediaType.APPLICATION_FORM_URLENCODED_VALUE.equals(request.getContentType()))
				|| (this.allowUriQueryParameter && "GET".equals(request.getMethod())));
	}

}
