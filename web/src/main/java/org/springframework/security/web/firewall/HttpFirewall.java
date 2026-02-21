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

package org.springframework.security.web.firewall;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Interface which can be used to reject potentially dangerous requests and/or wrap them
 * to control their behaviour.
 * <p>
 * <strong>可用于拒绝潜在危险请求，和/或对请求进行包装以控制其行为的接口。</strong>
 * <p>
 * The implementation is injected into the {@code FilterChainProxy} and will be invoked
 * before sending any request through the filter chain. It can also provide a response
 * wrapper if the response behaviour should also be restricted.
 * <p>
 * <strong>该实现会注入到 {@code FilterChainProxy} 中，并在请求进入过滤器链之前调用。</strong>
 * <strong>如果还需要限制响应行为，它也可以提供一个响应包装器。</strong>
 *
 * @author Luke Taylor
 */
public interface HttpFirewall {

	/**
	 * Provides the request object which will be passed through the filter chain.
	 * <p><strong>提供将传递给过滤器链的请求对象。</strong>
	 *
	 * @throws RequestRejectedException if the request should be rejected immediately
	 *                                  <p><strong>如果请求应立即被拒绝。</strong>
	 */
	FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException;

	/**
	 * Provides the response which will be passed through the filter chain.
	 * <p><strong>提供将传递给过滤器链的响应对象。</strong>
	 *
	 * @param response the original response
	 *                 <strong>原始响应对象。</strong>
	 * @return either the original response or a replacement/wrapper
	 * <p><strong>返回原始响应，或其替代/包装响应。</strong>
	 */
	HttpServletResponse getFirewalledResponse(HttpServletResponse response);

}
