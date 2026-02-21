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

package org.springframework.security.web;

import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

/**
 * Defines a {@code SecurityFilterChain} (security filter chain) which is capable
 * of being matched against an {@code HttpServletRequest} in order to decide whether it
 * applies to that request.
 * <p>
 * <strong>定义一条 {@code SecurityFilterChain}（安全过滤器链）：
 * 它会先和 {@code HttpServletRequest} 做匹配，再决定这条链是否该“接管”当前请求。</strong>
 * <p>
 * Used to configure a {@code FilterChainProxy}.
 * <p>
 * <strong>这个接口是配置 {@code FilterChainProxy} 的核心拼装单元。</strong>
 *
 * @author Luke Taylor
 * @since 3.1
 */
public interface SecurityFilterChain {

	/**
	 * Determines whether this chain should be applied to the request.
	 * <p>
	 * <strong>判断当前请求是否命中本链；命中则由这条过滤器链继续处理。</strong>
	 *
	 * @param request the request to test
	 * @return {@code true} if this chain applies
	 */
	boolean matches(HttpServletRequest request);

	/**
	 * <strong>Returns the filters that belong to this chain.</strong>
	 * <p>
	 * <strong>返回这条链上按顺序执行的过滤器列表。</strong>
	 *
	 * @return the filters in this chain
	 */
	List<Filter> getFilters();

}
