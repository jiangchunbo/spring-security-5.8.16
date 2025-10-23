/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.csrf;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Rob Winch
 * @author Steve Riesenberg
 * @since 5.8
 */
final class RepositoryDeferredCsrfToken implements DeferredCsrfToken {

	private final CsrfTokenRepository csrfTokenRepository;

	private final HttpServletRequest request;

	private final HttpServletResponse response;

	private CsrfToken csrfToken;

	private boolean missingToken;

	RepositoryDeferredCsrfToken(CsrfTokenRepository csrfTokenRepository, HttpServletRequest request,
			HttpServletResponse response) {
		this.csrfTokenRepository = csrfTokenRepository;
		this.request = request;
		this.response = response;
	}

	@Override
	public CsrfToken get() {
		init();
		return this.csrfToken;
	}

	@Override
	public boolean isGenerated() {
		init();
		return this.missingToken;
	}

	/**
	 * 得需要获取的时候再 init
	 */
	private void init() {
		// 初始化完毕
		if (this.csrfToken != null) {
			return;
		}

		// 加载 csrf token，其实就是从某个地方获取一下，可能还没创建
		this.csrfToken = this.csrfTokenRepository.loadToken(this.request);

		// 如果没有获取到，就生成
		this.missingToken = (this.csrfToken == null);
		if (this.missingToken) {
			this.csrfToken = this.csrfTokenRepository.generateToken(this.request);
			this.csrfTokenRepository.saveToken(this.csrfToken, this.request, this.response);
		}
	}

}
