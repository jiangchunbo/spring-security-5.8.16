/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.config.annotation;

/**
 * Allows for configuring a {@link SecurityBuilder}. All {@link SecurityConfigurer} first
 * have their {@link #init(SecurityBuilder)} method invoked. After all
 * {@link #init(SecurityBuilder)} methods have been invoked, each
 * {@link #configure(SecurityBuilder)} method is invoked.
 *
 * <p>允许配置 {@link SecurityBuilder}。
 * 所有的 {@link SecurityConfigurer} 都先调用它们的 init 方法。
 * 在所有 init 方法调用之后，在调用 configure 方法。
 *
 * <p>
 * 这个接口提供了两个方法 init、configure，并且这两个方法都提供了一个 B 参数，类型时 SecurityBuilder，
 * 其实，这个接口就是用来对 SecurityBuilder 进行配置的，包括 init 和 configure
 *
 * @param <O> The object being built by the {@link SecurityBuilder} B
 *            <p>被 B 构建出来的对象
 * @param <B> The {@link SecurityBuilder} that builds objects of type O. This is also the
 *            {@link SecurityBuilder} that is being configured.
 *            <p>SecurityBuilder 的类型
 * @author Rob Winch
 * @see AbstractConfiguredSecurityBuilder
 */
public interface SecurityConfigurer<O, B extends SecurityBuilder<O>> {

	/**
	 * Initialize the {@link SecurityBuilder}. Here only shared state should be created
	 * and modified, but not properties on the {@link SecurityBuilder} used for building
	 * the object. This ensures that the {@link #configure(SecurityBuilder)} method uses
	 * the correct shared objects when building. Configurers should be applied here.
	 * <p>
	 * 初始化 SecurityBuilder
	 *
	 * @param builder SecurityBuilder
	 * @throws Exception 异常
	 */
	void init(B builder) throws Exception;

	/**
	 * Configure the {@link SecurityBuilder} by setting the necessary properties on the
	 * {@link SecurityBuilder}.
	 * <p>
	 * 配置 SecurityBuilder
	 *
	 * @param builder SecurityBuilder
	 * @throws Exception 异常
	 */
	void configure(B builder) throws Exception;

}
