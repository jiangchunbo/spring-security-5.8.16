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

package org.springframework.security.config.annotation.web;

import javax.servlet.Filter;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Allows customization to the {@link WebSecurity}. In most instances users will use
 * {@link EnableWebSecurity} and create a {@link Configuration} that exposes a
 * {@link SecurityFilterChain} bean. This will automatically be applied to the
 * {@link WebSecurity} by the {@link EnableWebSecurity} annotation.
 * <p><strong>允许对 {@link WebSecurity} 进行自定义配置。</strong>
 * <strong>在大多数场景下，用户会使用 {@link EnableWebSecurity}，并创建一个暴露</strong>
 * <strong>{@link SecurityFilterChain} Bean 的 {@link Configuration}。</strong>
 * <strong>该配置会通过 {@link EnableWebSecurity} 注解自动应用到 {@link WebSecurity}。</strong>
 * <p>
 *
 * @param <T> the type of {@link SecurityBuilder} used to build the security filter
 *            <strong>用于构建安全过滤器的 {@link SecurityBuilder} 类型。</strong>
 * @author Rob Winch
 * @see SecurityFilterChain
 * @since 3.2
 */
public interface WebSecurityConfigurer<T extends SecurityBuilder<Filter>> extends SecurityConfigurer<Filter, T> {

	// 这个类设计出来用于表示实现类能够 build 出一个用于 Web 安全的 Filter

	// 或者，也可以认为专门就是为了 WebSecurity 这个 builder 设计的

	// WebSecurityConfigurerAdapter 进一步固定了泛型参数 T 为 WebSecurity

	// 因此这个接口大概率是为了 WebSecurityConfigurerAdapter (现已经不推荐)

}
