/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.method.configuration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.AdviceModeImportSelector;
import org.springframework.context.annotation.AutoProxyRegistrar;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.lang.NonNull;

/**
 * Dynamically determines which imports to include using the {@link EnableMethodSecurity}
 * annotation.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 */
final class MethodSecuritySelector implements ImportSelector {

	private final ImportSelector autoProxy = new AutoProxyRegistrarSelector();

	@Override
	public String[] selectImports(@NonNull AnnotationMetadata importMetadata) {
		// 触发这个 Selector 的类上面必须有 @EnableMethodSecurity
		// 也就是必须配合使用
		if (!importMetadata.hasAnnotation(EnableMethodSecurity.class.getName())) {
			return new String[0];
		}

		//
		EnableMethodSecurity annotation = importMetadata.getAnnotations().get(EnableMethodSecurity.class).synthesize();
		List<String> imports = new ArrayList<>(Arrays.asList(this.autoProxy.selectImports(importMetadata)));

		// 这个是默认开启的
		if (annotation.prePostEnabled()) {
			imports.add(PrePostMethodSecurityConfiguration.class.getName());
		}

		// 这个默认关闭
		if (annotation.securedEnabled()) {
			imports.add(SecuredMethodSecurityConfiguration.class.getName());
		}

		// 这个默认关闭
		if (annotation.jsr250Enabled()) {
			imports.add(Jsr250MethodSecurityConfiguration.class.getName());
		}
		return imports.toArray(new String[0]);
	}

	private static final class AutoProxyRegistrarSelector extends AdviceModeImportSelector<EnableMethodSecurity> {

		private static final String[] IMPORTS = new String[] { AutoProxyRegistrar.class.getName(),
				MethodSecurityAdvisorRegistrar.class.getName() };

		private static final String[] ASPECTJ_IMPORTS = new String[] {
				MethodSecurityAspectJAutoProxyRegistrar.class.getName() };

		@Override
		protected String[] selectImports(@NonNull AdviceMode adviceMode) {
			if (adviceMode == AdviceMode.PROXY) {
				return IMPORTS;
			}
			if (adviceMode == AdviceMode.ASPECTJ) {
				return ASPECTJ_IMPORTS;
			}
			throw new IllegalStateException("AdviceMode '" + adviceMode + "' is not supported");
		}

	}

}
