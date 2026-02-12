/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.config.annotation.configuration;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.Aware;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.util.Assert;

/**
 * Allows registering Objects to participate with an {@link AutowireCapableBeanFactory}'s
 * post processing of {@link Aware} methods, {@link InitializingBean#afterPropertiesSet()}
 * , and {@link DisposableBean#destroy()}.
 * <p>
 * 允许正在注册的对象，参与 BeanFactory 的后置处理 Aware 方法，afterProperties 方法，以及 destroy 方法
 *
 * @author Rob Winch
 * @since 3.2
 */
final class AutowireBeanFactoryObjectPostProcessor
		implements ObjectPostProcessor<Object>, DisposableBean, SmartInitializingSingleton {

	private final Log logger = LogFactory.getLog(getClass());

	/* BeanFactory */
	private final AutowireCapableBeanFactory autowireBeanFactory;

	private final List<DisposableBean> disposableBeans = new ArrayList<>();

	private final List<SmartInitializingSingleton> smartSingletons = new ArrayList<>();

	AutowireBeanFactoryObjectPostProcessor(AutowireCapableBeanFactory autowireBeanFactory) {
		Assert.notNull(autowireBeanFactory, "autowireBeanFactory cannot be null");
		this.autowireBeanFactory = autowireBeanFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T> T postProcess(T object) {
		if (object == null) {
			return null;
		}

		// 调用 initializeBean 方法
		// 如类注释所说，调用 Aware 方法
		T result = null;
		try {
			result = (T) this.autowireBeanFactory.initializeBean(object, object.toString());
		} catch (RuntimeException ex) {
			Class<?> type = object.getClass();
			throw new RuntimeException("Could not postProcess " + object + " of type " + type, ex);
		}

		// 调用 autowireBean 方法
		// 内部调用 populateBean 方法
		this.autowireBeanFactory.autowireBean(object);

		// 添加到 disposableBeans
		// 因为该 bean 本身实现了 DisposableBean，它只是把这些对象收集起来
		// 当它自己调用 destroy 时，再依次调用这些 bean 的 destroy
		if (result instanceof DisposableBean) {
			this.disposableBeans.add((DisposableBean) result);
		}

		// 添加到 smartSingletons
		// 因为该 bean 本身就是 SmartInitializingSingleton，他只是把这些对象收集起来
		// 当它自己调用 afterSingletonsInstantiated 时，再依次调用这些 bean 的 afterSingletonsInstantiated
		if (result instanceof SmartInitializingSingleton) {
			this.smartSingletons.add((SmartInitializingSingleton) result);
		}
		return result;
	}

	@Override
	public void afterSingletonsInstantiated() {
		for (SmartInitializingSingleton singleton : this.smartSingletons) {
			singleton.afterSingletonsInstantiated();
		}
	}

	@Override
	public void destroy() {
		for (DisposableBean disposable : this.disposableBeans) {
			try {
				disposable.destroy();
			} catch (Exception ex) {
				this.logger.error(ex);
			}
		}
	}

}
