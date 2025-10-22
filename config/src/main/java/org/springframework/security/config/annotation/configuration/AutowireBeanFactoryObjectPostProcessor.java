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

	// 由于可能需要后处理的对象类型很多，因此该后处理器必须支持 Object 类型。

	// 协助调用这些对象的方法，但是这些对象始终不是 bean

	private final Log logger = LogFactory.getLog(getClass());

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
		T result = null;
		try {
			result = (T) this.autowireBeanFactory.initializeBean(object, object.toString());
		} catch (RuntimeException ex) {
			Class<?> type = object.getClass();
			throw new RuntimeException("Could not postProcess " + object + " of type " + type, ex);
		}

		// 调用 autowireBean 方法
		this.autowireBeanFactory.autowireBean(object);

		// 添加到 disposableBeans 在这里销毁
		if (result instanceof DisposableBean) {
			this.disposableBeans.add((DisposableBean) result);
		}

		// 添加到 smartSingletons，等单例 bean 都创建好，调用
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
