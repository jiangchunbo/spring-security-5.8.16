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

import org.springframework.beans.factory.Aware;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;

/**
 * Allows initialization of Objects. Typically this is used to call the {@link Aware}
 * methods, {@link InitializingBean#afterPropertiesSet()}, and ensure that
 * {@link DisposableBean#destroy()} has been invoked.
 * <p>
 * <strong>允许对对象进行初始化。通常用于调用 Aware 系列方法、InitializingBean#afterPropertiesSet()，
 * 确保 DisposableBean#destroy() 方法能够被触发 (这里就是处理对象的生命周期回调)
 * </strong>
 *
 * @param <T> the bound of the types of Objects this {@link ObjectPostProcessor} supports.
 * @author Rob Winch
 * @since 3.2
 */
public interface ObjectPostProcessor<T> {

	/**
	 * Initialize the object possibly returning a modified instance that should be used
	 * instead.
	 * <p>
	 * <strong>初始化对象，并可能返回一个修改后的实例以替换原始实例使用。
	 * </strong>
	 *
	 * @param object the object to initialize
	 * @return the initialized version of the object
	 */
	<O extends T> O postProcess(O object);

}
