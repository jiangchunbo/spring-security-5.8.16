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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.util.Assert;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * <p>
 * A base {@link SecurityBuilder} that allows {@link SecurityConfigurer} to be applied to
 * it. This makes modifying the {@link SecurityBuilder} a strategy that can be customized
 * and broken up into a number of {@link SecurityConfigurer} objects that have more
 * specific goals than that of the {@link SecurityBuilder}.
 * </p>
 * <p>
 * 一个基础的 {@link SecurityBuilder}，支持向其中应用多个 {@link SecurityConfigurer}。
 * 通过这种方式，修改 {@link SecurityBuilder} 的策略可以被拆分，并封装到若干具备更明确职责的 {@link SecurityConfigurer} 中，
 * 而不必全部堆砌在 {@link SecurityBuilder} 自身
 *
 * <p>
 * For example, a {@link SecurityBuilder} may build an {@link DelegatingFilterProxy}, but
 * a {@link SecurityConfigurer} might populate the {@link SecurityBuilder} with the
 * filters necessary for session management, form based login, authorization, etc.
 * </p>
 * <p>
 * 例如，某个 {@link SecurityBuilder} 可能负责构建 {@link DelegatingFilterProxy}，
 * 而不同的 {@link SecurityConfigurer} 则可以向该 {@link SecurityBuilder} 中
 * 注入会话管理、表单登录、授权等所需的过滤器。
 *
 * @param <O> The object that this builder returns
 *            <p> 构建出来的东西
 * @param <B> The type of this builder (that is returned by the base class)
 *            <p> 本构建器类型，也就是自身类型。这个类可能是用于给子类一些链式调用使用的
 * @author Rob Winch
 * @see WebSecurity
 */
public abstract class AbstractConfiguredSecurityBuilder<O, B extends SecurityBuilder<O>>
		extends AbstractSecurityBuilder<O> {

	// 整个构建两步走 init + configure + build

	private final Log logger = LogFactory.getLog(getClass());

	/**
	 * 核心的成员变量，{@code Class -> List<SecurityConfigurer<O, B>>>}
	 *
	 * @see AbstractConfiguredSecurityBuilder#allowConfigurersOfSameType
	 */
	private final LinkedHashMap<Class<? extends SecurityConfigurer<O, B>>, List<SecurityConfigurer<O, B>>> configurers = new LinkedHashMap<>();

	/**
	 * init 过程中添加的配置器
	 */
	private final List<SecurityConfigurer<O, B>> configurersAddedInInitializing = new ArrayList<>();

	private final Map<Class<?>, Object> sharedObjects = new HashMap<>();

	/**
	 * 是否允许配置相同类型的 configurer
	 */
	private final boolean allowConfigurersOfSameType;

	private BuildState buildState = BuildState.UNBUILT;

	private ObjectPostProcessor<Object> objectPostProcessor;

	/**
	 * Creates a new instance with the provided {@link ObjectPostProcessor}. This post
	 * processor must support Object since there are many types of objects that may be
	 * post processed.
	 * <p>
	 * 使用所提供的 ObjectPostProcessor 创建一个新的实例。由于可能需要后处理的对象类型很多，因此该后处理器必须支持 Object 类型。
	 *
	 * @param objectPostProcessor the {@link ObjectPostProcessor} to use
	 */
	protected AbstractConfiguredSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
		this(objectPostProcessor, false);
	}

	/**
	 * Creates a new instance with the provided {@link ObjectPostProcessor}. This post
	 * processor must support Object since there are many types of objects that may be
	 * post processed.
	 *
	 * @param objectPostProcessor        the {@link ObjectPostProcessor} to use
	 * @param allowConfigurersOfSameType if true, will not override other
	 *                                   {@link SecurityConfigurer}'s when performing apply
	 */
	protected AbstractConfiguredSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor,
			boolean allowConfigurersOfSameType) {
		Assert.notNull(objectPostProcessor, "objectPostProcessor cannot be null");
		this.objectPostProcessor = objectPostProcessor;
		this.allowConfigurersOfSameType = allowConfigurersOfSameType;
	}

	/**
	 * Similar to {@link #build()} and {@link #getObject()} but checks the state to
	 * determine if {@link #build()} needs to be called first.
	 *
	 * @return the result of {@link #build()} or {@link #getObject()}. If an error occurs
	 * while building, returns null.
	 */
	public O getOrBuild() {
		if (!isUnbuilt()) {
			return getObject();
		}
		try {
			return build();
		} catch (Exception ex) {
			this.logger.debug("Failed to perform build. Returning null", ex);
			return null;
		}
	}

	/**
	 * Applies a {@link SecurityConfigurerAdapter} to this {@link SecurityBuilder} and
	 * invokes {@link SecurityConfigurerAdapter#setBuilder(SecurityBuilder)}.
	 *
	 * @param configurer
	 * @return the {@link SecurityConfigurerAdapter} for further customizations
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurerAdapter<O, B>> C apply(C configurer) throws Exception {
		// 添加 objectPostProcessor 只是为了能够给这些 configurer 对象添加 bean factory 的后置处理支持
		configurer.addObjectPostProcessor(this.objectPostProcessor);

		configurer.setBuilder((B) this);

		// 添加到内部维护的 configurer 中
		add(configurer);
		return configurer;
	}

	/**
	 * Applies a {@link SecurityConfigurer} to this {@link SecurityBuilder} overriding any
	 * {@link SecurityConfigurer} of the exact same class. Note that object hierarchies
	 * are not considered.
	 *
	 * @param configurer
	 * @return the {@link SecurityConfigurerAdapter} for further customizations
	 * @throws Exception
	 */
	public <C extends SecurityConfigurer<O, B>> C apply(C configurer) throws Exception {
		add(configurer); // 把 configurer 添加到 builder 中
		return configurer;
	}

	/**
	 * Sets an object that is shared by multiple {@link SecurityConfigurer}.
	 *
	 * @param sharedType the Class to key the shared object by.
	 * @param object     the Object to store
	 */
	@SuppressWarnings("unchecked")
	public <C> void setSharedObject(Class<C> sharedType, C object) {
		this.sharedObjects.put(sharedType, object);
	}

	/**
	 * Gets a shared Object. Note that object heirarchies are not considered.
	 *
	 * @param sharedType the type of the shared Object
	 * @return the shared Object or null if it is not found
	 */
	@SuppressWarnings("unchecked")
	public <C> C getSharedObject(Class<C> sharedType) {
		return (C) this.sharedObjects.get(sharedType);
	}

	/**
	 * Gets the shared objects
	 *
	 * @return the shared Objects
	 */
	public Map<Class<?>, Object> getSharedObjects() {
		return Collections.unmodifiableMap(this.sharedObjects);
	}

	/**
	 * Adds {@link SecurityConfigurer} ensuring that it is allowed and invoking
	 * {@link SecurityConfigurer#init(SecurityBuilder)} immediately if necessary.
	 *
	 * @param configurer the {@link SecurityConfigurer} to add
	 */
	@SuppressWarnings("unchecked")
	private <C extends SecurityConfigurer<O, B>> void add(C configurer) {
		Assert.notNull(configurer, "configurer cannot be null");
		Class<? extends SecurityConfigurer<O, B>> clazz = (Class<? extends SecurityConfigurer<O, B>>) configurer
				.getClass();

		synchronized (this.configurers) {
			// 如果已经执行过 build 了，那么说明已经构建结束，此时再添加 configurer 会报错
			if (this.buildState.isConfigured()) {
				throw new IllegalStateException("Cannot apply " + configurer + " to already built object");
			}
			List<SecurityConfigurer<O, B>> configs = null;

			// 如果允许配置相同类型的 configurer，那么获取之前的数组(?)
			if (this.allowConfigurersOfSameType) {
				configs = this.configurers.get(clazz);
			}

			// 添加到数组中(也有可能是初始化)
			configs = (configs != null) ? configs : new ArrayList<>(1);
			configs.add(configurer);

			this.configurers.put(clazz, configs);

			// 如果当前正在初始化，但是调用了 add configurer 方法，就添加到一个特殊的集合
			if (this.buildState.isInitializing()) {
				this.configurersAddedInInitializing.add(configurer);
			}
		}
	}

	/**
	 * Gets all the {@link SecurityConfigurer} instances by its class name or an empty
	 * List if not found. Note that object hierarchies are not considered.
	 *
	 * @param clazz the {@link SecurityConfigurer} class to look for
	 * @return a list of {@link SecurityConfigurer}s for further customization
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> List<C> getConfigurers(Class<C> clazz) {
		List<C> configs = (List<C>) this.configurers.get(clazz);
		if (configs == null) {
			return new ArrayList<>();
		}
		return new ArrayList<>(configs);
	}

	/**
	 * Removes all the {@link SecurityConfigurer} instances by its class name or an empty
	 * List if not found. Note that object hierarchies are not considered.
	 *
	 * @param clazz the {@link SecurityConfigurer} class to look for
	 * @return a list of {@link SecurityConfigurer}s for further customization
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> List<C> removeConfigurers(Class<C> clazz) {
		List<C> configs = (List<C>) this.configurers.remove(clazz);
		if (configs == null) {
			return new ArrayList<>();
		}
		removeFromConfigurersAddedInInitializing(clazz);
		return new ArrayList<>(configs);
	}

	/**
	 * Gets the {@link SecurityConfigurer} by its class name or <code>null</code> if not
	 * found. Note that object hierarchies are not considered.
	 * <p>
	 * 获取唯一的 Configurer，如果获取多个，则需要立即抛出异常。
	 *
	 * @param clazz
	 * @return the {@link SecurityConfigurer} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> C getConfigurer(Class<C> clazz) {
		List<SecurityConfigurer<O, B>> configs = this.configurers.get(clazz);
		if (configs == null) {
			return null;
		}
		Assert.state(configs.size() == 1,
				() -> "Only one configurer expected for type " + clazz + ", but got " + configs);
		return (C) configs.get(0);
	}

	/**
	 * Removes and returns the {@link SecurityConfigurer} by its class name or
	 * <code>null</code> if not found. Note that object hierarchies are not considered.
	 *
	 * @param clazz
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public <C extends SecurityConfigurer<O, B>> C removeConfigurer(Class<C> clazz) {
		List<SecurityConfigurer<O, B>> configs = this.configurers.remove(clazz);
		if (configs == null) {
			return null;
		}

		// configurers 没有 configurersAddedInInitializing 一定也没有
		// configurers 有 configurersAddedInInitializing 可能有
		removeFromConfigurersAddedInInitializing(clazz);
		Assert.state(configs.size() == 1,
				() -> "Only one configurer expected for type " + clazz + ", but got " + configs);
		return (C) configs.get(0);
	}

	private <C extends SecurityConfigurer<O, B>> void removeFromConfigurersAddedInInitializing(Class<C> clazz) {
		this.configurersAddedInInitializing.removeIf(clazz::isInstance);
	}

	/**
	 * Specifies the {@link ObjectPostProcessor} to use.
	 *
	 * @param objectPostProcessor the {@link ObjectPostProcessor} to use. Cannot be null
	 * @return the {@link SecurityBuilder} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public B objectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		Assert.notNull(objectPostProcessor, "objectPostProcessor cannot be null");
		this.objectPostProcessor = objectPostProcessor;
		return (B) this;
	}

	/**
	 * Performs post processing of an object. The default is to delegate to the
	 * {@link ObjectPostProcessor}.
	 *
	 * @param object the Object to post process
	 * @return the possibly modified Object to use
	 */
	protected <P> P postProcess(P object) {
		return this.objectPostProcessor.postProcess(object);
	}

	/**
	 * Executes the build using the {@link SecurityConfigurer}'s that have been applied
	 * using the following steps:
	 *
	 * <ul>
	 * <li>Invokes {@link #beforeInit()} for any subclass to hook into</li>
	 * <li>Invokes {@link SecurityConfigurer#init(SecurityBuilder)} for any
	 * {@link SecurityConfigurer} that was applied to this builder.</li>
	 * <li>Invokes {@link #beforeConfigure()} for any subclass to hook into</li>
	 * <li>Invokes {@link #performBuild()} which actually builds the Object</li>
	 * </ul>
	 */
	@Override
	protected final O doBuild() throws Exception {
		synchronized (this.configurers) {
			// 设置状态是 initializing，然后执行 beforeInit、init
			this.buildState = BuildState.INITIALIZING;
			beforeInit(); // 我没有看到任何子类实现
			init(); // private 方法，固定逻辑

			// 设置状态是 configuring，然后执行 beforeConfigure、configure
			this.buildState = BuildState.CONFIGURING;
			beforeConfigure();
			configure(); // private 方法，固定逻辑

			// 设置状态时 building，然后执行 performBuild
			this.buildState = BuildState.BUILDING;
			O result = performBuild(); // 子类实现

			// 结束，设置状态 built -> build 现在完成时
			this.buildState = BuildState.BUILT;
			return result;
		}
	}

	/**
	 * Invoked prior to invoking each {@link SecurityConfigurer#init(SecurityBuilder)}
	 * method. Subclasses may override this method to hook into the lifecycle without
	 * using a {@link SecurityConfigurer}.
	 */
	protected void beforeInit() throws Exception {
	}

	/**
	 * Invoked prior to invoking each
	 * {@link SecurityConfigurer#configure(SecurityBuilder)} method. Subclasses may
	 * override this method to hook into the lifecycle without using a
	 * {@link SecurityConfigurer}.
	 */
	protected void beforeConfigure() throws Exception {
	}

	/**
	 * Subclasses must implement this method to build the object that is being returned.
	 *
	 * @return the Object to be buit or null if the implementation allows it
	 */
	protected abstract O performBuild() throws Exception;

	@SuppressWarnings("unchecked")
	private void init() throws Exception {
		// 获取所有的 configurer，这是一个全新的对象
		Collection<SecurityConfigurer<O, B>> configurers = getConfigurers();

		// 调用所有 configurer 的 init
		for (SecurityConfigurer<O, B> configurer : configurers) {
			configurer.init((B) this);
		}

		// 如果在上面的循环中 init 方法调用了 add(C configurer)，会出现循环中操作集合的并发异常 ConcurrentModificationException 吗 ??? 不会!

		// 如果是 init 阶段添加了新的 SecurityConfigurer，那么还可以在这里再次调用一次
		for (SecurityConfigurer<O, B> configurer : this.configurersAddedInInitializing) {
			configurer.init((B) this);
		}
	}

	/**
	 * Spring Security 的好几个组件都会走这个模式，包括：
	 * - AuthenticationManagerBuilder 通过 GlobalAuthenticationConfigurerAdapter 配置
	 * - HttpSecurity 通过 AbstractHttpConfigurer 配置
	 *
	 * @throws Exception 异常
	 */
	@SuppressWarnings("unchecked")
	private void configure() throws Exception {
		// 再次从 Map 中获取所有 Value 构造了一个集合
		Collection<SecurityConfigurer<O, B>> configurers = getConfigurers();

		// 调用所有 configurer 的 configure 方法
		for (SecurityConfigurer<O, B> configurer : configurers) {
			configurer.configure((B) this);
		}
	}

	/**
	 * 获取所有配置器，表面上是简单的 get，实际上是构造了一个 List，然后汇总 Map 中的所有 Value
	 */
	private Collection<SecurityConfigurer<O, B>> getConfigurers() {
		List<SecurityConfigurer<O, B>> result = new ArrayList<>();

		// 虽然这是一个 Map，但是这里是直接获取所有 values，汇总成 List
		for (List<SecurityConfigurer<O, B>> configs : this.configurers.values()) {
			result.addAll(configs);
		}
		return result;
	}

	/**
	 * Determines if the object is unbuilt.
	 *
	 * @return true, if unbuilt else false
	 */
	private boolean isUnbuilt() {
		synchronized (this.configurers) {
			return this.buildState == BuildState.UNBUILT;
		}
	}

	/**
	 * The build state for the application
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	private enum BuildState {

		/**
		 * This is the state before the {@link Builder#build()} is invoked
		 */
		UNBUILT(0),

		/**
		 * The state from when {@link Builder#build()} is first invoked until all the
		 * {@link SecurityConfigurer#init(SecurityBuilder)} methods have been invoked.
		 */
		INITIALIZING(1),

		/**
		 * The state from after all {@link SecurityConfigurer#init(SecurityBuilder)} have
		 * been invoked until after all the
		 * {@link SecurityConfigurer#configure(SecurityBuilder)} methods have been
		 * invoked.
		 */
		CONFIGURING(2),

		/**
		 * From the point after all the
		 * {@link SecurityConfigurer#configure(SecurityBuilder)} have completed to just
		 * after {@link AbstractConfiguredSecurityBuilder#performBuild()}.
		 */
		BUILDING(3),

		/**
		 * After the object has been completely built.
		 */
		BUILT(4);

		private final int order;

		BuildState(int order) {
			this.order = order;
		}

		public boolean isInitializing() {
			return INITIALIZING.order == this.order;
		}

		/**
		 * Determines if the state is CONFIGURING or later
		 *
		 * @return
		 */
		public boolean isConfigured() {
			return this.order >= CONFIGURING.order;
		}

	}

}
