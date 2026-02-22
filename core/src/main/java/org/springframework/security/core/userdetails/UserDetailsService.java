/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core.userdetails;

/**
 * Core interface which loads user-specific data.
 * <br>
 * <strong>用于加载用户特定数据的核心接口。</strong>
 * <p>
 * It is used throughout the framework as a user DAO and is the strategy used by the
 * {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider
 * DaoAuthenticationProvider}.
 * <p>
 * <strong>该接口在框架中作为用户 DAO 使用，并且是</strong>
 * {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider
 * DaoAuthenticationProvider} <strong>采用的策略接口。</strong>
 *
 * <p>
 * The interface requires only one read-only method, which simplifies support for new
 * data-access strategies.
 * <br>
 * <strong>该接口仅要求一个只读方法，从而简化了对新数据访问策略的支持。</strong>
 *
 * @author Ben Alex
 * @see org.springframework.security.authentication.dao.DaoAuthenticationProvider
 * @see UserDetails
 */
public interface UserDetailsService {

	/**
	 * Locates the user based on the username. In the actual implementation, the search
	 * may possibly be case sensitive, or case insensitive depending on how the
	 * implementation instance is configured. In this case, the <code>UserDetails</code>
	 * object that comes back may have a username that is of a different case than what
	 * was actually requested.
	 * <p>
	 * <strong>根据用户名定位用户。具体实现中的查询可能区分大小写，也可能不区分大小写，这取决于实现实例的配置。
	 * 因此，返回的 <code>UserDetails</code> 对象中的用户名大小写可能与请求时传入的用户名不一致。</strong>
	 *
	 * @param username the username identifying the user whose data is required.
	 *                 <p>
	 *                 <strong>用于标识目标用户的用户名。</strong>
	 * @return a fully populated user record (never <code>null</code>). <strong>完整填充的用户记录（绝不会为 <code>null</code>）。</strong>
	 * @throws UsernameNotFoundException if the user could not be found or the user has no
	 *                                   GrantedAuthority
	 *                                   <p>
	 *                                   <strong>当用户不存在，或用户未被授予任何</strong>
	 *                                   <strong>GrantedAuthority 时抛出。</strong>
	 */
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;

}
