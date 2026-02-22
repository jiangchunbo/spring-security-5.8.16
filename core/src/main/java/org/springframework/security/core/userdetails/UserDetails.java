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

import java.io.Serializable;
import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Provides core user information.
 * <p>
 * <strong>提供核心的用户信息。</strong>
 *
 * <p>
 * Implementations are not used directly by Spring Security for security purposes. They
 * simply store user information which is later encapsulated into {@link Authentication}
 * objects. This allows non-security related user information (such as email addresses,
 * telephone numbers etc) to be stored in a convenient location.
 * <p>
 * <strong>实现类不会被 Spring Security 直接用于安全决策，而是用于存储用户信息，随后会封装进
 * {@link Authentication} 对象的用户信息。这使得邮箱、电话等与安全无直接关系的信息
 * 也能集中存放在一个方便的位置。</strong>
 *
 * <p>
 * Concrete implementations must take particular care to ensure the non-null contract
 * detailed for each method is enforced. See
 * {@link org.springframework.security.core.userdetails.User} for a reference
 * implementation (which you might like to extend or use in your code).
 * <p>
 * <strong>具体实现必须严格遵守各方法声明的非空约定。可参考
 * {@link org.springframework.security.core.userdetails.User} 这个实现（你也可以在代码中
 * 继承或直接使用它）。</strong>
 *
 * @author Ben Alex
 * @see UserDetailsService
 * @see UserCache
 */
public interface UserDetails extends Serializable {

	/**
	 * Returns the authorities granted to the user. Cannot return <code>null</code>.
	 * <p>
	 * <strong>返回授予该用户的权限集合，不能返回 <code>null</code>。</strong>
	 * @return the authorities, sorted by natural key (never <code>null</code>)
	 */
	Collection<? extends GrantedAuthority> getAuthorities();

	/**
	 * Returns the password used to authenticate the user.
	 * <p>
	 * <strong>返回用于认证该用户的密码。</strong>
	 * @return the password
	 */
	String getPassword();

	/**
	 * Returns the username used to authenticate the user. Cannot return
	 * <code>null</code>.
	 * <p>
	 * <strong>返回用于认证该用户的用户名，不能返回 <code>null</code>。</strong>
	 * @return the username (never <code>null</code>)
	 */
	String getUsername();

	/**
	 * Indicates whether the user's account has expired. An expired account cannot be
	 * authenticated.
	 * <p>
	 * <strong>指示用户账号是否未过期；账号过期后将无法通过认证。</strong>
	 * @return <code>true</code> if the user's account is valid (ie non-expired),
	 * <code>false</code> if no longer valid (ie expired)
	 */
	boolean isAccountNonExpired();

	/**
	 * Indicates whether the user is locked or unlocked. A locked user cannot be
	 * authenticated.
	 * <p>
	 * <strong>指示用户是否未被锁定；被锁定的用户无法通过认证。</strong>
	 * @return <code>true</code> if the user is not locked, <code>false</code> otherwise
	 */
	boolean isAccountNonLocked();

	/**
	 * Indicates whether the user's credentials (password) has expired. Expired
	 * credentials prevent authentication.
	 * <p>
	 * <strong>指示用户凭据（密码）是否未过期；凭据过期会阻止认证。</strong>
	 * @return <code>true</code> if the user's credentials are valid (ie non-expired),
	 * <code>false</code> if no longer valid (ie expired)
	 */
	boolean isCredentialsNonExpired();

	/**
	 * Indicates whether the user is enabled or disabled. A disabled user cannot be
	 * authenticated.
	 * <p>
	 * <strong>指示用户是否启用；被禁用的用户无法通过认证。</strong>
	 * @return <code>true</code> if the user is enabled, <code>false</code> otherwise
	 */
	boolean isEnabled();

}
