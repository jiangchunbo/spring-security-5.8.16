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

package org.springframework.security.core;

import java.io.Serializable;

import org.springframework.security.access.AccessDecisionManager;

/**
 * Represents an authority granted to an {@link Authentication} object.
 *
 * <p>
 * A <code>GrantedAuthority</code> must either represent itself as a <code>String</code>
 * or be specifically supported by an {@link AccessDecisionManager}.
 *
 * @author Ben Alex
 */
public interface GrantedAuthority extends Serializable {

	/**
	 * If the <code>GrantedAuthority</code> can be represented as a <code>String</code>
	 * and that <code>String</code> is sufficient in precision to be relied upon for an
	 * access control decision by an {@link AccessDecisionManager} (or delegate), this
	 * method should return such a <code>String</code>.
	 * <p>
	 * <strong>如果 <code>GrantedAuthority</code> 可以表示为一个 <code>String</code>，
	 * 并且该 <code>String</code> 具有足够的精度可以被 {@link AccessDecisionManager}（或委托）
	 * 用于访问控制决策，则此方法应该返回这样的 <code>String</code>。</strong>
	 *
	 * <p>
	 * If the <code>GrantedAuthority</code> cannot be expressed with sufficient precision
	 * as a <code>String</code>, <code>null</code> should be returned. Returning
	 * <code>null</code> will require an <code>AccessDecisionManager</code> (or delegate)
	 * to specifically support the <code>GrantedAuthority</code> implementation, so
	 * returning <code>null</code> should be avoided unless actually required.
	 * <p>
	 * <strong>如果 <code>GrantedAuthority</code> 无法以足够的精度表示为 <code>String</code>，
	 * 则应该返回 <code>null</code>。返回 <code>null</code> 将要求 <code>AccessDecisionManager</code>
	 * （或委托）专门支持该 <code>GrantedAuthority</code> 实现，因此除非确实需要，
	 * 否则应该避免返回 <code>null</code>。</strong>
	 *
	 * @return a representation of the granted authority (or <code>null</code> if the
	 * granted authority cannot be expressed as a <code>String</code> with sufficient
	 * precision).
	 * <p>
	 * <strong>授予权限的表示形式（如果授予的权限无法以足够精度表示为 <code>String</code>，
	 * 则返回 <code>null</code>）。</strong>
	 */
	String getAuthority();

}
