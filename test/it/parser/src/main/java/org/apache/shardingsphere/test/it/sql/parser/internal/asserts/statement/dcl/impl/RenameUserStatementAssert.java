/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shardingsphere.test.it.sql.parser.internal.asserts.statement.dcl.impl;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.shardingsphere.sql.parser.sql.dialect.statement.mysql.dcl.MySQLRenameUserStatement;
import org.apache.shardingsphere.test.it.sql.parser.internal.asserts.SQLCaseAssertContext;
import org.apache.shardingsphere.test.it.sql.parser.internal.cases.parser.jaxb.statement.dcl.RenameUserStatementTestCase;

/**
 * Rename user statement assert.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class RenameUserStatementAssert {
    
    /**
     * Assert rename user statement is correct with expected parser result.
     * 
     * @param assertContext assert context
     * @param actual actual rename user statement
     * @param expected expected rename user statement test case
     */
    public static void assertIs(final SQLCaseAssertContext assertContext, final MySQLRenameUserStatement actual, final RenameUserStatementTestCase expected) {
    }
}
