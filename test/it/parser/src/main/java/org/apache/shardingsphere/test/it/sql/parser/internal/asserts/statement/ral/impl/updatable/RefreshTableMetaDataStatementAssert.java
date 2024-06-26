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

package org.apache.shardingsphere.test.it.sql.parser.internal.asserts.statement.ral.impl.updatable;

import org.apache.shardingsphere.distsql.parser.statement.ral.updatable.RefreshTableMetaDataStatement;
import org.apache.shardingsphere.test.it.sql.parser.internal.asserts.SQLCaseAssertContext;
import org.apache.shardingsphere.test.it.sql.parser.internal.cases.parser.jaxb.statement.ral.RefreshTableMetaDataStatementTestCase;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Refresh table meta data statement assert.
 */
public final class RefreshTableMetaDataStatementAssert {
    
    /**
     * Assert refresh table meta data statement is correct with expected parser result.
     *
     * @param assertContext assert context
     * @param actual actual refresh table meta data statement
     * @param expected expected refresh table meta data statement test case
     */
    public static void assertIs(final SQLCaseAssertContext assertContext, final RefreshTableMetaDataStatement actual, final RefreshTableMetaDataStatementTestCase expected) {
        if (null == expected) {
            assertNull(actual, assertContext.getText("Actual statement should not exist."));
        } else {
            assertNotNull(actual, assertContext.getText("Actual statement should exist."));
            if (null != expected.getTableName()) {
                assertThat(assertContext.getText("Table name assertion error"), actual.getTableName().get(), is(expected.getTableName()));
            }
            if (null != expected.getStorageUnitName()) {
                assertThat(assertContext.getText("Storage unit name assertion error"), actual.getStorageUnitName().get(), is(expected.getStorageUnitName()));
            }
            if (null != expected.getSchemaName()) {
                assertThat(assertContext.getText("Schema name assertion error"), actual.getSchemaName().get(), is(expected.getSchemaName()));
            }
        }
    }
}
