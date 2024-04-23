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

package org.apache.shardingsphere.test.it.sql.parser.internal.asserts.statement.rdl.drop.impl;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.shardingsphere.sharding.distsql.parser.statement.DropShardingTableReferenceRuleStatement;
import org.apache.shardingsphere.test.it.sql.parser.internal.asserts.SQLCaseAssertContext;
import org.apache.shardingsphere.test.it.sql.parser.internal.cases.parser.jaxb.statement.rdl.rule.sharding.DropShardingTableReferenceRuleStatementTestCase;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Drop sharding table reference rule statement assert.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class DropShardingTableReferenceRulesStatementAssert {
    
    /**
     * Assert drop sharding table reference rule statement is correct with expected parser result.
     *
     * @param assertContext assert context
     * @param actual actual drop sharding table reference rule statement
     * @param expected expected drop sharding table reference rule statement test case
     */
    public static void assertIs(final SQLCaseAssertContext assertContext, final DropShardingTableReferenceRuleStatement actual, final DropShardingTableReferenceRuleStatementTestCase expected) {
        assertNotNull(actual, assertContext.getText("Actual statement should exist."));
        assertThat(assertContext.getText("Sharding table reference rule assertion error: "), actual.getNames(), is(expected.getRuleNames()));
        assertThat(assertContext.getText("Sharding table reference rule assertion error: "), actual.isIfExists(), is(expected.isIfExists()));
    }
}