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

package org.apache.shardingsphere.test.it.sql.parser.internal.asserts.segment.distsql;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.shardingsphere.sql.parser.sql.common.segment.SQLSegment;
import org.apache.shardingsphere.test.it.sql.parser.internal.asserts.SQLCaseAssertContext;
import org.apache.shardingsphere.test.it.sql.parser.internal.cases.parser.jaxb.segment.ExpectedSQLSegment;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 *  SQL segment assert.
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class SQLSegmentAssert {
    
    /**
     * Assert generic attributes of actual SQL segment are same with expected SQL segment.
     * 
     * @param assertContext assert context
     * @param actual actual SQL segment
     * @param expected expected SQL segment
     */
    public static void assertIs(final SQLCaseAssertContext assertContext, final SQLSegment actual, final ExpectedSQLSegment expected) {
        assertThat(assertContext.getText(String.format("`%s`'s start index assertion error: ", actual.getClass().getSimpleName())), actual.getStartIndex(), is(expected.getStartIndex()));
        assertThat(assertContext.getText(String.format("`%s`'s start index assertion error: ", actual.getClass().getSimpleName())), actual.getStopIndex(), is(expected.getStopIndex()));
    }
}
