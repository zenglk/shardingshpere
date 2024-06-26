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

package org.apache.shardingsphere.driver.jdbc.adapter.invocation;

import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public final class MethodInvocationRecorderTest {
    
    @Test
    public void assertRecordMethodInvocationSuccess() throws SQLException {
        MethodInvocationRecorder<List<?>> methodInvocationRecorder = new MethodInvocationRecorder<>();
        methodInvocationRecorder.record("isEmpty", List::isEmpty);
        methodInvocationRecorder.replay(Collections.emptyList());
    }
    
    @Test
    public void assertRecordSameMethodTwice() throws SQLException {
        MethodInvocationRecorder<List<Integer>> methodInvocationRecorder = new MethodInvocationRecorder<>();
        methodInvocationRecorder.record("add", target -> target.add(1));
        methodInvocationRecorder.record("add", target -> target.add(2));
        List<Integer> actual = new ArrayList<>();
        methodInvocationRecorder.replay(actual);
        assertThat(actual.size(), is(1));
        assertThat(actual.get(0), is(2));
    }
}
