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

package org.apache.shardingsphere.dialect.postgresql.message;

import org.apache.shardingsphere.dialect.postgresql.vendor.PostgreSQLVendorError;
import org.junit.jupiter.api.Test;
import org.postgresql.util.ServerErrorMessage;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public final class ServerErrorMessageBuilderTest {
    
    @Test
    public void assertToServerErrorMessage() {
        ServerErrorMessage actual = ServerErrorMessageBuilder.build("FATAL", PostgreSQLVendorError.PRIVILEGE_NOT_GRANTED, "foo_user", "foo_db");
        assertThat(actual.getSeverity(), is("FATAL"));
        assertThat(actual.getSQLState(), is(PostgreSQLVendorError.PRIVILEGE_NOT_GRANTED.getSqlState().getValue()));
        assertThat(actual.getMessage(), is("Access denied for user 'foo_user' to database 'foo_db'"));
    }
}
