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

package org.apache.shardingsphere.db.protocol.postgresql.packet.command.query.extended.bind.protocol;

import org.apache.shardingsphere.db.protocol.postgresql.packet.command.query.extended.PostgreSQLColumnType;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public final class PostgreSQLBinaryProtocolValueFactoryTest {
    
    @Test
    public void assertGetStringBinaryProtocolValueByVarchar() {
        PostgreSQLBinaryProtocolValue binaryProtocolValue = PostgreSQLBinaryProtocolValueFactory.getBinaryProtocolValue(PostgreSQLColumnType.POSTGRESQL_TYPE_VARCHAR);
        assertThat(binaryProtocolValue, instanceOf(PostgreSQLStringBinaryProtocolValue.class));
    }
    
    @Test
    public void assertGetStringBinaryProtocolValueByChar() {
        PostgreSQLBinaryProtocolValue binaryProtocolValue = PostgreSQLBinaryProtocolValueFactory.getBinaryProtocolValue(PostgreSQLColumnType.POSTGRESQL_TYPE_CHAR);
        assertThat(binaryProtocolValue, instanceOf(PostgreSQLStringBinaryProtocolValue.class));
    }
    
    @Test
    public void assertGetInt8BinaryProtocolValue() {
        PostgreSQLBinaryProtocolValue binaryProtocolValue = PostgreSQLBinaryProtocolValueFactory.getBinaryProtocolValue(PostgreSQLColumnType.POSTGRESQL_TYPE_INT8);
        assertThat(binaryProtocolValue, instanceOf(PostgreSQLInt8BinaryProtocolValue.class));
    }
    
    @Test
    public void assertGetInt4BinaryProtocolValue() {
        PostgreSQLBinaryProtocolValue binaryProtocolValue = PostgreSQLBinaryProtocolValueFactory.getBinaryProtocolValue(PostgreSQLColumnType.POSTGRESQL_TYPE_INT4);
        assertThat(binaryProtocolValue, instanceOf(PostgreSQLInt4BinaryProtocolValue.class));
    }
    
    @Test
    public void assertGetInt2BinaryProtocolValue() {
        PostgreSQLBinaryProtocolValue binaryProtocolValue = PostgreSQLBinaryProtocolValueFactory.getBinaryProtocolValue(PostgreSQLColumnType.POSTGRESQL_TYPE_INT2);
        assertThat(binaryProtocolValue, instanceOf(PostgreSQLInt2BinaryProtocolValue.class));
    }
    
    @Test
    public void assertGetDoubleBinaryProtocolValue() {
        PostgreSQLBinaryProtocolValue binaryProtocolValue = PostgreSQLBinaryProtocolValueFactory.getBinaryProtocolValue(PostgreSQLColumnType.POSTGRESQL_TYPE_FLOAT8);
        assertThat(binaryProtocolValue, instanceOf(PostgreSQLDoubleBinaryProtocolValue.class));
    }
    
    @Test
    public void assertGetFloatBinaryProtocolValue() {
        PostgreSQLBinaryProtocolValue binaryProtocolValue = PostgreSQLBinaryProtocolValueFactory.getBinaryProtocolValue(PostgreSQLColumnType.POSTGRESQL_TYPE_FLOAT4);
        assertThat(binaryProtocolValue, instanceOf(PostgreSQLFloatBinaryProtocolValue.class));
    }
    
    @Test
    public void assertGetNumericBinaryProtocolValue() {
        PostgreSQLBinaryProtocolValue binaryProtocolValue = PostgreSQLBinaryProtocolValueFactory.getBinaryProtocolValue(PostgreSQLColumnType.POSTGRESQL_TYPE_NUMERIC);
        assertThat(binaryProtocolValue, instanceOf(PostgreSQLNumericBinaryProtocolValue.class));
    }
    
    @Test
    public void assertGetDateBinaryProtocolValue() {
        PostgreSQLBinaryProtocolValue binaryProtocolValue = PostgreSQLBinaryProtocolValueFactory.getBinaryProtocolValue(PostgreSQLColumnType.POSTGRESQL_TYPE_DATE);
        assertThat(binaryProtocolValue, instanceOf(PostgreSQLDateBinaryProtocolValue.class));
    }
    
    @Test
    public void assertGetTimeBinaryProtocolValue() {
        PostgreSQLBinaryProtocolValue binaryProtocolValue = PostgreSQLBinaryProtocolValueFactory.getBinaryProtocolValue(PostgreSQLColumnType.POSTGRESQL_TYPE_TIMESTAMP);
        assertThat(binaryProtocolValue, instanceOf(PostgreSQLTimeBinaryProtocolValue.class));
    }
    
    @Test
    public void assertGetBinaryProtocolValueExThrown() {
        assertThrows(IllegalArgumentException.class, () -> PostgreSQLBinaryProtocolValueFactory.getBinaryProtocolValue(PostgreSQLColumnType.POSTGRESQL_TYPE_XML));
    }
}
