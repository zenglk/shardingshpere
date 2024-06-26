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

package org.apache.shardingsphere.db.protocol.postgresql.packet.command;

import org.apache.shardingsphere.db.protocol.postgresql.exception.PostgreSQLProtocolException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class PostgreSQLCommandPacketTypeTest {
    
    @Test
    public void assertValueOfUnknownCommandPacketType() {
        assertThrows(PostgreSQLProtocolException.class, () -> PostgreSQLCommandPacketType.valueOf(-1));
    }
    
    @Test
    public void assertValueOfExtendedProtocolCommandPacketType() {
        assertTrue(PostgreSQLCommandPacketType.isExtendedProtocolPacketType(PostgreSQLCommandPacketType.PARSE_COMMAND));
        assertTrue(PostgreSQLCommandPacketType.isExtendedProtocolPacketType(PostgreSQLCommandPacketType.BIND_COMMAND));
        assertTrue(PostgreSQLCommandPacketType.isExtendedProtocolPacketType(PostgreSQLCommandPacketType.DESCRIBE_COMMAND));
        assertTrue(PostgreSQLCommandPacketType.isExtendedProtocolPacketType(PostgreSQLCommandPacketType.EXECUTE_COMMAND));
        assertTrue(PostgreSQLCommandPacketType.isExtendedProtocolPacketType(PostgreSQLCommandPacketType.CLOSE_COMMAND));
        assertTrue(PostgreSQLCommandPacketType.isExtendedProtocolPacketType(PostgreSQLCommandPacketType.FLUSH_COMMAND));
        assertTrue(PostgreSQLCommandPacketType.isExtendedProtocolPacketType(PostgreSQLCommandPacketType.SYNC_COMMAND));
    }
}
