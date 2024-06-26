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

package org.apache.shardingsphere.db.protocol.postgresql.packet.generic;

import org.apache.shardingsphere.db.protocol.postgresql.packet.ByteBufTestUtils;
import org.apache.shardingsphere.db.protocol.postgresql.packet.identifier.PostgreSQLMessagePacketType;
import org.apache.shardingsphere.db.protocol.postgresql.payload.PostgreSQLPacketPayload;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public final class PostgreSQLCommandCompletePacketTest {
    
    @Test
    public void assertSelectReadWrite() {
        String sqlCommand = "SELECT";
        long rowCount = 1;
        String expectedString = sqlCommand + " " + rowCount;
        int expectedStringLength = expectedString.length();
        PostgreSQLPacketPayload payload = new PostgreSQLPacketPayload(ByteBufTestUtils.createByteBuf(expectedStringLength + 1), StandardCharsets.ISO_8859_1);
        PostgreSQLCommandCompletePacket packet = new PostgreSQLCommandCompletePacket(sqlCommand, rowCount);
        assertThat(packet.getIdentifier(), is(PostgreSQLMessagePacketType.COMMAND_COMPLETE));
        packet.write(payload);
        assertThat(payload.readStringNul(), is(expectedString));
    }
    
    @Test
    public void assertInsertReadWrite() {
        String sqlCommand = "INSERT";
        long rowCount = 1;
        String expectedString = sqlCommand + " 0 " + rowCount;
        int expectedStringLength = expectedString.length();
        PostgreSQLPacketPayload payload = new PostgreSQLPacketPayload(ByteBufTestUtils.createByteBuf(expectedStringLength + 1), StandardCharsets.ISO_8859_1);
        PostgreSQLCommandCompletePacket packet = new PostgreSQLCommandCompletePacket(sqlCommand, rowCount);
        assertThat(packet.getIdentifier(), is(PostgreSQLMessagePacketType.COMMAND_COMPLETE));
        packet.write(payload);
        assertThat(payload.readStringNul(), is(expectedString));
    }
    
    @Test
    public void assertMoveReadWrite() {
        String sqlCommand = "MOVE";
        long rowCount = 1;
        String expectedString = sqlCommand + " " + rowCount;
        int expectedStringLength = expectedString.length();
        PostgreSQLPacketPayload payload = new PostgreSQLPacketPayload(ByteBufTestUtils.createByteBuf(expectedStringLength + 1), StandardCharsets.ISO_8859_1);
        PostgreSQLCommandCompletePacket packet = new PostgreSQLCommandCompletePacket(sqlCommand, rowCount);
        assertThat(packet.getIdentifier(), is(PostgreSQLMessagePacketType.COMMAND_COMPLETE));
        packet.write(payload);
        assertThat(payload.readStringNul(), is(expectedString));
    }
}
