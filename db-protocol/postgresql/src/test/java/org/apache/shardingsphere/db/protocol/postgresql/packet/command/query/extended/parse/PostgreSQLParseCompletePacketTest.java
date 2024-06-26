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

package org.apache.shardingsphere.db.protocol.postgresql.packet.command.query.extended.parse;

import io.netty.buffer.ByteBuf;
import org.apache.shardingsphere.db.protocol.postgresql.payload.PostgreSQLPacketPayload;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public final class PostgreSQLParseCompletePacketTest {
    
    @Test
    public void assertGetInstanceAndWrite() {
        PostgreSQLPacketPayload payload = mock(PostgreSQLPacketPayload.class);
        ByteBuf byteBuf = mock(ByteBuf.class);
        when(payload.getByteBuf()).thenReturn(byteBuf);
        PostgreSQLParseCompletePacket packet = PostgreSQLParseCompletePacket.getInstance();
        packet.write(payload);
        verify(byteBuf).writeBytes(new byte[]{'1', 0, 0, 0, 4});
    }
}
