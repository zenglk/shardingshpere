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

package org.apache.shardingsphere.sharding.distsql.update;

import org.apache.shardingsphere.distsql.handler.exception.algorithm.AlgorithmInUsedException;
import org.apache.shardingsphere.distsql.handler.exception.algorithm.MissingRequiredAlgorithmException;
import org.apache.shardingsphere.infra.config.algorithm.AlgorithmConfiguration;
import org.apache.shardingsphere.infra.metadata.database.ShardingSphereDatabase;
import org.apache.shardingsphere.sharding.api.config.ShardingRuleConfiguration;
import org.apache.shardingsphere.sharding.api.config.rule.ShardingAutoTableRuleConfiguration;
import org.apache.shardingsphere.sharding.api.config.strategy.keygen.KeyGenerateStrategyConfiguration;
import org.apache.shardingsphere.sharding.distsql.handler.update.DropShardingKeyGeneratorStatementUpdater;
import org.apache.shardingsphere.sharding.distsql.parser.statement.DropShardingKeyGeneratorStatement;
import org.junit.Before;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.Collections;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public final class DropShardingKeyGeneratorStatementUpdaterTest {
    
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private ShardingSphereDatabase database;
    
    private final DropShardingKeyGeneratorStatementUpdater updater = new DropShardingKeyGeneratorStatementUpdater();
    
    @Before
    public void before() {
        when(database.getName()).thenReturn("test");
    }
    
    @Test
    public void assertExecuteWithNotExist() {
        assertThrows(MissingRequiredAlgorithmException.class, () -> updater.checkSQLStatement(database, createSQLStatement("uuid_key_generator"), new ShardingRuleConfiguration()));
    }
    
    @Test
    public void assertExecuteWithNotExistWithIfExists() {
        DropShardingKeyGeneratorStatement sqlStatement = new DropShardingKeyGeneratorStatement(true, Collections.singletonList("uuid_key_generator"));
        updater.checkSQLStatement(database, sqlStatement, new ShardingRuleConfiguration());
    }
    
    @Test
    public void assertDropSpecifiedKeyGenerator() {
        ShardingRuleConfiguration currentRuleConfig = new ShardingRuleConfiguration();
        currentRuleConfig.getKeyGenerators().put("uuid_key_generator", new AlgorithmConfiguration("uuid", new Properties()));
        updater.updateCurrentRuleConfiguration(createSQLStatement("uuid_key_generator"), currentRuleConfig);
        assertTrue(currentRuleConfig.getKeyGenerators().isEmpty());
    }
    
    @Test
    public void assertExecuteWithUsed() {
        ShardingRuleConfiguration currentRuleConfig = new ShardingRuleConfiguration();
        currentRuleConfig.getKeyGenerators().put("uuid_key_generator", new AlgorithmConfiguration("UUID", null));
        currentRuleConfig.getAutoTables().add(createShardingAutoTableRuleConfiguration());
        assertThrows(AlgorithmInUsedException.class, () -> updater.checkSQLStatement(database, createSQLStatement("uuid_key_generator"), currentRuleConfig));
    }
    
    private ShardingAutoTableRuleConfiguration createShardingAutoTableRuleConfiguration() {
        ShardingAutoTableRuleConfiguration result = new ShardingAutoTableRuleConfiguration("auto_table", null);
        result.setKeyGenerateStrategy(new KeyGenerateStrategyConfiguration("order_id", "uuid_key_generator"));
        return result;
    }
    
    private DropShardingKeyGeneratorStatement createSQLStatement(final String... keyGeneratorNames) {
        return new DropShardingKeyGeneratorStatement(false, Arrays.asList(keyGeneratorNames));
    }
}
