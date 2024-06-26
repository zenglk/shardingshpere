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

package org.apache.shardingsphere.sharding.cache.rule.builder;

import org.apache.shardingsphere.infra.instance.InstanceContext;
import org.apache.shardingsphere.infra.rule.ShardingSphereRule;
import org.apache.shardingsphere.infra.rule.builder.database.DatabaseRuleBuilder;
import org.apache.shardingsphere.infra.rule.identifier.scope.DatabaseRule;
import org.apache.shardingsphere.sharding.cache.api.ShardingCacheRuleConfiguration;
import org.apache.shardingsphere.sharding.cache.rule.ShardingCacheRule;
import org.apache.shardingsphere.sharding.constant.ShardingOrder;
import org.apache.shardingsphere.sharding.rule.ShardingRule;
import org.apache.shardingsphere.timeservice.core.rule.TimeServiceRule;

import javax.sql.DataSource;
import java.util.Collection;
import java.util.Map;

/**
 * Builder for Sharding cache rule.
 */
public final class ShardingCacheRuleBuilder implements DatabaseRuleBuilder<ShardingCacheRuleConfiguration> {
    
    @Override
    public DatabaseRule build(final ShardingCacheRuleConfiguration config, final String databaseName, final Map<String, DataSource> dataSources, final Collection<ShardingSphereRule> builtRules,
                              final InstanceContext instanceContext) {
        ShardingRule shardingRule = (ShardingRule) builtRules.stream().filter(ShardingRule.class::isInstance).findFirst()
                .orElseThrow(() -> new IllegalStateException("ShardingCacheRule requires ShardingRule"));
        TimeServiceRule timeServiceRule = (TimeServiceRule) builtRules.stream().filter(TimeServiceRule.class::isInstance).findFirst()
                .orElseThrow(() -> new IllegalStateException("ShardingCacheRule requires TimeServiceRule"));
        return new ShardingCacheRule(config, shardingRule, timeServiceRule);
    }
    
    @Override
    public int getOrder() {
        return ShardingOrder.ORDER + 1;
    }
    
    @Override
    public Class<ShardingCacheRuleConfiguration> getTypeClass() {
        return ShardingCacheRuleConfiguration.class;
    }
}
