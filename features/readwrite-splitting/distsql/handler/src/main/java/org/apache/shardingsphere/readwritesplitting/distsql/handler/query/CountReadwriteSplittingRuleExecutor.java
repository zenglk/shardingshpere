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

package org.apache.shardingsphere.readwritesplitting.distsql.handler.query;

import org.apache.shardingsphere.distsql.handler.query.RQLExecutor;
import org.apache.shardingsphere.infra.merge.result.impl.local.LocalDataQueryResultRow;
import org.apache.shardingsphere.infra.metadata.database.ShardingSphereDatabase;
import org.apache.shardingsphere.readwritesplitting.distsql.parser.statement.CountReadwriteSplittingRuleStatement;
import org.apache.shardingsphere.readwritesplitting.rule.ReadwriteSplittingRule;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Count readwrite splitting rule executor.
 */
public final class CountReadwriteSplittingRuleExecutor implements RQLExecutor<CountReadwriteSplittingRuleStatement> {
    
    private static final String READWRITE_SPLITTING = "readwrite_splitting";
    
    @Override
    public Collection<String> getColumnNames() {
        return Arrays.asList("rule_name", "database", "count");
    }
    
    @Override
    public Collection<LocalDataQueryResultRow> getRows(final ShardingSphereDatabase database, final CountReadwriteSplittingRuleStatement sqlStatement) {
        Optional<ReadwriteSplittingRule> rule = database.getRuleMetaData().findSingleRule(ReadwriteSplittingRule.class);
        Map<String, LinkedList<Object>> rowMap = new LinkedHashMap<>();
        rule.ifPresent(optional -> addReadwriteSplittingData(rowMap, database.getName(), rule.get()));
        Collection<LocalDataQueryResultRow> result = new LinkedList<>();
        for (final Entry<String, LinkedList<Object>> entry : rowMap.entrySet()) {
            entry.getValue().addFirst(entry.getKey());
            result.add(new LocalDataQueryResultRow(entry.getValue()));
        }
        return result;
    }
    
    private void addReadwriteSplittingData(final Map<String, LinkedList<Object>> rowMap, final String databaseName, final ReadwriteSplittingRule rule) {
        addData(rowMap, READWRITE_SPLITTING, databaseName, () -> rule.getDataSourceMapper().size());
    }
    
    private void addData(final Map<String, LinkedList<Object>> rowMap, final String dataKey, final String databaseName, final Supplier<Integer> apply) {
        rowMap.compute(dataKey, (key, value) -> buildRow(value, databaseName, apply.get()));
    }
    
    private LinkedList<Object> buildRow(final LinkedList<Object> value, final String databaseName, final int count) {
        if (null == value) {
            return new LinkedList<>(Arrays.asList(databaseName, count));
        }
        value.set(1, (Integer) value.get(1) + count);
        return value;
    }
    
    @Override
    public String getType() {
        return CountReadwriteSplittingRuleStatement.class.getName();
    }
}
