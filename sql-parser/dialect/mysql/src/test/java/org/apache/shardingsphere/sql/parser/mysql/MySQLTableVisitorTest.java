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

package org.apache.shardingsphere.sql.parser.mysql;

import org.antlr.v4.runtime.CodePointBuffer;
import org.antlr.v4.runtime.CodePointCharStream;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTree;
import org.apache.shardingsphere.sql.parser.core.ParseASTNode;
import org.apache.shardingsphere.sql.parser.mysql.parser.MySQLLexer;
import org.apache.shardingsphere.sql.parser.mysql.parser.MySQLParser;
import org.apache.shardingsphere.sql.parser.mysql.visitor.MySQLSQLStatVisitor;
import org.apache.shardingsphere.sql.parser.sql.common.SQLStats;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.nio.CharBuffer;
import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public final class MySQLTableVisitorTest {
    
    @ParameterizedTest(name = "{0}")
    @ArgumentsSource(TestCaseArgumentsProvider.class)
    public void assertSQLStats(final String caseId, final String inputSql, final int tableNum, final int columnNum) {
        CodePointBuffer buffer = CodePointBuffer.withChars(CharBuffer.wrap(inputSql.toCharArray()));
        MySQLLexer lexer = new MySQLLexer(CodePointCharStream.fromBuffer(buffer));
        MySQLParser parser = new MySQLParser(new CommonTokenStream(lexer));
        ParseTree tree = ((ParseASTNode) parser.parse()).getRootNode();
        MySQLSQLStatVisitor visitor = new MySQLSQLStatVisitor();
        SQLStats sqlStats = visitor.visit(tree);
        assertThat(sqlStats.getTables().keySet().size(), is(tableNum));
        assertThat(sqlStats.getColumns().keySet().size(), is(columnNum));
    }
    
    private static class TestCaseArgumentsProvider implements ArgumentsProvider {
        
        @Override
        public Stream<? extends Arguments> provideArguments(final ExtensionContext extensionContext) {
            return Stream.of(Arguments.of("select_with_union", "select a+1 as b, name n from table1 join table2 where id=1 and name='lu';", 2, 3),
                    Arguments.of("select_item_nums", "select id, name, age, sex, ss, yy from table1 where id=1", 1, 6),
                    Arguments.of("select_with_subquery", "select id, name, age, count(*) as n, (select id, name, age, sex from table2 where id=2) as sid, yyyy from table1 where id=1", 2, 5),
                    Arguments.of("select_where_num", "select id, name, age, sex, ss, yy from table1 where id=1 and name=1 and a=1 and b=2 and c=4 and d=3", 1, 10),
                    Arguments.of("alter_table", "ALTER TABLE t_order ADD column4 DATE, ADD column5 DATETIME, engine ss max_rows 10,min_rows 2, ADD column6 TIMESTAMP, ADD column7 TIME;", 1, 4),
                    Arguments.of("create_table", "CREATE TABLE IF NOT EXISTS `runoob_tbl`(\n"
                            + "`runoob_id` INT UNSIGNED AUTO_INCREMENT,\n"
                            + "`runoob_title` VARCHAR(100) NOT NULL,\n"
                            + "`runoob_author` VARCHAR(40) NOT NULL,\n"
                            + "`runoob_test` NATIONAL CHAR(40),\n"
                            + "`submission_date` DATE,\n"
                            + "PRIMARY KEY ( `runoob_id` )\n"
                            + ")ENGINE=InnoDB DEFAULT CHARSET=utf8;",
                            1, 5));
        }
    }
}
