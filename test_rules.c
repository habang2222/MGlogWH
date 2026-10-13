/* SPDX-License-Identifier: BSD-3-Clause */
/* Portable matcher tests and a userspace cost proxy; this does not load BPF. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "rules.h"

static struct eq_rule_token predicate(unsigned field, unsigned comparison,
                                      long long value) {
    struct eq_rule_token token = {.opcode = EQ_TEST, .field = field,
        .comparison = comparison, .value_count = 1};
    token.values[0] = value;
    return token;
}
static long long string_value(unsigned offset, unsigned length) {
    return ((long long)length << 32) | offset;
}

static unsigned check(struct eq_rule_program *program, struct eq_rule_input *input,
                      struct eq_rule_token token) {
    program->token_count = 1;
    program->tokens[0] = token;
    return eq_rule_evaluate(program, input);
}

static void test_numeric_and_event_fields(void) {
    struct eq_rule_program program = {};
    struct eq_rule_input input = {.kind = EQ_OPEN, .result = 7, .flags = 2 | 0100 | 01000,
        .uid = 1000, .pid = 42, .cgroup_id = 55};
    assert(check(&program, &input, predicate(EQ_FIELD_KIND, EQ_OP_EQ, EQ_OPEN)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_SUCCESS, EQ_OP_EQ, 1)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_RESULT, EQ_OP_GT, 6)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_RESULT, EQ_OP_GE, 7)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_RESULT, EQ_OP_LT, 8)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_RESULT, EQ_OP_LE, 7)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_RESULT, EQ_OP_NE, -1)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_ACCESS_MODE, EQ_OP_EQ, 2)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_WRITE_ACCESS, EQ_OP_EQ, 1)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_CREATE, EQ_OP_EQ, 1)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_TRUNCATE, EQ_OP_EQ, 1)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_ROOT, EQ_OP_EQ, 0)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_UID, EQ_OP_EQ, 1000)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_PID, EQ_OP_EQ, 42)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_CGROUP, EQ_OP_EQ, 55)) == EQ_TRUE);

    struct eq_rule_token list = predicate(EQ_FIELD_UID, EQ_OP_IN, 0);
    list.value_count = 3;
    list.values[1] = 1000; list.values[2] = 2000;
    assert(check(&program, &input, list) == EQ_TRUE);
    list.comparison = EQ_OP_NOT_IN;
    assert(check(&program, &input, list) == EQ_FALSE);
    list.values[1] = 1001;
    assert(check(&program, &input, list) == EQ_TRUE);
    input.result = -13;
    assert(check(&program, &input, predicate(EQ_FIELD_SUCCESS, EQ_OP_EQ, 0)) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_RESULT, EQ_OP_LT, 0)) == EQ_TRUE);
    input.flags = EQ_OPEN_PATH_ONLY;
    assert(check(&program, &input, predicate(EQ_FIELD_ACCESS_MODE, EQ_OP_EQ, 0)) == EQ_UNKNOWN);
    assert(check(&program, &input, predicate(EQ_FIELD_WRITE_ACCESS, EQ_OP_EQ, 0)) == EQ_UNKNOWN);
    input.kind = EQ_EXEC;
    assert(check(&program, &input, predicate(EQ_FIELD_CREATE, EQ_OP_EQ, 0)) == EQ_UNKNOWN);
}

static void test_strings_and_uncertainty(void) {
    struct eq_rule_program program = {};
    struct eq_rule_input input = {.kind = EQ_OPEN, .path = "/etc/shadow", .comm = "bash"};
    const char first[] = "/etc/shadow";
    const char second[] = "/etc/passwd";
    unsigned second_offset = sizeof(first);
    memcpy(program.strings, first, sizeof(first));
    memcpy(program.strings + second_offset, second, sizeof(second));
    program.string_bytes = sizeof(first) + sizeof(second);
    assert(check(&program, &input, predicate(EQ_FIELD_PATH, EQ_OP_EQ,
                                            string_value(0, sizeof(first) - 1))) == EQ_TRUE);
    assert(check(&program, &input, predicate(EQ_FIELD_PATH, EQ_OP_NE,
                                            string_value(second_offset, sizeof(second) - 1))) == EQ_TRUE);
    struct eq_rule_token list = predicate(EQ_FIELD_PATH, EQ_OP_IN,
                                          string_value(0, sizeof(first) - 1));
    list.value_count = 2; list.values[1] = string_value(second_offset, sizeof(second) - 1);
    assert(check(&program, &input, list) == EQ_TRUE);
    list.comparison = EQ_OP_NOT_IN;
    assert(check(&program, &input, list) == EQ_FALSE);
    memcpy(program.strings, "/etc/", 6);
    program.string_bytes = 6;
    assert(check(&program, &input, predicate(EQ_FIELD_PATH, EQ_OP_PREFIX, string_value(0, 5))) == EQ_TRUE);
    input.path = "/etc2/shadow";
    assert(check(&program, &input, predicate(EQ_FIELD_PATH, EQ_OP_PREFIX, string_value(0, 5))) == EQ_FALSE);
    input.path = "etc/shadow";
    assert(check(&program, &input, predicate(EQ_FIELD_PATH, EQ_OP_NE, string_value(0, 5))) == EQ_UNKNOWN);
    input.path = "/etc/shadow"; input.path_quality = EQ_TRUNCATED;
    assert(check(&program, &input, predicate(EQ_FIELD_PATH, EQ_OP_NOT_IN, string_value(0, 5))) == EQ_UNKNOWN);
    input.path_quality = EQ_READ_ERROR;
    assert(check(&program, &input, predicate(EQ_FIELD_PATH, EQ_OP_PREFIX, string_value(0, 5))) == EQ_UNKNOWN);
    input.path_quality = 0;
    memcpy(program.strings, "bash\0python3", 13);
    program.string_bytes = 13;
    list = predicate(EQ_FIELD_COMM, EQ_OP_IN, string_value(0, 4));
    list.value_count = 2; list.values[1] = string_value(5, 7);
    assert(check(&program, &input, list) == EQ_TRUE);
    input.comm = "python3";
    assert(check(&program, &input, list) == EQ_TRUE);
    list.comparison = EQ_OP_NOT_IN;
    assert(check(&program, &input, list) == EQ_FALSE);
    input.comm = "ssh";
    assert(check(&program, &input, list) == EQ_TRUE);
}

static void test_logic_and_conflicts(void) {
    struct eq_rule_program program = {};
    memcpy(program.strings, "/etc/", 6);
    program.string_bytes = 6;
    program.token_count = 9;
    program.tokens[0] = predicate(EQ_FIELD_KIND, EQ_OP_EQ, EQ_OPEN);
    program.tokens[1] = predicate(EQ_FIELD_PATH, EQ_OP_PREFIX, string_value(0, 5));
    program.tokens[2].opcode = EQ_ALL;
    program.tokens[3] = predicate(EQ_FIELD_ROOT, EQ_OP_EQ, 0);
    program.tokens[4].opcode = EQ_ALL;
    program.tokens[5] = predicate(EQ_FIELD_WRITE_ACCESS, EQ_OP_EQ, 1);
    program.tokens[6].opcode = EQ_ALL;
    program.tokens[7] = predicate(EQ_FIELD_SUCCESS, EQ_OP_EQ, 1);
    program.tokens[8].opcode = EQ_ALL;
    struct eq_rule_input input = {.kind = EQ_OPEN, .path = "/etc/hosts",
        .flags = 1, .uid = 1000, .result = 3};
    assert(eq_rule_evaluate(&program, &input) == EQ_TRUE);
    input.uid = 0;
    assert(eq_rule_evaluate(&program, &input) == EQ_FALSE);
    input.uid = 1000; input.result = -13;
    assert(eq_rule_evaluate(&program, &input) == EQ_FALSE);
    input.result = 3; input.path_quality = EQ_TRUNCATED;
    assert(eq_rule_evaluate(&program, &input) == EQ_UNKNOWN);

    program.token_count = 4;
    program.tokens[0] = predicate(EQ_FIELD_UID, EQ_OP_EQ, 0);
    program.tokens[1].opcode = EQ_NOT;
    program.tokens[2] = predicate(EQ_FIELD_PID, EQ_OP_EQ, 42);
    program.tokens[3].opcode = EQ_ANY;
    input.path_quality = 0; input.pid = 42;
    assert(eq_rule_evaluate(&program, &input) == EQ_TRUE);
    input.uid = 0; input.pid = 7;
    assert(eq_rule_evaluate(&program, &input) == EQ_FALSE);

    struct eq_rule_program rules[3] = {};
    for (unsigned i = 0; i < 3; i++) {
        rules[i].enabled = 1; rules[i].id = 30 - i * 10;
        rules[i].token_count = 1;
        rules[i].tokens[0] = predicate(EQ_FIELD_KIND, EQ_OP_EQ, EQ_OPEN);
    }
    rules[0].precedence = 10; rules[0].priority = EQ_NORMAL;
    rules[1].precedence = 10; rules[1].priority = EQ_CRITICAL;
    rules[2].precedence = 20; rules[2].priority = EQ_BULK;
    assert(eq_rule_evaluate(&rules[0], &input) == EQ_TRUE);
    assert(eq_rule_evaluate(&rules[1], &input) == EQ_TRUE);
    assert(eq_rule_evaluate(&rules[2], &input) == EQ_TRUE);
    assert(eq_rule_better(&rules[2], &rules[1]));
    rules[2].precedence = 10;
    assert(eq_rule_better(&rules[1], &rules[2]));
    rules[2].priority = EQ_CRITICAL;
    rules[1].overload_policy = EQ_POLICY_EXEMPT;
    rules[2].overload_policy = EQ_POLICY_QUARANTINE;
    assert(eq_rule_better(&rules[2], &rules[1]));
    rules[2].overload_policy = EQ_POLICY_EXEMPT;
    assert(eq_rule_better(&rules[2], &rules[1])); /* smaller ID wins */
}

static volatile unsigned long long benchmark_sink;
static unsigned long long elapsed_ns(struct timespec start, struct timespec end) {
    return (unsigned long long)(end.tv_sec - start.tv_sec) * 1000000000ULL +
           (unsigned long long)(end.tv_nsec - start.tv_nsec);
}
static unsigned long long benchmark(unsigned rule_count) {
    struct eq_rule_program programs[EQ_RULES] = {};
    struct eq_rule_input input = {.kind = EQ_OPEN};
    for (unsigned rule = 0; rule < rule_count; rule++) {
        programs[rule].token_count = 1;
        programs[rule].tokens[0] = predicate(EQ_FIELD_PID, EQ_OP_GE, 0);
    }
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (unsigned event = 0; event < 100000; event++) {
        input.pid = event;
        for (unsigned rule = 0; rule < rule_count; rule++)
            benchmark_sink += eq_rule_evaluate(&programs[rule], &input);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    return elapsed_ns(start, end);
}

int main(void) {
    test_numeric_and_event_fields();
    test_strings_and_uncertainty();
    test_logic_and_conflicts();
    unsigned long long one = benchmark(1), four = benchmark(4),
                       eight = benchmark(EQ_RULES);
    printf("rule matcher cases: OK; 100000 events: 1 rule %llu ns, 4 rules %llu ns, %u rules %llu ns (userspace proxy)\n",
           one, four, EQ_RULES, eight);
    return 0;
}
