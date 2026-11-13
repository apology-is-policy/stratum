#!/usr/bin/env python3
# Adds a MEASURING test to a scratch copy of tests/test_9p_client.c (never to the clone): a call whose stop is asked nine
# tenths of the way through its first wait; it prints how long after the asking the call was given up and how many looks
# said yes. Usage: measure-test.py <root>
import sys
root = sys.argv[1]
p = root + '/tests/test_9p_client.c'
s = open(p).read()
anchor = 'STM_TEST(p9_client_wait_takes_a_slow_reply_for_a_reply)\n'
assert s.count(anchor) == 1
new = r'''STM_TEST(p9_client_wait_measure_the_wait_the_asking_came_in)
{
    const char *e = getenv("MEASURE_TICK_MS");
    const uint32_t tick = e ? (uint32_t)atoi(e) : 100u;
    e = getenv("MEASURE_LIMIT_MS");
    const uint32_t limit = e ? (uint32_t)atoi(e) : 300u;
    e = getenv("MEASURE_INTO_PCT");
    const uint32_t into = e ? (uint32_t)atoi(e) : 90u;
    fake_daemon d;
    fake_daemon_start(&d, "wait_measure", FAKE_NEVER_ANSWERS, STM_9P_MSIZE_DEFAULT);
    leave_from l = { UINT64_MAX, 0 };
    stm_9p_wait w = { leave_once_it_is_time, &l, tick, limit };
    stm_9p_dial_opts o = default_dial_opts(100);
    o.wait = &w;
    stm_9p_client *c = NULL;
    STM_ASSERT_OK(retry_dial(g_sock_path, &o, &c));
    uint64_t began = test_mono_ms();
    l.from_ms = began + (uint64_t)tick * into / 100u;
    stm_status rc = stm_9p_clunk(c, 100);
    uint64_t ended = test_mono_ms();
    fprintf(stderr, "MEASURE tick=%u limit=%u asked %u%% into the first wait: given up %llu ms after the asking, "
            "%llu ms after the call began, %u looks said yes, rc=%d errno=%d\n", tick, limit, into,
            (unsigned long long)(ended - l.from_ms), (unsigned long long)(ended - began), l.said, (int)rc,
            stm_9p_last_errno(c));
    STM_ASSERT_EQ(rc, STM_EIO);
    stm_9p_close(c);
    fake_daemon_stop(&d);
}

'''
s = s.replace(anchor, new + anchor)
open(p, 'w').write(s)
print('added the measuring test')
