#include "framework.h"
#include "map.h"
#include <stdint.h>

TEST(test_map_prev_from_end_of_empty_map) {
    TEST_CASE("walking backwards from the end of an empty map yields nothing");

    /* __map_maximum started from the sentinel, whose children are NULL, and
     * dereferenced one. Found by the misc_containers fuzz target. */
    map_t* map = map_create_int();
    TEST_REQUIRE_NOT_NULL(map, "map");

    map_iterator_t it = map_prev(map_end(map));
    TEST_ASSERT(!map_iterator_valid(it), "no element before the end");

    map_insert_int(map, 1, NULL);
    map_erase_int(map, 1);
    it = map_prev(map_end(map));
    TEST_ASSERT(!map_iterator_valid(it), "still none once emptied again");

    map_free(map);
}

TEST(test_map_prev_walks_in_reverse) {
    TEST_CASE("map_prev from the end visits every key in descending order");

    map_t* map = map_create_int();
    TEST_REQUIRE_NOT_NULL(map, "map");
    for (int i = 0; i < 50; i++)
        map_insert_int(map, (i * 37) % 50, NULL);

    intptr_t expect = 49;
    for (map_iterator_t it = map_prev(map_end(map)); map_iterator_valid(it); it = map_prev(it))
        TEST_ASSERT_EQUAL(expect--, (intptr_t)map_iterator_key(it), "descending");
    TEST_ASSERT_EQUAL(-1, expect, "all fifty seen");

    map_free(map);
}
