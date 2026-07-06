#include <stdlib.h>

#include "viewcommon.h"

static void __view_tag_free(view_tag_t* tag);

/**
 * Free a view tag.
 *
 * @param tag The view tag to free.
 * @return void
 */
void view_tag_free(view_tag_t* tag) {
    if (tag == NULL) return;

    __view_tag_free(tag);

    free(tag);
}

/**
 * Free a view if tag.
 *
 * @param tag The view if tag to free.
 * @return void
 */
void view_tag_condition_free(view_tag_t* tag) {
    if (tag == NULL) return;

    __view_tag_free(tag);

    free((view_condition_item_t*)tag);
}

/**
 * Free a view for tag.
 *
 * @param tag The view for tag to free.
 * @return void
 */
void view_tag_loop_free(view_tag_t* tag) {
    if (tag == NULL) return;

    __view_tag_free(tag);

    free((view_loop_t*)tag);
}

/**
 * Free a view include tag.
 *
 * @param tag The view include tag to free.
 * @return void
 */
void view_tag_include_free(view_tag_t* tag) {
    if (tag == NULL) return;

    __view_tag_free(tag);

    free((view_include_t*)tag);
}

/**
 * Free a view tag.
 *
 * @param tag The view tag to free.
 * @return void
 */
void __view_tag_free(view_tag_t* tag) {
    if (tag == NULL) return;

    tag->type = VIEW_TAGTYPE_VAR;
    tag->parent_text_offset = 0;
    tag->parent_text_size = 0;
    bufferdata_clear(&tag->result_content);
    tag->data_parent = NULL;
    tag->parent = NULL;
    tag->last_child = NULL;

    if (tag->child != NULL)
        tag->child->free(tag->child);

    if (tag->next != NULL)
        tag->next->free(tag->next);

    viewexpr_node_free(tag->expr);
    tag->expr = NULL;
}
