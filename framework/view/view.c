#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>

#include "appconfig.h"
#include "viewparser.h"
#include "viewstore.h"
#include "view.h"

typedef struct view_scope_data {
    view_copy_tags_t* copy_tags;
    json_doc_t* document;
    view_tag_t* tag;
} view_scope_data_t;

static char* __view_render(json_doc_t* document, view_escape_e escape, const char* storage_name, const char* path);
static char* __view_make_content(view_t* view, json_doc_t* document, view_escape_e escape);
static viewexpr_value_t __view_eval_tag(view_copy_tags_t* copy_tags, json_doc_t* document, view_tag_t* tag);
static void __view_write_value(view_copy_tags_t* copy_tags, const viewexpr_node_t* expr, const viewexpr_value_t* value);
static void __view_build_content_recursive(view_t* view, json_doc_t* document, view_copy_tags_t* copy_tags, view_tag_t* tag);
static void __view_copy_loop_tags_init(view_copy_tags_t* copy_tags);
static void __view_copy_loop_tags_free(view_copy_tags_t* copy_tags);
static view_loop_t* __view_copy_loop_tag_add(view_copy_tags_t* copy_tags, view_tag_t* tag);
static view_loop_t* __view_copy_loop_tag_get(view_copy_tags_t* copy_tags, view_tag_t* tag);

/**
 * Reclaims what modifiers allocated for one tag. arena_reset() keeps every
 * block for reuse, and a request larger than all spare blocks takes a new
 * one, so results that grow from tag to tag (truncate(n) with increasing n)
 * would keep the sum of their sizes until the render ends. Past
 * VIEW_ARENA_RETAIN the blocks go back to the allocator instead.
 *
 * @param arena The render's modifier arena.
 * @return void
 */
void view_arena_reset(arena_t* arena) {
    arena_reset(arena);

    if (arena->total_bytes > VIEW_ARENA_RETAIN)
        arena_free(arena); // leaves it empty and ready, as arena_init() does
}

/**
 * Render a view using a JSON document and a storage.
 *
 * @param document The JSON document to use.
 * @param escape VIEW_ESCAPE to HTML-escape {{ }} values, VIEW_RAW to write them as is.
 * @param storage_name The name of the storage to use.
 * @param path_format The format of the path.
 * @param ... The arguments to format the path.
 * @return The rendered content of the view.
 */
char* render(json_doc_t* document, view_escape_e escape, const char* storage_name, const char* path_format, ...) {
    char path[PATH_MAX];

    va_list args;
    va_start(args, path_format);
    const int written = vsnprintf(path, sizeof(path), path_format, args);
    va_end(args);

    if (written < 0 || written >= (int)sizeof(path))
        return NULL;

    return __view_render(document, escape, storage_name, path);
}

/**
 * Render a view.
 *
 * @param document The JSON document to render.
 * @param escape How {{ }} values are written.
 * @param storage_name The name of the storage to use.
 * @param path The path of the view.
 * @return The rendered content of the view, or NULL if an error occurred.
 */
char* __view_render(json_doc_t* document, view_escape_e escape, const char* storage_name, const char* path) {
    viewstore_t* viewstore = appconfig()->viewstore;
    if (viewstore == NULL) return NULL;

    viewstore_lock(viewstore);
    view_t* view = viewstore_get_view(viewstore, path);
    viewstore_unlock(viewstore);

    if (view == NULL) {
        viewparser_t* parser = viewparser_init(storage_name, path);
        if (parser == NULL) return NULL;

        if (!viewparser_run(parser)) {
            viewparser_free(parser);
            return NULL;
        }

        view_tag_t* root_tag = viewparser_move_root_tag(parser);
        viewparser_free(parser);

        viewstore_lock(viewstore);
        // another thread may have parsed and cached the same path in between
        view = viewstore_get_view(viewstore, path);
        if (view != NULL) {
            viewstore_unlock(viewstore);
            root_tag->free(root_tag);
        }
        else {
            view = viewstore_add_view(viewstore, root_tag, path);
            viewstore_unlock(viewstore);

            if (view == NULL) {
                root_tag->free(root_tag);
                return NULL;
            }
        }
    }

    return __view_make_content(view, document, escape);
}

/**
 * Render a view.
 *
 * @param view The view to render.
 * @param document The JSON document to render.
 * @param escape How {{ }} values are written.
 * @return The rendered content of the view, or NULL if an error occurred.
 */
char* __view_make_content(view_t* view, json_doc_t* document, view_escape_e escape) {
    view_tag_t* child = view->root_tag->child;
    if (child == NULL)
        return bufferdata_copy(&view->root_tag->result_content);

    view_copy_tags_t copy_tags;
    __view_copy_loop_tags_init(&copy_tags);
    copy_tags.escape = escape;

    __view_build_content_recursive(view, document, &copy_tags, child);

    bufferdata_complete(&copy_tags.buf);

    char* data = bufferdata_copy(&copy_tags.buf);

    __view_copy_loop_tags_free(&copy_tags);

    return data;
}

/**
 * Resolves the leading identifier of an expression variable: loop key and
 * element names of enclosing loops first, then the document root fields.
 *
 * @param scope The expression scope.
 * @param name The identifier name.
 * @return The resolved value, or a null value if the name is unknown.
 */
static viewexpr_value_t __view_scope_resolve(const viewexpr_scope_t* scope, const char* name) {
    const view_scope_data_t* data = scope->data;
    viewexpr_value_t value = { VIEWEXPR_NULL, 0, 0, NULL, NULL, 0 };

    view_loop_t* tag_parent = __view_copy_loop_tag_get(data->copy_tags, data->tag->data_parent);
    while (tag_parent != NULL) {
        if (strcmp(name, tag_parent->key_name) == 0) {
            if (tag_parent->key_is_index) {
                value.type = VIEWEXPR_NUMBER;
                value.number = (long double)tag_parent->key_index;
            }
            else {
                value.type = VIEWEXPR_STRING;
                value.string = tag_parent->key_value;
                value.length = tag_parent->key_length;
            }

            return value;
        }

        if (strcmp(name, tag_parent->element_name) == 0)
            return viewexpr_value_from_token(tag_parent->token);

        tag_parent = __view_copy_loop_tag_get(data->copy_tags, tag_parent->base.data_parent);
    }

    const json_token_t* root = data->document != NULL ? json_root(data->document) : NULL;
    if (root == NULL || root->type != JSON_OBJECT)
        return value;

    return viewexpr_value_from_token(json_object_get(root, name));
}

/**
 * Evaluates the expression of a tag within the loop scope of the tag.
 *
 * @param copy_tags The copy tags structure.
 * @param document The JSON document.
 * @param tag The tag with an expression.
 * @return The expression value.
 */
viewexpr_value_t __view_eval_tag(view_copy_tags_t* copy_tags, json_doc_t* document, view_tag_t* tag) {
    view_scope_data_t data = { copy_tags, document, tag };
    const viewexpr_scope_t scope = { __view_scope_resolve, &data, &copy_tags->arena };

    return viewexpr_eval(tag->expr, &scope);
}

/**
 * Writes the value of a {{ }} tag to the output buffer: strings HTML-escaped
 * in VIEW_ESCAPE mode unless the tag ends in raw (NUL bytes as U+FFFD), numbers and booleans in
 * their canonical text form, null and containers as nothing. A tag ending in
 * a safe modifier (nl2br) is written by that modifier.
 *
 * @param copy_tags The copy tags structure with the output buffer and mode.
 * @param expr The tag expression.
 * @param value The value to write.
 * @return void
 */
void __view_write_value(view_copy_tags_t* copy_tags, const viewexpr_node_t* expr, const viewexpr_value_t* value) {
    const viewmodifier_t* root = expr != NULL && expr->type == VIEWEXPR_NODE_MODIFIER ? expr->modifier : NULL;

    if (root != NULL && root->kind == VIEWMOD_SAFE) {
        root->output(&copy_tags->buf, value, copy_tags->escape);
        return;
    }

    switch (value->type)
    {
    case VIEWEXPR_STRING:
    {
        if (value->string == NULL) return;

        const int raw = root != NULL && root->kind == VIEWMOD_RAW;
        viewmodifier_write_text(&copy_tags->buf, value->string, value->length, raw ? VIEW_RAW : copy_tags->escape);

        break;
    }
    case VIEWEXPR_NUMBER:
    {
        char buffer[64];
        const size_t size = viewexpr_number_format(value->number, buffer, sizeof(buffer));

        for (size_t i = 0; i < size; i++)
            bufferdata_push(&copy_tags->buf, buffer[i]);

        break;
    }
    case VIEWEXPR_BOOL:
    {
        const char* string = value->boolean ? "true" : "false";

        for (size_t i = 0; string[i] != 0; i++)
            bufferdata_push(&copy_tags->buf, string[i]);

        break;
    }
    default:
        break;
    }
}

/**
 * Builds the content recursively for a view.
 *
 * @param view The view to build content for.
 * @param document The JSON document to build content with.
 * @param copy_tags The copy tags to use.
 * @param tag The tag to start building content from.
 * @return None.
 */
void __view_build_content_recursive(view_t* view, json_doc_t* document, view_copy_tags_t* copy_tags, view_tag_t* tag) {
    view_tag_t* child = tag;
    while (child) {
        switch (child->type) {
        case VIEW_TAGTYPE_VAR:
        {
            view_tag_t* parent = child->parent;

            size_t size = bufferdata_writed(&parent->result_content);
            const char* content = bufferdata_get(&parent->result_content);
            for (size_t i = child->parent_text_offset; i < child->parent_text_offset + child->parent_text_size && i < size; i++)
                bufferdata_push(&copy_tags->buf, content[i]);

            const viewexpr_value_t value = __view_eval_tag(copy_tags, document, child);
            __view_write_value(copy_tags, child->expr, &value);

            // the value is in the buffer now: what modifiers allocated is no longer needed
            view_arena_reset(&copy_tags->arena);

            if (child->next == NULL) {
                size = bufferdata_writed(&parent->result_content);
                content = bufferdata_get(&parent->result_content);
                for (size_t i = child->parent_text_offset + child->parent_text_size; i < size; i++)
                    bufferdata_push(&copy_tags->buf, content[i]);

                if (child == tag) return;
            }

            child = child->next;

            break;
        }
        case VIEW_TAGTYPE_COND:
        {
            __view_build_content_recursive(view, document, copy_tags, child->child);

            child = child->next;

            break;
        }
        case VIEW_TAGTYPE_COND_IF:
        case VIEW_TAGTYPE_COND_ELSEIF:
        case VIEW_TAGTYPE_COND_ELSE:
        {
            view_tag_t* parent = child->parent;
            view_condition_item_t* tag = (view_condition_item_t*)child;

            int istrue = tag->always_true;
            if (!istrue) {
                const viewexpr_value_t value = __view_eval_tag(copy_tags, document, child);
                istrue = viewexpr_value_istrue(&value);
                view_arena_reset(&copy_tags->arena);
            }

            if (!istrue) {
                if (child->next != NULL) {
                    child = child->next;
                    break;
                }
            }

            size_t size = bufferdata_writed(&parent->parent->result_content);
            const char* content = bufferdata_get(&parent->parent->result_content);
            for (size_t i = parent->parent_text_offset; i < parent->parent_text_offset + parent->parent_text_size && i < size; i++)
                bufferdata_push(&copy_tags->buf, content[i]);

            if (istrue) {
                if (child->child != NULL) {
                    __view_build_content_recursive(view, document, copy_tags, child->child);
                }
                else {
                    const size_t size = bufferdata_writed(&child->result_content);
                    const char* content = bufferdata_get(&child->result_content);
                    for (size_t i = 0; i < size; i++)
                        bufferdata_push(&copy_tags->buf, content[i]);
                }
            }

            if (parent->next == NULL) {
                size = bufferdata_writed(&parent->parent->result_content);
                content = bufferdata_get(&parent->parent->result_content);
                for (size_t i = parent->parent_text_offset + parent->parent_text_size; i < size; i++)
                    bufferdata_push(&copy_tags->buf, content[i]);
            }

            if (istrue) return;

            child = child->next;

            break;
        }
        case VIEW_TAGTYPE_LOOP:
        {
            view_loop_t* tag_for = __view_copy_loop_tag_get(copy_tags, child);
            if (tag_for == NULL)
                tag_for = __view_copy_loop_tag_add(copy_tags, child);

            if (tag_for == NULL)
                return;

            view_tag_t* parent = child->parent;
            size_t size = bufferdata_writed(&parent->result_content);
            const char* content = bufferdata_get(&parent->result_content);
            for (size_t i = child->parent_text_offset; i < child->parent_text_offset + child->parent_text_size && i < size; i++)
                bufferdata_push(&copy_tags->buf, content[i]);

            const viewexpr_value_t loop_value = __view_eval_tag(copy_tags, document, child);
            const json_token_t* token = loop_value.type == VIEWEXPR_TOKEN ? loop_value.token : NULL;

            // a collection is always a document token (modifiers never make
            // containers): what its expression allocated is no longer needed
            view_arena_reset(&copy_tags->arena);
            if (token != NULL) {
                if (token->type == JSON_OBJECT || token->type == JSON_ARRAY) {
                    for (json_it_t it = json_init_it(token); !json_end_it(&it); it = json_next_it(&it)) {
                        // the key is the document's, which outlives the
                        // render: borrowed whole, never copied into a buffer
                        // that would have to cut it
                        if (token->type == JSON_OBJECT) {
                            const char* key = json_it_key(&it);
                            tag_for->key_value = key != NULL ? key : "";
                            tag_for->key_length = key != NULL ? json_string_size(it.key) : 0;
                            tag_for->key_is_index = 0;
                            tag_for->key_index = 0;
                        }
                        else {
                            const int key_index = *(int*)json_it_key(&it);
                            tag_for->key_value = NULL;
                            tag_for->key_length = 0;
                            tag_for->key_is_index = 1;
                            tag_for->key_index = key_index;
                        }

                        tag_for->token = json_it_value(&it);

                        if (child->child != NULL) {
                            __view_build_content_recursive(view, document, copy_tags, child->child);
                        }
                        else {
                            const size_t size = bufferdata_writed(&child->result_content);
                            const char* content = bufferdata_get(&child->result_content);
                            for (size_t i = 0; i < size; i++)
                                bufferdata_push(&copy_tags->buf, content[i]);
                        }
                    }
                }
            }

            if (child->next == NULL) {
                size = bufferdata_writed(&parent->result_content);
                content = bufferdata_get(&parent->result_content);
                for (size_t i = child->parent_text_offset + child->parent_text_size; i < size; i++)
                    bufferdata_push(&copy_tags->buf, content[i]);
            }

            child = child->next;

            break;
        }
        case VIEW_TAGTYPE_INC:
        {
            view_tag_t* parent = child->parent;

            if (parent != NULL) {
                const size_t size = bufferdata_writed(&parent->result_content);
                const char* content = bufferdata_get(&parent->result_content);
                for (size_t i = child->parent_text_offset; i < child->parent_text_offset + child->parent_text_size && i < size; i++)
                    bufferdata_push(&copy_tags->buf, content[i]);
            }

            if (child->child != NULL) {
                __view_build_content_recursive(view, document, copy_tags, child->child);
            }
            else {
                const size_t size = bufferdata_writed(&child->result_content);
                const char* content = bufferdata_get(&child->result_content);
                for (size_t i = 0; i < size; i++)
                    bufferdata_push(&copy_tags->buf, content[i]);
            }

            if (child->next == NULL && parent != NULL) {
                const size_t size = bufferdata_writed(&parent->result_content);
                const char* content = bufferdata_get(&parent->result_content);
                for (size_t i = child->parent_text_offset + child->parent_text_size; i < size; i++)
                    bufferdata_push(&copy_tags->buf, content[i]);
            }

            child = child->next;

            break;
        }
        default:
            // Unknown/corrupt tag type: advance past this node instead of
            // spinning on it forever (CWE-835).
            child = child->next;
            break;
        }
    }
}

/**
 * Initializes a view_copy_tags_t struct.
 *
 * @param copy_tags The view_copy_tags_t struct to initialize.
 * @return void
 */
void __view_copy_loop_tags_init(view_copy_tags_t* copy_tags) {
    if (copy_tags == NULL) return;

    bufferdata_init(&copy_tags->buf);
    arena_init(&copy_tags->arena);
    copy_tags->escape = VIEW_ESCAPE;
    copy_tags->copy = NULL;
    copy_tags->last_copy = NULL;
}

/**
 * Free the resources allocated by a view_copy_tags_t struct.
 *
 * @param copy_tags The view_copy_tags_t struct to free.
 * @return void
 */
void __view_copy_loop_tags_free(view_copy_tags_t* copy_tags) {
    if (copy_tags == NULL) return;

    view_loop_copy_t* copy = copy_tags->copy;
    while (copy != NULL) {
        view_loop_copy_t* next = copy->next;
        free(copy);
        copy = next;
    }

    bufferdata_clear(&copy_tags->buf);
    arena_free(&copy_tags->arena);
}

/**
 * Add a loop tag to the copy tags.
 *
 * @param copy_tags The copy tags to add the loop tag to.
 * @param tag The loop tag to add.
 * @return The added loop tag.
 */
view_loop_t* __view_copy_loop_tag_add(view_copy_tags_t* copy_tags, view_tag_t* tag) {
    view_loop_copy_t* copy = malloc(sizeof * copy);
    if (copy == NULL) {
        printf("__view_copy_loop_tag_add: failed to allocate memory for loop tag copy\n");
        return NULL;
    }

    copy->source_address = (view_tag_t*)tag;
    memcpy(&copy->tag, tag, sizeof(view_loop_t));
    copy->next = NULL;

    if (copy_tags->copy == NULL)
        copy_tags->copy = copy;

    if (copy_tags->last_copy != NULL)
        copy_tags->last_copy->next = copy;

    copy_tags->last_copy = copy;

    return &copy->tag;
}

/**
 * Get the loop tag from the copy tags.
 *
 * @param copy_tags The copy tags to get the loop tag from.
 * @param tag The loop tag to get.
 * @return The loop tag, or NULL if not found.
 */
view_loop_t* __view_copy_loop_tag_get(view_copy_tags_t* copy_tags, view_tag_t* tag) {
    if (tag == NULL) return NULL;

    view_loop_copy_t* copy = copy_tags->copy;
    while (copy) {
        if (copy->source_address == tag) {
            return &copy->tag;
        }

        copy = copy->next;
    }

    return NULL;
}
