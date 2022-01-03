#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

struct Node
{
    struct Node* next;
    int value;
};

void print_linked_list(struct Node* head);

struct Node* init_linked_list_node(int value);
void free_linked_list_node(struct Node* node);

struct Node* append_linked_list(struct Node* head, struct Node* item);
struct Node* prepend_linked_list(struct Node* head, struct Node* item);
struct Node* insert_linked_list(struct Node* head, struct Node* item, int index);

struct Node* pop_linked_list(struct Node* head);
struct Node* delete_linked_list_node_index(struct Node* head, int index);

#ifdef __cplusplus
}
#endif