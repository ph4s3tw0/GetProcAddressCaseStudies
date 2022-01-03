#include "linked_list.h"

struct Node* init_linked_list_node(int value)
{
    struct Node* head = NULL;

    head = malloc(sizeof(*head));

    head->value = value;
    head->next = NULL;

    return head;
}

void free_linked_list_node(struct Node* node)
{
    free(node);
}

struct Node* append_linked_list(struct Node* head, struct Node* item)
{
    struct Node* original = head;

    /*
        Walk through list until we hit the end,
        then link item to end of list.
    */
    do
    {
        if (head->next == NULL)
        {
            head->next = item;
            break;
        }
    } while ((head = head->next));

    return original;
}

struct Node* prepend_linked_list(struct Node* head, struct Node* item)
{
    /*
        Prepending can basically be boiled down to
        appending the head of the linked list to the end of
        the item linked list
    */
    return append_linked_list(item, head);
}

struct Node* insert_linked_list(struct Node* head, struct Node* item, int index)
{
    struct Node* original = head;
    struct Node* next = NULL;

    /*
        If index is 0, we just prepend to list
    */
    if (index == 0)
        return prepend_linked_list(head, item);

    /*
        Walk the linked list until we hit our index
    */
    for (int i = 0; i < index - 1; i++)
    {
        if (head->next == NULL)
            break;

        head = head->next;
    }

    /*
        Append the next node of the linked list to the
        tail of the new linked list.
    */
    next = head->next;
    head->next = item;
    append_linked_list(head->next, next);

    return original;
}

struct Node* pop_linked_list(struct Node* head)
{
    struct Node* previous = NULL;

    /*
        Walk the linked list until the tail,
        then unlink the tail and return it.
    */
    do
    {
        if (head->next == NULL)
        {
            if (previous)
                previous->next = NULL;
            return head;
        }
        else
            previous = head;
    } while ((head = head->next));

    return NULL;
}

struct Node* delete_linked_list_node_index(struct Node* head, int index)
{
    struct Node* original = head;
    struct Node* previous = NULL;

    /*
        If index == 0, make new head the next entry
        and return new head.
    */
    if (index == 0)
    {
        original = head->next;
        free_linked_list_node(head);
        return original;
    }

    /*
        Walk the linked list until the index is reached.
    */
    for (int i = 0; i < index - 1; i++)
    {
        if (head->next == NULL)
            break;

        previous = head;
        head = head->next;
    }

    /*
        Link the previous node to the next node and
        free the current node.
    */
    previous->next = head->next;
    free_linked_list_node(head);

    return original;
}

void print_linked_list(struct Node* head)
{
    int i = 0;

    do
    {
        printf("%d:\t%d\n", i++, head->value);
    } while ((head = head->next));
}