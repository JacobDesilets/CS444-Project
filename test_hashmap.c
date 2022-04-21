#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define NUM_VARIABLES 26
#define NUM_SESSIONS 128
#define NUM_BROWSER 128
#define DATA_DIR "./sessions"
#define SESSION_PATH_LEN 128
#define HASH_SIZE 128

typedef struct session_struct {
    bool in_use;
    bool variables[NUM_VARIABLES];
    double values[NUM_VARIABLES];
} session_t;

typedef struct entry_struct {
    session_t* session;
    int key;
    struct entry_struct* collision;
} hash_entry_t;

typedef struct hashmap_struct {
    hash_entry_t **entries;
} hashmap_t;

int hash(int key) {
    return key % HASH_SIZE;
}

hashmap_t* create_hashmap() {
    hashmap_t* hashmap = malloc(sizeof(hashmap_t));
    hashmap -> entries = malloc(sizeof(hash_entry_t*) * HASH_SIZE);

    // Initialize each entry to NULL
    for (int i = 0; i < HASH_SIZE; ++i) {
        hashmap -> entries[i] = NULL;
    }

    return hashmap;
}

hash_entry_t* set_hash_entry(hashmap_t* hashmap, int key, session_t* data) {
    int hash_index = hash(key);
    hash_entry_t* entry = hashmap -> entries[hash_index];

    if (entry == NULL) {
        hashmap -> entries[hash_index] = malloc(sizeof(hash_entry_t*));
        hash_entry_t* entry = hashmap -> entries[hash_index];
        entry -> session = malloc(sizeof(session_t*));
        memcpy(entry -> session, data, sizeof(session_t*));
        entry -> key = key;
        entry -> collision = NULL;

        return entry;
    }

    hash_entry_t* previous;

    while (entry != NULL) {
        if (entry -> key == key) {
            entry -> session = data;
            return entry;
        }

        previous = entry;
        entry = previous -> collision;

    }

    hash_entry_t* new_entry = malloc(sizeof(hash_entry_t*));
    new_entry -> session = malloc(sizeof(session_t*));
    memcpy(new_entry -> session, data, sizeof(session_t*));
    new_entry -> key = key;
    new_entry -> collision = NULL;

    previous -> collision = new_entry;

}

hash_entry_t* get_hash_entry(hashmap_t* hashmap, int key) {
    int hash_index = hash(key);
    hash_entry_t* entry = hashmap -> entries[hash_index];

    while (entry != NULL) {
        if (entry -> key == key) {
            return entry;
        }
        entry = entry -> collision;
    }

    return NULL;
}

bool destroy_hash_entry(hashmap_t* hashmap, int key) {
    int hash_index = hash(key);
    hash_entry_t* entry = hashmap -> entries[hash_index];

    if (entry -> collision == NULL)
    {
        free(entry -> session);
        free(entry);
        return true;
    }

    hash_entry_t* previous = NULL;

    while (entry != NULL) {
        if (entry -> key == key) {
            hash_entry_t* next = entry -> collision;
            if (next != NULL) {
                if (previous = NULL) {
                    hash_entry_t* new_entry;
                    new_entry -> session = entry -> session;
                    new_entry -> collision = next -> collision;
                    new_entry -> key = key;
                    hashmap -> entries[hash_index] = new_entry;
                } else {
                    previous -> collision = next;
                }
            }
            free(entry -> collision);
            free(entry -> session);
            free(entry);
            entry = NULL;

            return true;
        }
        previous = entry;
        entry = entry -> collision;
    }

    return false;
}


int main() {
    session_t session = {NULL, NULL, NULL};
    hashmap_t* hm = create_hashmap();
    
    set_hash_entry(hm, 1, &session);
    set_hash_entry(hm, 129, &session);
    hash_entry_t* entry = get_hash_entry(hm, 129);
    if (entry != NULL) {
        printf("YES!\n");
        printf("%d\n", entry->key);
    } else {
        printf("NO!\n");
    }

    destroy_hash_entry(hm, 129);
    entry = get_hash_entry(hm, 129);
    if (entry != NULL) {
        printf("YES!\n");
        printf("%d\n", entry->key);
    } else {
        printf("NO!\n");
    }

    return 0;
}