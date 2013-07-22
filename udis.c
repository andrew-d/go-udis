#include "_cgo_export.h"
#include <string.h>
#include <udis86.h>

typedef struct _opaque_data_t {
    void* input_hook_pointer;
    void* sym_resolver_pointer;
} opaque_data_t;

opaque_data_t* get_opaque_data(struct ud* inp) {
    // Get the opaque data - will return NULL if none.
    opaque_data_t* opaque = (opaque_data_t*)ud_get_user_opaque_data(inp);

    // If none, we allocate it and then set it on the structure.
    if( NULL == opaque ) {
        opaque = (opaque_data_t*)malloc(sizeof(opaque_data_t));
        memset(opaque, 0, sizeof(opaque_data_t));

        ud_set_user_opaque_data(inp, (void*)opaque);
    }

    // Return the opaque data.
    return opaque;
}

void free_opaque_data(struct ud* inp) {
    opaque_data_t* opaque = (opaque_data_t*)ud_get_user_opaque_data(inp);

    if( NULL != opaque ) {
        free(opaque);
        ud_set_user_opaque_data(inp, NULL);
    }
}

// This wrapper is used to proxy to the input hook pointer.
int input_hook_wrapper(struct ud* inp) {
    opaque_data_t* data = get_opaque_data(inp);
    return goInputHookCallback((void*)inp, data->input_hook_pointer);
}

// Set the input hook in the udis86 structure.
void setup_input_hook(struct ud* inp, void* hook) {
    opaque_data_t* data = get_opaque_data(inp);

    ud_set_input_hook(inp, &input_hook_wrapper);
    data->input_hook_pointer = hook;
}

// This wrapper is used to proxy to the symbol resolver pointer.
const char* sym_resolver_wrapper(struct ud* inp, uint64_t addr, int64_t *offset) {
    opaque_data_t* data = get_opaque_data(inp);
    return goSymResolverCallback((void*)inp, addr, offset, data->sym_resolver_pointer);
}

// Set the sym resolver in the udis86 structure.
void setup_sym_resolver(struct ud* inp, void* hook) {
    opaque_data_t* data = get_opaque_data(inp);

    ud_set_sym_resolver(inp, &sym_resolver_wrapper);
    data->sym_resolver_pointer = hook;
}
