// fishhook.h
// Copyright (c) Meta Platforms, Inc. and affiliates. (BSD License)
// Minimal rebind_symbols API for C function hooking

#ifndef fishhook_h
#define fishhook_h

#include <stddef.h>
#include <stdint.h>

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

// Rebind symbols in all loaded images
int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);

// Rebind symbols in a specific image
int rebind_symbols_image(void *header, intptr_t slide,
                         struct rebinding rebindings[], size_t rebindings_nel);

#endif
