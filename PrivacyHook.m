//
// EmptyHook.m — completely empty, no hooks, just to test if dylib injection itself crashes
//
// If this empty dylib also crashes, the problem is in the injection process or
// JD's code integrity check, not in our hook code.
//

__attribute__((constructor))
static void initEmptyHook(void) {
    // Do nothing
}
