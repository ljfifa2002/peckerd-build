#ifndef NINJECTOR_SYMBI_STUB_H
#define NINJECTOR_SYMBI_STUB_H

#include "stub_src/stub.h"
#if defined(__aarch64__)
#include "stub_src/generated_stub.h"
#else
#include "stub_src/generated_stub_arm.h"
#endif

#endif // NINJECTOR_SYMBI_STUB_H
