#ifdef ESP32
#ifndef MEMORY_CHECK_HPP
#define MEMORY_CHECK_HPP

#include <Arduino.h>

enum class MemCheckResult {
    OK,
    LOW_HEAP,
    LOW_STACK,
    CRITICAL
};

inline MemCheckResult checkMemory(const char* location, uint32_t minHeap = 16384, uint32_t minStack = 512) {
    UBaseType_t stackMark = uxTaskGetStackHighWaterMark(NULL);
    uint32_t freeHeap = ESP.getFreeHeap();
    
    // heap_caps_print_heap_info(MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    
    log_d("Memory check at %s:", location);
    log_d("Stack watermark: %d words", stackMark);
    log_d("Free heap: %d bytes", freeHeap);
    log_v("Free heap (largest block): %d bytes", ESP.getMaxAllocHeap());
    log_v("Used heap: %d bytes", ESP.getHeapSize() - freeHeap);
    log_d("Free PSRAM: %d bytes", ESP.getFreePsram());
    log_v("Free PSRAM (largest block): %d bytes", ESP.getMaxAllocPsram());
    log_v("Used PSRAM: %d bytes", ESP.getPsramSize() - ESP.getFreePsram());
    
    if (stackMark < 256) {
        log_w("Stack space is CRITICAL at %s!", location);
        return MemCheckResult::CRITICAL;
    }

    if (freeHeap < 1024) {
        log_w("heap space is CRITICAL at %s!", location);
        return MemCheckResult::CRITICAL;
    }
    
    if (stackMark < minStack) {
        log_w("Low stack at %s", location);
        return MemCheckResult::LOW_STACK;
    }
    
    if (freeHeap < minHeap) {
        log_w("Low heap at %s", location);
        return MemCheckResult::LOW_HEAP;
    }
    
    return MemCheckResult::OK;
}

#endif // MEMORY_CHECK_HPP
#endif // ESP32