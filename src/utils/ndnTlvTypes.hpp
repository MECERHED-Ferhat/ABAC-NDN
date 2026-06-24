#pragma once
#include <cstdint>

/**
 * @brief TLV values used throughout the system
 */
namespace TlvType {
    // Manifest and general message types
    constexpr uint32_t Manifest = 0xF0;
    constexpr uint32_t SegmentCount = 0xF1;
    constexpr uint32_t CurrentSegment = 0xF2;
    constexpr uint32_t AbeNonce = 0xF4;
    constexpr uint32_t AbeCipher = 0xF5;
    constexpr uint32_t ClientUpdate = 0xF6;
    constexpr uint32_t ClientUpdateGamma = 0xF7;
    constexpr uint32_t ClientUpdateRandom = 0xF8;
    constexpr uint32_t StatusResponse = 0xFD;

    // Policy-specific TLV types
    constexpr uint32_t Policy = 0x81C9;
    constexpr uint32_t PolicyString = 0x81CA;
    constexpr uint32_t PolicyC0 = 0x81CB;
    constexpr uint32_t ThresholdNode = 0x81CC;
    constexpr uint32_t LeafNode = 0x81CD;
    constexpr uint32_t Attribute = 0x81CE;
    constexpr uint32_t NodeK = 0x81CF;
    constexpr uint32_t NodeN = 0x81D0;
    constexpr uint32_t C1 = 0x81D1;
    constexpr uint32_t C2 = 0x81D2;
    constexpr uint32_t C3 = 0x81D3;
    constexpr uint32_t Children = 0x81D4;
    constexpr uint32_t SplittedPolicy = 0x81D5;
    constexpr uint32_t TotalSplittedParts = 0x81D6;
    constexpr uint32_t IsModified = 0x81D7;
}