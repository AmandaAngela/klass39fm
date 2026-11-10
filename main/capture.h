#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_wifi.h"

enum { CAPACITY = 1024, BATCH = 32, DWELL_MS = 500, CHANNELS = 13 };
typedef struct __attribute__((packed)) {
    uint32_t id, timestamp;
    uint16_t length, fc, sc;
    int8_t rssi;
    uint8_t channel, tid; // 255 when QoS control is absent
    uint8_t addr[4][6];
    // PHY metadata from the driver's rx_ctrl. Records how a frame was modulated,
    // so captures can show which PHY modes this radio actually delivers.
    uint8_t phy;       // bit0-1 sig_mode, bit2 cwb, bit3 aggregation, bit4 sgi, bit5-6 stbc
    uint8_t mcs;       // 0-76, meaningful when sig_mode is HT or VHT
    uint8_t rate;      // legacy PHY rate encoding, meaningful when sig_mode is non-HT
    int8_t noise_floor;
} observation_t;
typedef struct {
    uint32_t eligible, overflow, malformed, unsupported, rx_errors, high_water;
} capture_stats_t;
void capture_callback(void *buffer, wifi_promiscuous_pkt_type_t kind);
void capture_configure(const uint8_t target[6]);
void capture_enable(bool enabled);
uint8_t capture_detected_channel(void);
size_t capture_take(observation_t *dest, size_t limit);
capture_stats_t capture_stats(void);
