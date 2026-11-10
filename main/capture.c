#include "capture.h"
#include <string.h>
#include "freertos/FreeRTOS.h"

static portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
static observation_t ring[CAPACITY];
static size_t head, used;
static bool active;
static uint8_t camera[6];
static bool has_target;
static uint8_t detected;
static capture_stats_t counts;

void capture_configure(const uint8_t target[6])
{
    portENTER_CRITICAL(&lock);
    active = false;
    head = used = detected = 0;
    counts = (capture_stats_t){0};
    memcpy(camera, target, 6);
    const uint8_t empty[6] = {0};
    has_target = memcmp(target, empty, sizeof(empty)) != 0;
    portEXIT_CRITICAL(&lock);
}

void capture_enable(bool enabled)
{
    portENTER_CRITICAL(&lock);
    active = enabled;
    portEXIT_CRITICAL(&lock);
}

uint8_t capture_detected_channel(void)
{
    portENTER_CRITICAL(&lock);
    uint8_t result = detected;
    portEXIT_CRITICAL(&lock);
    return result;
}

capture_stats_t capture_stats(void)
{
    portENTER_CRITICAL(&lock);
    capture_stats_t result = counts;
    portEXIT_CRITICAL(&lock);
    return result;
}

size_t capture_take(observation_t *dest, size_t limit)
{
    portENTER_CRITICAL(&lock);
    size_t n = used < limit ? used : limit;
    size_t first = CAPACITY - head;
    if (first > n) first = n;
    memcpy(dest, ring + head, first * sizeof(*dest));
    memcpy(dest + first, ring, (n - first) * sizeof(*dest));
    head = (head + n) % CAPACITY;
    used -= n;
    portEXIT_CRITICAL(&lock);
    return n;
}

enum parse_result { VALID, MALFORMED, UNSUPPORTED, RX_ERROR };
static enum parse_result parse(const wifi_promiscuous_pkt_t *pkt,
                               wifi_promiscuous_pkt_type_t kind, observation_t *r)
{
    if (!pkt) return MALFORMED;
    if (kind != WIFI_PKT_MGMT && kind != WIFI_PKT_DATA && kind != WIFI_PKT_CTRL)
        return UNSUPPORTED;
    if (pkt->rx_ctrl.rx_state) return RX_ERROR;
    const uint8_t *f = pkt->payload;
    unsigned length = pkt->rx_ctrl.sig_len; // includes four-byte FCS
    if (length < 10 + 4) return MALFORMED;  // ACK and CTS are the shortest frames
    uint16_t fc = f[0] | ((uint16_t)f[1] << 8);
    unsigned type = (fc >> 2) & 3;
    unsigned expected = kind == WIFI_PKT_DATA ? 2 : kind == WIFI_PKT_CTRL ? 1 : 0;
    if ((fc & 3) || type != expected) return UNSUPPORTED;
    r->timestamp = pkt->rx_ctrl.timestamp;
    r->rssi = pkt->rx_ctrl.rssi;
    r->length = length;
    r->channel = pkt->rx_ctrl.channel;
    r->phy = (pkt->rx_ctrl.sig_mode & 3) | (pkt->rx_ctrl.cwb << 2) |
             (pkt->rx_ctrl.aggregation << 3) | (pkt->rx_ctrl.sgi << 4) |
             ((pkt->rx_ctrl.stbc & 3) << 5);
    r->mcs = pkt->rx_ctrl.mcs;
    r->rate = pkt->rx_ctrl.rate;
    r->noise_floor = pkt->rx_ctrl.noise_floor;
    r->fc = fc;
    if (type == 1) {
        // Control frames carry no sequence control. The receiver address is always
        // present; a transmitter address only in the longer variants (RTS, BlockAck,
        // BlockAckReq, PS-Poll, CF-End), so the short ones leave addr2 zeroed.
        memcpy(r->addr[0], f + 4, 6);
        if (length >= 16 + 4) memcpy(r->addr[1], f + 10, 6);
        r->tid = 255;
        return VALID;
    }
    if (length < 24 + 4) return MALFORMED;
    bool four = type == 2 && (fc & 0x300) == 0x300;
    bool qos = type == 2 && (fc & 0x80);
    unsigned qos_offset = four ? 30 : 24;
    unsigned header = qos_offset + (qos ? 2 : 0);
    if ((fc & 0x8000) && (qos || type == 0)) header += 4;
    if (length < header + 4) return MALFORMED;
    r->sc = f[22] | ((uint16_t)f[23] << 8);
    r->tid = qos ? f[qos_offset] & 15 : 255;
    memcpy(r->addr, f + 4, 18);
    if (four) memcpy(r->addr[3], f + 24, 6);
    return VALID;
}

void capture_callback(void *buffer, wifi_promiscuous_pkt_type_t kind)
{
    observation_t r = {0};
    enum parse_result result = parse(buffer, kind, &r);
    portENTER_CRITICAL(&lock);
    if (result == VALID && has_target && !detected && memcmp(r.addr[1], camera, 6) == 0 &&
        r.channel >= 1 && r.channel <= CHANNELS) detected = r.channel;
    if (active) {
        switch (result) {
        case MALFORMED: counts.malformed++; break;
        case UNSUPPORTED: counts.unsupported++; break;
        case RX_ERROR: counts.rx_errors++; break;
        case VALID:
            r.id = ++counts.eligible; // assign before overflow so gaps remain visible
            if (used == CAPACITY) {
                counts.overflow++;
            } else {
                ring[(head + used) % CAPACITY] = r;
                if (++used > counts.high_water) counts.high_water = used;
            }
            break;
        }
    }
    portEXIT_CRITICAL(&lock);
}
