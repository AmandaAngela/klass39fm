#include <stdio.h>
#include <string.h>
#include "capture.h"
#include "transport.h"
#include "esp_app_desc.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_rom_crc.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

// WFS2 frames use little-endian integers. Only this task writes protocol bytes.
typedef struct __attribute__((packed)) {
    char magic[4];
    uint8_t version, kind;
    uint16_t bytes;
    uint32_t token, serial;
} header_t;
typedef struct __attribute__((packed)) {
    capture_stats_t capture;
    uint32_t sent, tx_errors, tx_lost, tune_errors;
    uint64_t uptime_us;
    int8_t mode; // -1 scan, 0 automatic, 1..13 fixed
    uint8_t channel, locked;
    uint8_t firmware_sha[32];
    char idf[32], target[16];
} status_t;
// Version 3 adds four PHY bytes per observation (41 -> 45). The magic word stays
// "WFS2" so a host resynchronising a version-2 archive still finds frame starts;
// the version byte is what selects the record layout.
_Static_assert(sizeof(observation_t) == 45 && sizeof(header_t) == 16 &&
               sizeof(status_t) == 131, "wire schema mismatch");

static struct {
    header_t header;
    union {
        observation_t packets[BATCH];
        status_t status;
    } body;
    uint8_t trailer[4];
} frame;
_Static_assert(offsetof(typeof(frame), body) == 16, "wire header padding");

static uint32_t token, serial_no, sent, tx_errors, tx_lost, tune_errors;
static observation_t pending[BATCH];
static size_t pending_count;
static int mode;
static uint8_t channel;
static bool locked;
static int64_t next_hop, next_status;

static bool send_frame(char kind, size_t bytes)
{
    frame.header = (header_t){.magic = {'W','F','S','2'}, .version = 3, .kind = kind,
        .bytes = bytes, .token = token, .serial = serial_no};
    size_t length = sizeof(header_t) + bytes;
    uint32_t crc = esp_rom_crc32_le(0, (uint8_t *)&frame, length);
    memcpy((uint8_t *)&frame + length, &crc, sizeof(crc));
    if (transport_write(&frame, length + sizeof(crc)) == length + sizeof(crc)) {
        serial_no++;
        return true;
    }
    tx_errors++;
    return false;
}

static void status(char kind)
{
    status_t *s = &frame.body.status;
    *s = (status_t){.capture = capture_stats(), .sent = sent, .tx_errors = tx_errors,
        .tx_lost = tx_lost, .tune_errors = tune_errors, .uptime_us = esp_timer_get_time(),
        .mode = mode, .channel = channel, .locked = locked, .target = CONFIG_IDF_TARGET};
    const esp_app_desc_t *app = esp_app_get_description();
    memcpy(s->firmware_sha, app->app_elf_sha256, sizeof(s->firmware_sha));
    memcpy(s->idf, app->idf_ver, sizeof(s->idf));
    send_frame(kind, sizeof(*s));
}

static size_t send_batch(void)
{
    if (!pending_count) pending_count = capture_take(pending, BATCH);
    size_t n = pending_count;
    if (!n) return 0;
    memcpy(frame.body.packets, pending, n * sizeof(*pending));
    if (!send_frame('P', n * sizeof(*pending))) return 0;
    sent += n;
    pending_count = 0;
    return n;
}

static void finish(void)
{
    capture_enable(false);
    int64_t deadline = esp_timer_get_time() + 2000000;
    for (;;) {
        size_t delivered = send_batch();
        if (!delivered && !pending_count) break;
        if (!delivered && esp_timer_get_time() >= deadline) {
            // Bound STOP/replacement even if the host disappeared. No new records
            // can enter the ring after capture_enable(false).
            do {
                tx_lost += pending_count;
                pending_count = capture_take(pending, BATCH);
            } while (pending_count);
            break;
        }
        vTaskDelay(1);
    }
    status('E');
    token = 0;
}

static bool tune(uint8_t wanted)
{
    // Use a fixed 20 MHz receive bandwidth for comparable observations.
    if (esp_wifi_set_channel(wanted, WIFI_SECOND_CHAN_NONE) == ESP_OK) {
        channel = wanted;
        return true;
    }
    tune_errors++;
    return false;
}

static void command(const char *line)
{
    unsigned long id;
    int requested;
    uint8_t mac[6];
    char extra;
    if (sscanf(line, "STOP %8lx %c", &id, &extra) == 1 && token && id == token) {
        finish();
        return;
    }
    if (sscanf(line, "START %8lx %d %2hhx%2hhx%2hhx%2hhx%2hhx%2hhx %c",
               &id, &requested, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5],
               &extra) != 8 || !id || requested < -1 || requested > CHANNELS) return;
    if (id == token) return; // repeated command cannot reset a live session
    if (token) finish(); // allow a fresh recorder after a host disconnect
    capture_configure(mac);
    token = id;
    serial_no = sent = tx_errors = tx_lost = tune_errors = 0;
    mode = requested;
    locked = false;
    bool tuned = tune(mode > 0 ? mode : 1);
    locked = tuned && mode > 0;
    next_hop = esp_timer_get_time() + DWELL_MS * 1000;
    next_status = esp_timer_get_time() + 1000000;
    capture_enable(tuned);
    status('B');
    if (!tuned) finish();
}

static void poll_commands(void)
{
    static char line[80];
    static size_t used;
    static bool discard;
    char input[80];
    int n = transport_read(input, sizeof(input));
    for (int i = 0; i < n; ++i) {
        if (input[i] == '\n') {
            if (!discard) {
                line[used] = '\0';
                command(line);
            }
            discard = false;
            used = 0;
        } else if (used < sizeof(line) - 1) {
            line[used++] = input[i];
        } else {
            discard = true;
        }
    }
}

static void channel_step(int64_t now)
{
    if (locked || now < next_hop) return;
    uint8_t found = mode == 0 ? capture_detected_channel() : 0;
    uint8_t requested = found ? found : channel % CHANNELS + 1;
    locked = tune(requested) && found;
    next_hop = now + DWELL_MS * 1000;
    if (token) status('S');
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init()); // report NVS failures, never erase automatically
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&config));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    const wifi_country_t country = {.cc = "MY", .schan = 1, .nchan = CHANNELS,
        .max_tx_power = 20, .policy = WIFI_COUNTRY_POLICY_MANUAL};
    ESP_ERROR_CHECK(esp_wifi_set_country(&country));
    // Control frames go out at legacy rates for compatibility, so they stay readable
    // when a modern client's high-throughput payload does not. FCSFAIL makes frames
    // that arrive but fail checksum countable in rx_errors; they are never stored.
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA |
                       WIFI_PROMIS_FILTER_MASK_CTRL | WIFI_PROMIS_FILTER_MASK_FCSFAIL};
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    const wifi_promiscuous_filter_t control = {
        .filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL};
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_ctrl_filter(&control));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(capture_callback));
    transport_init();
    ESP_ERROR_CHECK(esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE));
    channel = 1;
    next_hop = esp_timer_get_time() + DWELL_MS * 1000;
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    while (true) {
        poll_commands();
        int64_t now = esp_timer_get_time();
        channel_step(now);
        if (token) {
            // Bound each service pass even when the callback continually refills the ring.
            for (unsigned i = 0; i < 4 && send_batch() == BATCH; ++i) {}
            if (now >= next_status) {
                status('S');
                next_status = now + 1000000;
            }
        }
        vTaskDelay(1); // let the monitored idle task run under sustained load
    }
}
