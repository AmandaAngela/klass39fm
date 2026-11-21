/*
  ESP32-C5 wifi sniffer -> Wireshark view
  ESP32-C5 802.11 promiscuous sniffer  ->  serial  ->  host/sniff_host.py  ->  pcap / CSV / live Wireshark

  - Does not join any network (WIFI_MODE_NULL + promiscuous).
  - Two modes, both driven by the host over serial:
      fixed channel  "c<N>\n"            lock to channel N (2.4 GHz 1-13 or 5 GHz 36-177), 20 MHz, stops hopping
                     "c<N>,a\n" "c<N>,b\n" same, 40 MHz with the secondary channel above / below N
                                         (hopping is always 20 MHz)
      hop / scan     "h<dwell>,<band>,<widths>\n" visit every channel for <dwell> ms; band 0 = both,
                                         2 = 2.4 GHz, 5 = 5 GHz; widths 0 = 20 MHz only, 1 = every channel
                                         at 20 MHz, then every 40 MHz pair
                     "x\n"               stop hopping, stay on the current channel
    Every channel change and every completed sweep is reported as a REC_EVENT record.
  - Frames are copied into a ring buffer in the Wi-Fi callback; loop() does all serial writes,
    so slow serial never blocks the Wi-Fi task. Overflows are counted and reported, not hidden.
  - Only the first SNAPLEN bytes of each frame are sent (payload is encrypted anyway);
    the true on-air length is kept in orig_len.
  - Timestamps: rx_ctrl.timestamp (radio RX time, us) and esp_timer at callback (us), both sent.

  Arduino IDE setup:
    Board manager: "esp32 by Espressif" >= 3.3.0 (first release with ESP32-C5 support)
    Board: "ESP32C5 Dev Module"
    USB CDC On Boot: "Enabled"  if you plug into the chip's native USB port (fast, baud ignored)
                     "Disabled" if you plug into the USB-UART bridge port (then SERIAL_BAUD matters)
    Core Debug Level: "None"    (log text would share the serial link; host skips it, but it wastes bandwidth)
    Do NOT open the Arduino Serial Monitor while the host script runs (only one program can own the port).

  Record format (little-endian, packed, 22-byte header + cap_len bytes), must match sniff_host.py:
    u8 magic0=0xA5, u8 magic1=0x5A, u8 type, u8 channel,
    u32 rx_ts, u32 cb_ts, u16 orig_len, u16 cap_len,
    i8 rssi, i8 noise_floor, u8 phy_format, u8 pkt_type, u16 sum   (sum = byte sum of header with sum=0, plus payload)
*/

#include <Arduino.h>
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "freertos/ringbuf.h"
#include "soc/soc_caps.h"

// ===================== SETTINGS =====================
#define START_CHANNEL   6          // channel used at boot; host -c overrides it // default: channel 6 on 20mhz bandwidth avoids interference
#define SNAPLEN         128        // bytes of each frame forwarded (MAC header + CCMP header + beacon SSID fit)

// 802.11 frames: mgmt/data/ctrl. 1 = keep, 0 = don't keep
#define CAPTURE_MGMT    1          // beacons, probes, assoc... (needed for BSSID->SSID mapping)
#define CAPTURE_DATA    1          // the camera stream itself
#define CAPTURE_CTRL    0          // ACK/RTS/CTS/BlockAck; ESP32 control capture is partial

#define SERIAL_BAUD     2000000    // only used on a USB-UART bridge port
#define RINGBUF_BYTES   (96 * 1024)   // queue size; for the ring buffer between the promiscuous callback and the data transport
#define STATS_MS        1000        // how often to send stats
#define COUNTRY_CODE    "SG"         // can prob find a way to change this according to traveller's location
// ====================================================

// Channels visited when hopping. Ones the radio rejects (country rules) are skipped automatically.
// 2.4 GHz
static const uint8_t CH_24[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
// 5 GHz
#if SOC_WIFI_SUPPORT_5G
static const uint8_t CH_5[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
                               124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177};
#endif
// One hop = a channel plus its width: sec 0 = 20 MHz, 1 = 40 MHz secondary above, 2 = 40 MHz below
// (same numbering as wifi_second_chan_t).
struct HopEntry { uint8_t ch, sec; };
static HopEntry hopList[128];
static uint8_t  hopCount = 0, hopIdx = 0;
static bool     hopping = false;
static uint16_t hopDwellMs = 200;
static uint32_t hopLast = 0, hopSweeps = 0;

// Record Header: a 22-byte wrapper over the 802.11 frame for the USB cable -> PC
// start marker to find where each record begins
static const uint8_t MAGIC0 = 0xA5, MAGIC1 = 0x5A;    
// values for 'type' variable in RecHdr
// REC_FRAME: 802.11 frame
// REC_STATS: 13 bytes of counters (frames, drops, free buffer space, channel)
// REC_TEXT: an ASCII msg (eg. "channel 6")
// REC_EVENT: 9-byte channel-change/sweep-done/hop-stopped event (event, channel, sweeps, dwell, width)
// Frame records carry the listening width in the high 4 bits of pkt_type (0 = 20 MHz, 1/2 = 40 MHz above/below)
enum : uint8_t { REC_FRAME = 0, REC_STATS = 1, REC_TEXT = 2, REC_EVENT = 3 };
// event codes for 'REC_EVENT', used by host scanner to count visits per channel / finished sweeps
enum : uint8_t { EV_CHANNEL = 1, EV_SWEEP_DONE = 2, EV_HOP_STOP = 3 };

struct __attribute__((packed)) RecHdr {
  uint8_t  magic0, magic1, type, channel;
  uint32_t rx_ts;      // [rx_ctrl.timestamp] in µs; time the radio received the frame
  uint32_t cb_ts;      // [esp_timer_get_time()] at callback, µs (low 32 bits); time the callback ran
  uint16_t orig_len;   // [rx_ctrl.sig_len − 4]; 802.11 frame length on air, FCS excluded
  uint16_t cap_len;    // number of bytes that follow this header (802.11 frame size)
  int8_t   rssi;       // [rx_ctrl.rssi]; signal strength in dBm
  int8_t   noise;      // [rx_ctrl.noise_floor]; noise floor, dBm
  uint8_t  phy_format; // [rx_ctrl.cur_bb_format]; PHY format: 0 = 11b, 1 = 11a/g, 2 = HT (11n), 3 = VHT (11ac), 4–7 = HE (11ax) variants
  uint8_t  pkt_type;   // 0 mgmt, 1 ctrl, 2 data
  uint16_t sum;        // 16-bit byte-sum checksum of header + payload
};
static_assert(sizeof(RecHdr) == 22, "RecHdr must be 22 bytes (host script depends on it)");

// Global vars
static RingbufHandle_t rb = nullptr;
static volatile uint8_t  curChannel = START_CHANNEL;
static volatile uint8_t  curSecond = 0;  // 0 = 20 MHz, 1 = 40 MHz secondary above, 2 = below
static volatile uint32_t nFrames = 0;   // frames queued
static volatile uint32_t nDrops  = 0;   // frames lost because the ring buffer was full

// Sums up all the bytes into a 16-bit checksum
static uint16_t sum16(const uint8_t *p, size_t n, uint16_t s = 0) {
  while (n--) s += *p++;
  return s;
}

// ---------- Wi-Fi task context: copy frames ----------
// promiscuous-mode callback; runs inside the WiFi task for every received frame
static void snifferCb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type == WIFI_PKT_MISC) return; // skips MISC (malformed) frames
  const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
  const wifi_pkt_rx_ctrl_t &rc = pkt->rx_ctrl;

  uint16_t len = rc.sig_len;
  len = (len > 4) ? (uint16_t)(len - 4) : 0;   // compute frame length without the additional FCS
  if (len == 0) return;
  uint16_t cap = (len < SNAPLEN) ? len : SNAPLEN; // cap length at SNAPLEN

  void *slot = nullptr;
  if (xRingbufferSendAcquire(rb, &slot, sizeof(RecHdr) + cap, 0) != pdTRUE || !slot) {
    nDrops = nDrops + 1;
    return;
  }
  // fill in a RecHdr with info from rx_ctrl
  RecHdr *h = (RecHdr *)slot;
  h->magic0   = MAGIC0;
  h->magic1   = MAGIC1;
  h->type     = REC_FRAME;
  h->channel  = curChannel;
  h->rx_ts    = rc.timestamp;
  h->cb_ts    = (uint32_t)esp_timer_get_time();
  h->orig_len = len;
  h->cap_len  = cap;
  h->rssi     = rc.rssi;
  h->noise    = rc.noise_floor;   // if your core version lacks this field, replace with 0
  h->phy_format = rc.cur_bb_format;
  h->pkt_type = (uint8_t)type | (uint8_t)(curSecond << 4);   // low 4 bits: frame kind, high 4: width (curSecond)
  h->sum      = 0;
  uint8_t *payload = (uint8_t *)slot + sizeof(RecHdr);

  // copy frame bytes
  memcpy(payload, pkt->payload, cap);
  h->sum = sum16((const uint8_t *)slot, sizeof(RecHdr) + cap);
  xRingbufferSendComplete(rb, slot);
  nFrames = nFrames + 1;
}

// ---------- loop() context: write to Serial ----------
static void emitRecord(uint8_t type, const uint8_t *data, uint16_t n) {
  RecHdr h = {};
  h.magic0 = MAGIC0; h.magic1 = MAGIC1; h.type = type; h.channel = curChannel;
  h.cb_ts = (uint32_t)esp_timer_get_time();
  h.orig_len = n; h.cap_len = n;
  h.sum = sum16(data, n, sum16((const uint8_t *)&h, sizeof(h)));
  Serial.write((const uint8_t *)&h, sizeof(h));
  if (n) Serial.write(data, n);
}

static void emitText(const char *fmt, ...) {
  char msg[160];
  va_list ap; va_start(ap, fmt);
  int n = vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  if (n < 0) return;
  emitRecord(REC_TEXT, (const uint8_t *)msg, (uint16_t)min(n, (int)sizeof(msg) - 1));
}

static void emitStats() {
  struct __attribute__((packed)) { uint32_t frames, drops, rbFree; uint8_t ch; } s;
  s.frames = nFrames; s.drops = nDrops;
  s.rbFree = (uint32_t)xRingbufferGetCurFreeSize(rb);
  s.ch = curChannel;
  emitRecord(REC_STATS, (const uint8_t *)&s, sizeof(s));
}

static void emitEvent(uint8_t ev) {
  struct __attribute__((packed)) { uint8_t ev, ch; uint32_t sweeps; uint16_t dwell; uint8_t sec; } e;
  e.ev = ev; e.ch = curChannel; e.sweeps = hopSweeps; e.dwell = hopDwellMs; e.sec = curSecond;
  emitRecord(REC_EVENT, (const uint8_t *)&e, sizeof(e));
}

// Check that the channel exists on the wifi chip
static bool validChannel(int ch) {
  if (ch >= 1 && ch <= 14) return true;
#if SOC_WIFI_SUPPORT_5G
  if (ch >= 36 && ch <= 177) return true;
#endif
  return false;
}

// Sets the channel to listen on. quiet = no text message (used while hopping).
// second = WIFI_SECOND_CHAN_NONE for 20 MHz, or ABOVE / BELOW to also listen on the neighbouring
// 20 MHz channel, which is needed to receive 40 MHz frames (must match the router's 40 MHz setup).
static bool setChannel(int ch, bool quiet = false, wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE) {
  if (!validChannel(ch)) { emitText("channel %d not valid on this chip", ch); return false; }
  esp_err_t e = esp_wifi_set_channel((uint8_t)ch, second);
  const char *width = second == WIFI_SECOND_CHAN_ABOVE ? "40 MHz, secondary above"
                    : second == WIFI_SECOND_CHAN_BELOW ? "40 MHz, secondary below" : "20 MHz";
  if (e != ESP_OK) {
    if (!quiet) emitText("set channel %d (%s) failed: %s (check COUNTRY_CODE / channel pair)",
                         ch, width, esp_err_to_name(e));
    return false;
  }
  curChannel = (uint8_t)ch;
  curSecond = (uint8_t)second;
  if (!quiet) emitText("channel %d (%s)", ch, width);
  emitEvent(EV_CHANNEL);
  return true;
}

// 5 GHz 40 MHz pairs are fixed (36+40, 44+48, ..., 149+153, 157+161): 1 = above, 2 = below, 0 = none
static uint8_t secondFor5G(uint8_t ch) {
  if (ch >= 36 && ch <= 144) return ((ch - 36) / 4) % 2 == 0 ? 1 : 2;
  if (ch >= 149 && ch <= 161) return ((ch - 149) / 4) % 2 == 0 ? 1 : 2;
  return 0;
}

static void addHop(uint8_t ch, uint8_t sec) {
  if (hopCount < sizeof(hopList) / sizeof(hopList[0])) hopList[hopCount++] = {ch, sec};
}

// Hop between the different channels. widths 0 = 20 MHz only;
// 1 = every channel at 20 MHz, then every possible 40 MHz pair (2.4 GHz: 1-9 above, 5-13 below).
static void startHop(uint16_t dwellMs, int band, int widths) {
  hopCount = 0;
  bool b24 = band == 0 || band == 2, b5 = band == 0 || band == 5;
  if (b24) for (uint8_t c : CH_24) addHop(c, 0);
#if SOC_WIFI_SUPPORT_5G
  if (b5) for (uint8_t c : CH_5) addHop(c, 0);
#endif
  if (widths == 1) {
    if (b24) {
      for (uint8_t c : CH_24) if (c + 4 <= 13) addHop(c, 1);
      for (uint8_t c : CH_24) if (c >= 5) addHop(c, 2);
    }
#if SOC_WIFI_SUPPORT_5G
    if (b5) for (uint8_t c : CH_5) if (secondFor5G(c)) addHop(c, secondFor5G(c));
#endif
  }
  if (hopCount == 0) { emitText("no channels for band %d", band); return; }
  hopDwellMs = dwellMs < 50 ? 50 : dwellMs;
  hopIdx = 0;
  hopSweeps = 0;
  hopping = true;
  emitText("hopping %d channel/width settings, dwell %d ms", hopCount, hopDwellMs);
  setChannel(hopList[0].ch, true, (wifi_second_chan_t)hopList[0].sec);
  hopLast = millis();
}

static void stopHop() {
  if (!hopping) return;
  hopping = false;
  emitEvent(EV_HOP_STOP);
}

static void hopTick() {
  if (!hopping || millis() - hopLast < hopDwellMs) return;
  // Advance to the next channel the radio accepts; give up after one full lap of failures.
  for (uint8_t tries = 0; tries < hopCount; tries++) {
    if (++hopIdx >= hopCount) {
      hopIdx = 0;
      hopSweeps++;
      emitEvent(EV_SWEEP_DONE);
    }
    if (setChannel(hopList[hopIdx].ch, true, (wifi_second_chan_t)hopList[hopIdx].sec)) break;
  }
  hopLast = millis();
}

// reads from Serial for channel commands eg. 'c36' sets the channel to 36
static void handleCommands() {
  static char line[16];
  static uint8_t n = 0;
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      line[n] = 0;
      if (n > 1 && line[0] == 'c') {
        // "c6" = channel 6 at 20 MHz, "c6,a" / "c6,b" = 40 MHz with the secondary channel above / below
        int ch = 0; char sec = 0;
        sscanf(line + 1, "%d,%c", &ch, &sec);
        wifi_second_chan_t second = sec == 'a' ? WIFI_SECOND_CHAN_ABOVE
                                  : sec == 'b' ? WIFI_SECOND_CHAN_BELOW : WIFI_SECOND_CHAN_NONE;
        stopHop();
        setChannel(ch, false, second);
      }
      else if (n >= 1 && line[0] == 'h') {
        // "h<dwell>,<band>,<widths>": band 0 both / 2 = 2.4 GHz / 5 = 5 GHz; widths 0 = 20 MHz, 1 = 20 then 40
        int dwell = 200, band = 0, widths = 0;
        if (n > 1) sscanf(line + 1, "%d,%d,%d", &dwell, &band, &widths);
        startHop((uint16_t)dwell, band, widths);
      }
      else if (n == 1 && line[0] == 'x') stopHop();
      else if (n == 1 && line[0] == 's') emitStats();
      n = 0;
    } else if (n < sizeof(line) - 1) {
      line[n++] = c;
    }
  }
}

#define TRY(x) do { esp_err_t _e = (x); if (_e != ESP_OK) emitText("%s -> %s", #x, esp_err_to_name(_e)); } while (0)

// Sets up the ring buffer, WiFi, enable promiscuous mode, tune to start channel
void setup() {
  Serial.setTxBufferSize(16384);
  Serial.begin(SERIAL_BAUD);
  esp_log_level_set("*", ESP_LOG_NONE);
  delay(300);

  rb = xRingbufferCreate(RINGBUF_BYTES, RINGBUF_TYPE_NOSPLIT);
  if (!rb) { while (true) { emitText("ring buffer alloc failed"); delay(1000); } }

  esp_err_t e = nvs_flash_init();
  if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    nvs_flash_erase();
    nvs_flash_init();
  }
  esp_event_loop_create_default();   // ESP_ERR_INVALID_STATE if it already exists: fine

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  TRY(esp_wifi_init(&cfg));
  TRY(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  TRY(esp_wifi_set_mode(WIFI_MODE_NULL));       // no STA, no AP: nothing to connect, no own beacons
  if (COUNTRY_CODE[0]) TRY(esp_wifi_set_country_code(COUNTRY_CODE, true));
  TRY(esp_wifi_start());
#if SOC_WIFI_SUPPORT_5G
  TRY(esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO));   // allow both 2.4 and 5 GHz channels
#endif

  wifi_promiscuous_filter_t filt = {};
  filt.filter_mask = (CAPTURE_MGMT ? WIFI_PROMIS_FILTER_MASK_MGMT : 0) |
                     (CAPTURE_DATA ? WIFI_PROMIS_FILTER_MASK_DATA : 0) |
                     (CAPTURE_CTRL ? WIFI_PROMIS_FILTER_MASK_CTRL : 0);
  TRY(esp_wifi_set_promiscuous_filter(&filt));
#if CAPTURE_CTRL
  wifi_promiscuous_filter_t cfilt = {};
  cfilt.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL;
  TRY(esp_wifi_set_promiscuous_ctrl_filter(&cfilt));
#endif
  TRY(esp_wifi_set_promiscuous_rx_cb(snifferCb));
  TRY(esp_wifi_set_promiscuous(true));
  setChannel(START_CHANNEL);
  emitText("esp32c5 sniffer ready, snaplen %d", SNAPLEN);
}

// Takes up to 64 queued frames out of the ring buffer and writes them to Serial
void loop() {
  // Drain the ring buffer: block briefly for the first item, then take whatever is ready.
  for (int i = 0; i < 64; i++) {
    size_t sz = 0;
    void *item = xRingbufferReceive(rb, &sz, i == 0 ? pdMS_TO_TICKS(10) : 0);
    if (!item) break;
    Serial.write((const uint8_t *)item, sz);
    vRingbufferReturnItem(rb, item);
  }

  static uint32_t lastStats = 0;
  if (millis() - lastStats >= STATS_MS) {
    lastStats = millis();
    emitStats();
  }
  handleCommands();
  hopTick();
}
