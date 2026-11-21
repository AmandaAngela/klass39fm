#include "transport.h"
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "esp_err.h"
#include "driver/uart.h"
static bool use_usb;
#if CONFIG_SOC_USB_SERIAL_JTAG_SUPPORTED
#include "driver/usb_serial_jtag.h"
#endif
// Listen on both exposed interfaces. The port issuing commands receives replies.
void transport_init(void)
{
#if CONFIG_SOC_USB_SERIAL_JTAG_SUPPORTED
    usb_serial_jtag_driver_config_t config = {.tx_buffer_size = 8192, .rx_buffer_size = 256};
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&config));
#endif
    uart_config_t cfg = {.baud_rate = 921600, .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE, .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE, .source_clk = UART_SCLK_DEFAULT};
    ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &cfg));
    ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 256, 8192, 0, NULL, 0));
}
int transport_read(void *data, size_t size)
{
#if CONFIG_SOC_USB_SERIAL_JTAG_SUPPORTED
    int n = usb_serial_jtag_read_bytes(data, size, 0);
    if (n > 0) {
        use_usb = true;
        return n;
    }
#endif
    int received = uart_read_bytes(UART_NUM_0, data, size, 0);
    if (received > 0) use_usb = false;
    return received;
}
int transport_write(const void *data, size_t size)
{
#if CONFIG_SOC_USB_SERIAL_JTAG_SUPPORTED
    if (use_usb) return usb_serial_jtag_write_bytes(data, size, pdMS_TO_TICKS(40));
#endif
    return uart_write_bytes(UART_NUM_0, data, size);
}
