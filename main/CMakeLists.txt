idf_component_register(SRCS "main.c" "capture.c" "transport.c" INCLUDE_DIRS "."
    PRIV_REQUIRES esp_wifi esp_event esp_netif nvs_flash esp_timer esp_app_format
                  esp_driver_uart esp_driver_usb_serial_jtag)
