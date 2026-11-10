The current recorder uses the WFS2 binary firmware. Follow ../../README.md for
Windows setup, port selection, recording modes, file schemas and quality checks.

Run from the project root in the ESP-IDF PowerShell environment:
  python esp32_camera_recorder/esp32_camera_recorder/record_wifi.py --port <receiver-port> --channel scan --state unknown --duration 20
