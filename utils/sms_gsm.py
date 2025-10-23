import serial, time

def send_sms_gsm(port: str, to: str, text: str) -> bool:
    try:
        ser = serial.Serial(port, 115200, timeout=5)
        time.sleep(0.5)
        ser.write(b'AT\r')
        time.sleep(0.5)
        ser.write(b'AT+CMGF=1\r')
        time.sleep(0.5)
        ser.write(f'AT+CMGS="{to}"\r'.encode())
        time.sleep(0.5)
        ser.write(text.encode() + b"\x1A")
        time.sleep(4)
        resp = ser.read_all().decode(errors="ignore")
        ser.close()
        return "OK" in resp or "+CMGS" in resp
    except Exception as e:
        print("SMS error:", e)
        return False
