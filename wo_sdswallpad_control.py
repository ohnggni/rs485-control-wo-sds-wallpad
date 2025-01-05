import serial
import logging
import paho.mqtt.client as mqtt
import time
import threading

# 기본 설정
config = {
    "serial": {
        "port": "/dev/ttyUSB0",
        "baudrate": 9600,
        "bytesize": 8,
        "parity": "E",
        "stopbits": 1
    },
    "mqtt": {
        "server": "mqtt://ipaddress",
        "port": 1883,
        "need_login": True,
        "user": "username",
        "passwd": "password",
        "discovery": True,
        "prefix": "wosds"
    },
    "log": {
        "to_file": True,
        "filename": "/share/wosds_wallpad.log"
    },
    "rs485": {
        "retry_limit": 3,  # 재시도 횟수 제한
        "timeout": 2  # 응답 대기 시간 (초)
    }
}

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(message)s',
    handlers=[
        logging.FileHandler(config["log"]["filename"]),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("wosds")

# RS485 패킷을 송신하고 응답을 수신. 재시도를 통해 안정적인 통신 보장
def send_rs485_command(packet, log_packet=True):
    retries = 0
    while retries < config["rs485"]["retry_limit"]:
        with serial_lock:
            try:
                ser.reset_input_buffer()
                ser.write(packet)
                if log_packet:  # 상태 확인 패킷 로그 비활성화
                    logger.info(f"Sent RS485 packet: {packet.hex()}")

                response = ser.read(8)  # 8바이트 응답 데이터 읽기
                if response:
                    logger.debug(f"Received RS485 response (raw): {response.hex()}")
                    return response
                else:
                    logger.warning("No response received. Retrying...")
            except serial.SerialException as e:
                logger.error(f"RS485 communication error: {e}")
        retries += 1
        time.sleep(1)  # 재시도 간격 추가
    if log_packet:
        logger.error("Failed to communicate with RS485 device after retries.")
    return None

# MQTT 클라이언트 설정
client = mqtt.Client()
if config["mqtt"]["need_login"]:
    client.username_pw_set(config["mqtt"]["user"], config["mqtt"]["passwd"])

# MQTT 브로커에 연결
def connect_mqtt():
    try:
        client.connect(config["mqtt"].get("server").replace("mqtt://", ""), config["mqtt"].get("port"))
        client.loop_start()
        logger.info("Connected to MQTT broker.")
    except Exception as e:
        logger.error(f"Failed to connect to MQTT broker: {e}")

# RS485 연결 설정
def initialize_serial():
    global ser
    if 'ser' in globals() and ser.is_open:
        logger.info("RS485 device already initialized.")
        return
    try:
        ser = serial.Serial(
            port=config["serial"].get("port"),
            baudrate=config["serial"].get("baudrate"),
            bytesize=config["serial"].get("bytesize"),
            parity=config["serial"].get("parity"),
            stopbits=config["serial"].get("stopbits"),
            timeout=config["rs485"].get("timeout")
        )
        logger.info("RS485 device initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize RS485 device: {e}")
        raise

# 조명 상태 저장
light_status = [0, 0, 0]  # 1, 2, 3번 조명 상태 (꺼짐=0, 켜짐=1)

# 난방 상태 저장
heating_status = [
    {"on": 0, "set_temp": 20, "current_temp": 20},  # 난방 1
    {"on": 0, "set_temp": 20, "current_temp": 20},  # 난방 2
    {"on": 0, "set_temp": 20, "current_temp": 20},  # 난방 3
    {"on": 0, "set_temp": 20, "current_temp": 20}   # 난방 4
]

serial_lock = threading.Lock()


# 조명 상태 요청 및 업데이트 함수
def request_light_status():
    packet = bytearray([0xAC, 0x79, 0x00, 0x01, 0x54])
    response = send_rs485_command(packet, log_packet=False)  # 로그 비활성화
    if response and response[:2] == b'\xB0\x79':
        logger.debug(f"Light status response: {response.hex()}")
        return response
    else:
        logger.warning("Invalid or no response for light status request.")
        return None

# 조명 및 난방 상태를 주기적으로 업데이트하고 MQTT로 발행
def update_light_status(force_log=False):
    response = request_light_status()
    if response:
        state = response[3]
        for i in range(3):
            new_status = (state >> i) & 0x01  # 상태 추출
            if light_status[i] != new_status or force_log:
                light_status[i] = new_status
                client.publish(f"{config['mqtt']['prefix']}/light/{i+1}/status", light_status[i], retain=True)
                logger.info(f"Updated light {i+1} status to {light_status[i]}")

# 난방 상태 요청 및 업데이트 함수
def request_heating_status(group_id):
    packet = bytearray([0xAE, 0x7C, group_id, 0x00, 0x00, 0x00, 0x00])
    packet.append(calculate_checksum(packet))
    response = send_rs485_command(packet, log_packet=False)  # 로그 비활성화
    if response and response[:2] == b'\xB0\x7C':
        logger.debug(f"Heating status response: {response.hex()}")
        return response
    else:
        logger.warning(f"Invalid or no response for heating status request: group_id={group_id}")
        return None

# 난방 상태 응답 데이터를 파싱하여 그룹 ID, 상태, 설정 온도, 현재 온도를 추출
def parse_heating_status(response):
    try:
        group_id = response[2]
        current_state = response[3]
        set_temp = response[4]
        current_temp = response[5]
        return group_id, current_state, set_temp, current_temp
    except IndexError:
        logger.error("Invalid heating status response format.")
        return None, None, None, None

# 난방 상태를 MQTT로 발행하고 로컬 상태를 업데이트
def update_heating_status(group_id, force_log=False):
    response = request_heating_status(group_id)
    if response:
        group_id, current_state, set_temp, current_temp = parse_heating_status(response)
        if group_id is not None:
            changed = (
                heating_status[group_id - 1]["on"] != current_state or
                heating_status[group_id - 1]["set_temp"] != set_temp or
                heating_status[group_id - 1]["current_temp"] != current_temp
            )

            heating_status[group_id - 1]["on"] = current_state
            heating_status[group_id - 1]["set_temp"] = set_temp
            heating_status[group_id - 1]["current_temp"] = current_temp

            if changed or force_log:
                heating_state_str = f"{group_id},{current_state},{set_temp},{current_temp}"
                client.publish(f"{config['mqtt']['prefix']}/heating/{group_id}/status", heating_state_str, retain=True)
                logger.info(f"Updated heating group {group_id} status: {heating_state_str}")

# 체크섬 (XOR) 계산 함수
def calculate_checksum(packet):
    """
    패킷의 마지막 바이트를 제외한 모든 바이트를 XOR하여 체크섬을 계산합니다.
    계산된 체크섬의 최상위 비트는 항상 0으로 설정됩니다.
    """
    checksum = 0
    for b in packet[:-1]:  # 마지막 바이트 제외하고 XOR 계산
        checksum ^= b
    # 최상위 비트를 항상 0으로 유지
    if checksum >= 0x80:  # 0x80 이상인 경우 최상위 비트 제거
        checksum -= 0x80

    return checksum

def calculate_light_checksum(packet):
    """
    조명 패킷 체크섬 계산.
    """
    checksum = 0
    for byte in packet:
        checksum ^= byte
    if checksum >= 0x80:  # 0x80 이상인 경우 최상위 비트 제거
        checksum -= 0x80

    return checksum

# MQTT 메시지 핸들러
def on_message(client, userdata, msg):
    logger.info(f"Received MQTT message: {msg.topic} {msg.payload}")
    try:
        if "light" in msg.topic:
            payload = msg.payload.decode("utf-8").split(",")
            light_group = int(msg.topic.split("/")[-1])
            toggle = int(payload[0])
            control_light(light_group, toggle)

        elif "heating" in msg.topic:
            payload = msg.payload.decode("utf-8").split(",")
            heating_group = int(msg.topic.split("/")[-1])
            if len(payload) == 1:
                toggle = int(payload[0])
                control_heating(heating_group, toggle=toggle)
            elif len(payload) == 2:
                temp = int(payload[1])
                control_heating(heating_group, temp=temp)
    except Exception as e:
        logger.error(f"Failed to process MQTT message: {e}")

# 특정 조명 그룹을 켜거나 끄는 RS485 제어 패킷 송신
def control_light(group_id, toggle):
    if group_id < 1 or group_id > 3:
        logger.error("Invalid light group ID")
        return

    packet = bytearray([0xAC, 0x7A, group_id, toggle])
    checksum = calculate_light_checksum(packet)  # 조명용 체크섬 계산
    packet.append(checksum)
    logger.info(f"Generated light packet: {packet.hex()}")
    send_rs485_command(packet)
    update_light_status()

# 특정 난방 그룹의 온도를 설정하거나 전원을 제어하는 RS485 패킷 송신
def control_heating(group_id, temp=None, toggle=None):
    if toggle is not None:
        packet = bytearray([0xAE, 0x7D, group_id, toggle, 0x00, 0x00, 0x00])
    elif temp is not None:
        packet = bytearray([0xAE, 0x7F, group_id, temp, 0x00, 0x00, 0x00])
    else:
        logger.error("Invalid heating control command.")
        return
    packet.append(calculate_checksum(packet))
    send_rs485_command(packet)
    update_heating_status(group_id)

# 조명 및 난방 관련 MQTT 토픽 구독
def subscribe_topics():
    topics = [
        f"{config['mqtt']['prefix']}/light/1",
        f"{config['mqtt']['prefix']}/light/2",
        f"{config['mqtt']['prefix']}/light/3",
        f"{config['mqtt']['prefix']}/heating/1",
        f"{config['mqtt']['prefix']}/heating/2",
        f"{config['mqtt']['prefix']}/heating/3",
        f"{config['mqtt']['prefix']}/heating/4"
    ]
    for topic in topics:
        client.subscribe(topic)
        logger.info(f"Subscribed to topic: {topic}")

# 시스템 초기화 시 조명 및 난방 상태를 업데이트
def initial_status_update():
    logger.info("Performing initial status update...")
    update_light_status(force_log=True)
    for group_id in range(1, 5):
        update_heating_status(group_id, force_log=True)

# 조명 및 난방 상태를 주기적으로 업데이트하고 MQTT로 발행
def periodic_status_update():
    """
    주기적으로 조명 및 난방 상태를 요청하고 MQTT로 상태를 발행합니다.
    """
    while True:
        try:
            # 조명 상태 업데이트
            update_light_status()

            # 난방 상태 업데이트
            for group_id in range(1, 5):  # 난방 그룹 ID 1~4
                update_heating_status(group_id)

            time.sleep(5)  # 5초 간격으로 상태 업데이트
        except Exception as e:
            logger.error(f"Error during periodic status update: {e}")

def main():
    initialize_serial()
    connect_mqtt()
    subscribe_topics()
    initial_status_update()

    # 주기적 상태 업데이트 스레드 시작
    threading.Thread(target=periodic_status_update, daemon=True).start()

    client.on_message = on_message
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down.")
        client.loop_stop()
        ser.close()

if __name__ == "__main__":
    main()
