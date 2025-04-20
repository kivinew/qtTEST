import sys
import re
import telnetlib3
import pyperclip
from Pyside6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QGroupBox,
                             QMessageBox, QTabWidget)
from Pyside6.QtCore import Qt, QThread, pyqtSignal
from Pyside6.QtGui import QFont, QTextCursor

class TelnetWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, host, port, username, password, command):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.command = command

    def run(self):
        try:
            tn = telnetlib3.Telnet(self.host, self.port, timeout=10)
            
            # Login process
            tn.read_until(b"Username:", timeout=5)
            tn.write(self.username.encode('ascii') + b"\n")
            tn.read_until(b"Password:", timeout=5)
            tn.write(self.password.encode('ascii') + b"\n")
            
            # Wait for prompt
            tn.read_until(b">", timeout=5)
            
            # Send command and get output
            tn.write(self.command.encode('ascii') + b"\n")
            
            # For commands that might have paged output
            if "display" in self.command.lower():
                tn.write(b" \n")  # Send space to get full output
                
            # Read output until prompt appears again
            output = tn.read_until(b">", timeout=10).decode('ascii')
            
            # Clean up the output
            output = output.replace(self.command, "").strip()
            output = output.replace("\r", "").replace(">", "").strip()
            
            tn.write(b"quit\n")
            tn.close()
            
            self.finished.emit(output)
            
        except Exception as e:
            self.error.emit(f"Telnet error: {str(e)}")

class GPONDiagnosticApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GPON Auto-Diagnostic Tool")
        self.setGeometry(100, 100, 900, 700)
        
        # Initialize parsed data structure
        self.parsed_data = {
            "status": "offline",
            "serial": "нет данных",
            "description": "нет данных",
            "model": "нет данных",
            "version": "нет данных",
            "distance": "нет данных",
            "uptime": "нет данных",
            "downtime": "нет данных",
            "downcause": "нет данных",
            "ont_rx_power": "нет данных",
            "olt_rx_power": "нет данных",
            "upstream_errors": "0",
            "downstream_errors": "0",
            "lan_ports": [],
            "eth_errors": {"fcs": 0, "received_bad_bytes": 0, "sent_bad_bytes": 0},
            "troubleshooting": "Сбой диагностики!"
        }
        
        # Regular expressions patterns
        self.PATTERNS = {
            "ont_by_serial": r"F\/S\/P\s*:\s(\d+)\/(\d+)\/(\d+).*ONT-ID\s*:\s(\d+)",
            "ont_by_desc": r"(\d+)/\s*(\d+)/\s*(\d+)\s+(\d+)",
            "status": r"Run state\s+:\s+(\S+)",
            "serial": r"(?i)SN\s+:\s+([\da-f]{16})",
            "description": r"Description\s+:\s(\S+)",
            "uptime": r"Last up time\s*:\s*([\d-]+\s[\d:+-]+)",
            "downtime": r"Last down time\s*:\s*([\d-]+\s[\d:+-]+)",
            "downcause": r"Last down cause\s+:\s+(\S+)",
            "distance": r" distance\(m\)\s*:\s*(\d+)",
            "soft_version": r"Main Software Version\s*:\s*(\S*)",
            "ont_model": r"OntProductDescription    : EchoLife (\S+) GPON",
            "ont_model2": r"Equipment-ID\s*:\s*(\w+)",
            "ont_rx_power": r"Rx optical power\(dBm\)\s*:\s*([\d.-]+)",
            "olt_rx_power": r"OLT Rx ONT optical power\(dBm\)\s*:\s*([\d.-]+)",
            "lan_ports": r"(\d+)\s+(\d+)\s+(GE|FE)\s+(\d+|-)+\s+(full|half|-)\s+(up|down)",
            "upstream_errors": r"Upstream frame BIP error count\s*:\s*(\d+)",
            "downstream_errors": r"Downstream frame BIP error count\s*:\s*(\d+)",
            "eth_errors": {
                "fcs": r"Received FCS error frames\s+:\s+(\d+)",
                "received_bad_bytes": r"Received bad bytes\s+:\s+(\d+)",
                "sent_bad_bytes": r"Sent bad bytes\s+:\s+(\d+)"
            }
        }
        
        self.init_ui()
        
    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # Connection settings group
        connection_group = QGroupBox("Настройки подключения")
        connection_layout = QVBoxLayout()
        
        # Host, port, credentials
        host_layout = QHBoxLayout()
        host_layout.addWidget(QLabel("OLT IP:"))
        self.host_input = QLineEdit("192.168.1.1")
        host_layout.addWidget(self.host_input)
        
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Порт:"))
        self.port_input = QLineEdit("23")
        port_layout.addWidget(self.port_input)
        
        user_layout = QHBoxLayout()
        user_layout.addWidget(QLabel("Логин:"))
        self.user_input = QLineEdit("admin")
        user_layout.addWidget(self.user_input)
        
        pass_layout = QHBoxLayout()
        pass_layout.addWidget(QLabel("Пароль:"))
        self.pass_input = QLineEdit("admin")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        pass_layout.addWidget(self.pass_input)
        
        connection_layout.addLayout(host_layout)
        connection_layout.addLayout(port_layout)
        connection_layout.addLayout(user_layout)
        connection_layout.addLayout(pass_layout)
        connection_group.setLayout(connection_layout)
        
        # Input data group
        input_group = QGroupBox("Входные данные")
        input_layout = QVBoxLayout()
        
        self.input_type = QComboBox()
        self.input_type.addItems(["Серийный номер", "Дескрипшен (лицевой счет)", "ONT (F/S/P ID)"])
        input_layout.addWidget(self.input_type)
        
        self.data_input = QLineEdit()
        self.data_input.setPlaceholderText("Введите серийный номер, дескрипшен или ONT (например: 485754430068409E, 102147 или 0/1/1 10)")
        input_layout.addWidget(self.data_input)
        
        input_group.setLayout(input_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.run_button = QPushButton("Выполнить диагностику")
        self.run_button.clicked.connect(self.run_diagnostics)
        button_layout.addWidget(self.run_button)
        
        self.copy_button = QPushButton("Копировать результат")
        self.copy_button.clicked.connect(self.copy_to_clipboard)
        self.copy_button.setEnabled(False)
        button_layout.addWidget(self.copy_button)
        
        # Results tabs
        self.tabs = QTabWidget()
        
        # Diagnostic results tab
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setFont(QFont("Courier New", 10))
        self.tabs.addTab(self.results_text, "Результаты диагностики")
        
        # Raw output tab (for debugging)
        self.raw_output_text = QTextEdit()
        self.raw_output_text.setReadOnly(True)
        self.raw_output_text.setFont(QFont("Courier New", 10))
        self.tabs.addTab(self.raw_output_text, "Сырой вывод")
        
        # Assemble main layout
        main_layout.addWidget(connection_group)
        main_layout.addWidget(input_group)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.tabs)
        
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
    def parse_output(self, output, pattern, transform=lambda x: x):
        """Парсинг вывода с использованием регулярных выражений."""
        match = re.search(pattern, output)
        return transform(match.group(1)) if match else None
    
    def parse_by_description(self, output):
        """Извлечение frame, slot, port и ont из вывода команды display ont info by-desc."""
        match = re.search(self.PATTERNS['ont_by_desc'], output)
        if match:
            return match.groups()
        raise ValueError("Не удалось найти данные ONT по дескрипшену!")
    
    def parse_by_serial(self, output):
        """Извлечение frame, slot, port и ont из вывода команды display ont info by-desc."""
        match = re.search(self.PATTERNS['ont_by_serial'], output)
        if match:
            return match.groups()
        raise ValueError("Не удалось найти данные ONT по серийному номеру!")
    
    def parse_lan_ports(self, output):
        """Парсинг состояния LAN портов."""
        return [
            {
                "lan_id": match.group(2),
                "port_type": match.group(3),
                "speed": match.group(4),
                "duplex": match.group(5),
                "link_state": match.group(6),
            }
            for match in re.finditer(self.PATTERNS['lan_ports'], output)
        ]
    
    def parse_eth_errors(self, output):
        """Парсинг ошибок Ethernet."""
        return {
            key: self.parse_output(output, pattern, int) or 0
            for key, pattern in self.PATTERNS['eth_errors'].items()
        }
    
    def send_command(self, command):
        """Отправка команды через Telnet и получение результата."""
        worker = TelnetWorker(
            self.host_input.text(),
            int(self.port_input.text()),
            self.user_input.text(),
            self.pass_input.text(),
            command
        )
        
        worker.finished.connect(self.handle_command_output)
        worker.error.connect(self.show_error)
        worker.start()
        
        return worker
    
    def handle_command_output(self, output):
        """Обработка вывода команды."""
        self.raw_output_text.append(output)
        self.raw_output_text.moveCursor(QTextCursor.MoveOperation.End)
    
    def show_error(self, error_msg):
        """Показать сообщение об ошибке."""
        QMessageBox.critical(self, "Ошибка", error_msg)
    
    def run_diagnostics(self):
        """Основная логика диагностики."""
        self.results_text.clear()
        self.raw_output_text.clear()
        
        input_data = self.data_input.text().strip()
        if not input_data:
            QMessageBox.warning(self, "Предупреждение", "Пожалуйста, введите данные для диагностики!")
            return
        
        input_type = self.input_type.currentText()
        
        try:
            if input_type == "Серийный номер":
                if not re.fullmatch(r'(?i)(48575443|hwtc)[\da-z]{8}', input_data):
                    raise ValueError("Неверный формат серийного номера!")
                
                command = f"display ont info by-sn {input_data.upper()}"
                worker = self.send_command(command)
                worker.finished.connect(lambda output: self.process_serial_output(output, input_data))
                
            elif input_type == "Дескрипшен (лицевой счет)":
                command = f"display ont info by-desc {input_data}"
                worker = self.send_command(command)
                worker.finished.connect(lambda output: self.process_desc_output(output, input_data))
                
            elif input_type == "ONT (F/S/P ID)":
                ont_data = input_data.replace('/', ' ').split()
                if len(ont_data) != 4:
                    raise ValueError("Неверный формат ONT! Используйте формат F/S/P ID (например: 0/1/1 10)")
                
                frame, slot, port, ont = ont_data
                command = f"display ont info {frame} {slot} {port} {ont}"
                worker = self.send_command(command)
                worker.finished.connect(lambda output: self.process_ont_output(output, frame, slot, port, ont))
                
        except Exception as e:
            self.show_error(str(e))
    
    def process_serial_output(self, output, serial):
        """Обработка вывода для серийного номера."""
        try:
            frame, slot, port, ont = self.parse_by_serial(output)
            self.process_ont_output(output, frame, slot, port, ont)
        except Exception as e:
            self.show_error(f"Ошибка обработки серийного номера: {str(e)}")
    
    def process_desc_output(self, output, description):
        """Обработка вывода для дескрипшена."""
        try:
            frame, slot, port, ont = self.parse_by_description(output)
            command = f"display ont info {frame} {slot} {port} {ont}"
            worker = self.send_command(command)
            worker.finished.connect(lambda output: self.process_ont_output(output, frame, slot, port, ont))
        except Exception as e:
            self.show_error(f"Ошибка обработки дескрипшена: {str(e)}")
    
    def process_ont_output(self, output, frame, slot, port, ont):
        """Основная обработка вывода информации ONT."""
        try:
            # Parse basic info
            for key in ['status', 'distance', 'serial', 'description', 'uptime', 'downtime', 'downcause']:
                self.parsed_data[key] = self.parse_output(output, self.PATTERNS[key]) or self.parsed_data[key]
            
            # Build basic info string
            result_text = (
                f"ONT = {frame}/{slot}/{port}/{ont}\n"
                f"Дескрипшн (лицевой счёт) = {self.parsed_data['description']}\n"
                f"PON SN = {self.parsed_data['serial']}\n"
                f"Терминал {'доступен' if self.parsed_data['status'] == 'online' else 'недоступен'}.\n"
            )
            
            if self.parsed_data['status'] == 'offline':
                # Handle offline case
                if not any(character.isdigit() for character in self.parsed_data['downtime']):
                    self.parsed_data['downtime'] = "нет данных"
                    self.parsed_data['downcause'] = "нет данных" if '-' in self.parsed_data['downcause'] else self.parsed_data['downcause']
                    self.parsed_data['troubleshooting'] = "Интернет не работает. Запись о причине недоступности терминала отсутствует."
                elif 'LOFi' in self.parsed_data['downcause']:
                    self.parsed_data['downcause'] += " — низкий/отсутствует уровень оптического сигнала."
                    self.parsed_data['troubleshooting'] = "Интернет не работает. Необходима проверка оптической линии."
                elif 'LOS' in self.parsed_data['downcause']:
                    self.parsed_data['downcause'] += " — отсутствует оптический сигнал."
                    self.parsed_data['troubleshooting'] = "Интернет не работает. Необходима проверка оптической линии."
                elif 'dying-gasp' in self.parsed_data['downcause']:
                    self.parsed_data['downcause'] += " — отключение эл.питания."
                    self.parsed_data['troubleshooting'] = "Интернет не работает. Необходима проверка терминала и БП."
                
                result_text += (
                    f"Отключён: {self.parsed_data['downtime']}\n"
                    f"Время последнего включения: {self.parsed_data['uptime']}\n"
                    f"Растояние от головной станции (м): {self.parsed_data['distance']}\n"
                    f"Причина недоступности — {self.parsed_data['downcause']}\n"
                    f"\n{self.parsed_data['troubleshooting']}"
                )
                
                self.results_text.setPlainText(result_text)
                self.copy_button.setEnabled(True)
                return
            
            # If online, get more info
            command = f"display ont version {frame} {slot} {port} {ont}"
            worker = self.send_command(command)
            worker.finished.connect(lambda output: self.process_version_output(output, frame, slot, port, ont, result_text))
            
        except Exception as e:
            self.show_error(f"Ошибка обработки информации ONT: {str(e)}")
    
    def process_version_output(self, output, frame, slot, port, ont, result_text):
        """Обработка вывода версии ПО."""
        try:
            # Parse version info
            soft_version = self.parse_output(output, self.PATTERNS['ont_model'])
            if not soft_version:
                soft_version = self.parse_output(output, self.PATTERNS['ont_model2'])
            self.parsed_data['model'] = soft_version or self.parsed_data['model']
            self.parsed_data['version'] = self.parse_output(output, self.PATTERNS['soft_version']) or self.parsed_data['model']
            
            result_text += (
                f"Включён: {self.parsed_data['uptime']}\n"
                f"Модель терминала: '{self.parsed_data['model']}'\n"
                f"Версия ПО терминала: '{self.parsed_data['version']}'\n"
                f"Растояние от головной станции (м): {self.parsed_data['distance']}\n"
            )
            
            # Get optical info
            command = f"interface gpon {frame}/{slot}"
            worker = self.send_command(command)
            worker.finished.connect(lambda _: self.send_command(f"display ont optical-info {port} {ont}"))
            worker.finished.connect(lambda output: self.process_optical_output(output, frame, slot, port, ont, result_text))
            
        except Exception as e:
            self.show_error(f"Ошибка обработки версии ПО: {str(e)}")
    
    def process_optical_output(self, output, frame, slot, port, ont, result_text):
        """Обработка оптической информации."""
        try:
            self.parsed_data['ont_rx_power'] = self.parse_output(output, self.PATTERNS['ont_rx_power'], str) or self.parsed_data['ont_rx_power']
            self.parsed_data['olt_rx_power'] = self.parse_output(output, self.PATTERNS['olt_rx_power'], str) or self.parsed_data['olt_rx_power']
            
            result_text += (
                f"ONT Rx (оптический сигнал на терминале)(dBm): {self.parsed_data['ont_rx_power']}\n"
                f"OLT Rx (сигнал на головной станции)(dBm): {self.parsed_data['olt_rx_power']}\n"
            )
            
            if self.parsed_data['ont_rx_power'] != 'нет данных' and self.parsed_data['olt_rx_power'] != 'нет данных':
                if float(self.parsed_data['ont_rx_power']) < -26.5 or float(self.parsed_data['olt_rx_power']) < -31.5:
                    self.parsed_data['troubleshooting'] = "Обнаружен низкий уровень оптического сигнала. Необходима проверка оптической линии."
                else:
                    self.parsed_data['troubleshooting'] = "Нарушений не выявлено."
            else:
                self.parsed_data['troubleshooting'] = "Не удалось определить уровень оптического сигнала! Необходима диагностика терминала."
            
            # Get line quality
            command = f"display statistics ont-line-quality {port} {ont}"
            worker = self.send_command(command)
            worker.finished.connect(lambda output: self.process_line_quality(output, frame, slot, port, ont, result_text))
            
        except Exception as e:
            self.show_error(f"Ошибка обработки оптической информации: {str(e)}")
    
    def process_line_quality(self, output, frame, slot, port, ont, result_text):
        """Обработка информации о качестве линии."""
        try:
            self.parsed_data['upstream_errors'] = self.parse_output(output, self.PATTERNS['upstream_errors'], int) or 0
            self.parsed_data['downstream_errors'] = self.parse_output(output, self.PATTERNS['downstream_errors'], int) or 0
            optic_errors = self.parsed_data['upstream_errors'] + self.parsed_data['downstream_errors']
            
            if optic_errors:
                prefix = "Обнаружено значительное количество ошибок оптики: " if optic_errors > 10000 else "Незначительное количество ошибок оптики: "
                result_text += (
                    f"{prefix}"
                    f"Upstream: {self.parsed_data['upstream_errors']}. "
                    f"Downstream: {self.parsed_data['downstream_errors']}.\n"
                    "Выполнен сброс счётчиков ошибок.\n"
                )
                self.send_command(f"clear statistics ont-line-quality {port} {ont}")
            else:
                result_text += "Ошибок оптики нет.\n"
            
            # Get LAN ports state
            command = f"display ont port state {port} {ont} eth-port all"
            worker = self.send_command(command)
            worker.finished.connect(lambda output: self.process_lan_ports(output, frame, slot, port, ont, result_text))
            
        except Exception as e:
            self.show_error(f"Ошибка обработки качества линии: {str(e)}")
    
    def process_lan_ports(self, output, frame, slot, port, ont, result_text):
        """Обработка состояния LAN портов."""
        try:
            self.parsed_data['lan_ports'] = self.parse_lan_ports(output)
            has_eth_errors = False
            eth_errors_text = ""
            
            for port_state in self.parsed_data['lan_ports']:
                if port_state['link_state'] == 'up':
                    result_text += (
                        f"LAN{port_state['lan_id']}: Type={port_state['port_type']}, "
                        f"Speed={port_state['speed']} Mbps, Duplex={port_state['duplex']}, "
                        f"Link State={port_state['link_state']}\n"
                    )
                    
                    command = f"display statistics ont-eth {port} {ont} ont-port {port_state['lan_id']}"
                    worker = self.send_command(command)
                    worker.finished.connect(lambda output, port_id=port_state['lan_id']: 
                        self.process_eth_errors(output, port_id, result_text, eth_errors_text, has_eth_errors))
            
            # Finalize the results
            result_text += eth_errors_text + ("Выполнен сброс счётчиков ошибок.\n" if has_eth_errors else "Ошибок портов LAN нет.\n")
            result_text += f"\n{self.parsed_data['troubleshooting']}"
            
            # Display the final results
            self.results_text.setPlainText(result_text)
            self.copy_button.setEnabled(True)
            
            # Get additional info if needed
            if '310' not in self.parsed_data['model']:
                self.send_command(f"ont remote-ping {port} {ont} ip-address 8.8.8.8")
                self.send_command(f"display ont ipconfig {port} {ont}")
            
            # Get MAC addresses
            self.send_command(f"display mac-address ont {frame}/{slot}/{port} {ont}")
            
        except Exception as e:
            self.show_error(f"Ошибка обработки LAN портов: {str(e)}")
    
    def process_eth_errors(self, output, port_id, result_text, eth_errors_text, has_eth_errors):
        """Обработка ошибок Ethernet."""
        try:
            self.parsed_data['eth_errors'] = self.parse_eth_errors(output)
            errors = self.parsed_data['eth_errors']
            
            if any(errors.values()):
                has_eth_errors = True
                eth_errors_text += (
                    f"Обнаружены ошибки на порту LAN{port_id}: "
                    f"FCS = {errors['fcs']}. "
                    f"Input = {errors['received_bad_bytes']}. "
                    f"Output = {errors['sent_bad_bytes']}.\n"
                )
                self.send_command(f"clear statistics ont-eth {port} {ont} ont-port {port_id}")
            
        except Exception as e:
            self.show_error(f"Ошибка обработки ошибок Ethernet: {str(e)}")
    
    def copy_to_clipboard(self):
        """Копирование результатов в буфер обмена."""
        pyperclip.copy(self.results_text.toPlainText())
        QMessageBox.information(self, "Успех", "Результаты скопированы в буфер обмена!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GPONDiagnosticApp()
    window.show()
    sys.exit(app.exec())