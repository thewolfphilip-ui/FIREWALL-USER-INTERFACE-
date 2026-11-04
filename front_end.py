"VILA CODE"
import sys

from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QLabel,
    QCheckBox,
    QMessageBox,
    QComboBox,
    QLineEdit,
    QPushButton,
    QListWidget,
    QGroupBox,
    QFormLayout,
)

from PySide6.QtCore import Qt
from PySide6.QtGui import QIntValidator

from firewall_backend import (
    get_default_policy,
    set_default_policy,
    add_firewall_rule,
    get_firewall_rules,
    delete_firewall_rule,
)


class FirewallDashboard(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("VILAWALL - Firewall Manager")
        self.setMinimumSize(700, 700)

        self.current_policy = None

        self.setup_ui()
        self.load_firewall_policy()
        self.refresh_rules()

    # =====================================
    # MAIN UI
    # =====================================

    def setup_ui(self):

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(40, 30, 40, 30)
        layout.setSpacing(18)

        title = QLabel("VILAWALL")
        title.setStyleSheet("""
            font-size: 28px;
            font-weight: bold;
            color: #55B5FF;
        """)

        subtitle = QLabel("Firewall Management")
        subtitle.setStyleSheet(
            "color: #91A4BA; font-size: 14px;"
        )

        self.status_label = QLabel("Checking firewall...")
        self.status_label.setStyleSheet(
            "font-size: 16px;"
        )

        self.policy_switch = QCheckBox(
            "ALLOW incoming traffic"
        )

        self.policy_switch.setCursor(
            Qt.CursorShape.PointingHandCursor
        )

        self.policy_switch.setStyleSheet("""
            QCheckBox {
                color: #E6EEF9;
                font-size: 18px;
                spacing: 12px;
            }

            QCheckBox::indicator {
                width: 48px;
                height: 26px;
                border-radius: 13px;
                background-color: #51252B;
            }

            QCheckBox::indicator:checked {
                background-color: #176B4A;
            }
        """)

        self.policy_switch.toggled.connect(
            self.change_firewall_policy
        )

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(10)
        layout.addWidget(self.status_label)
        layout.addWidget(self.policy_switch)

        self.create_rule_section(layout)
        self.create_rules_list(layout)

        layout.addStretch()

        self.setStyleSheet("""
            QMainWindow {
                background-color: #0B1018;
            }

            QLabel {
                color: #E6EEF9;
            }

            QGroupBox {
                color: #55B5FF;
                font-size: 16px;
                font-weight: bold;
                border: 1px solid #29394C;
                border-radius: 8px;
                margin-top: 12px;
                padding: 15px;
            }

            QComboBox, QLineEdit {
                background-color: #151F2D;
                color: #E6EEF9;
                border: 1px solid #35465B;
                border-radius: 5px;
                padding: 8px;
            }

            QPushButton {
                background-color: #176B9A;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 9px;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #238BC5;
            }

            QPushButton:disabled {
                background-color: #35465B;
                color: #91A4BA;
            }

            QListWidget {
                background-color: #111A26;
                color: #E6EEF9;
                border: 1px solid #29394C;
                border-radius: 5px;
                padding: 5px;
            }

            QListWidget::item:selected {
                background-color: #176B9A;
            }
        """)


    def create_rule_section(self, parent_layout):

        group = QGroupBox("Add Firewall Rule")
        form = QFormLayout(group)
        form.setSpacing(12)

        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems([
            "TCP",
            "UDP",
            "ICMP"
        ])

        self.protocol_combo.currentTextChanged.connect(
            self.update_port_input
        )

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText(
            "Example: 443 (leave empty for all ports)"
        )

        self.port_input.setValidator(
            QIntValidator(1, 65535, self)
        )

        self.action_combo = QComboBox()
        self.action_combo.addItems([
            "ALLOW",
            "BLOCK"
        ])

        self.add_rule_button = QPushButton(
            "Add Firewall Rule"
        )

        self.add_rule_button.clicked.connect(
            self.add_rule
        )

        form.addRow("Protocol:", self.protocol_combo)
        form.addRow("Destination Port:", self.port_input)
        form.addRow("Action:", self.action_combo)
        form.addRow(self.add_rule_button)

        parent_layout.addWidget(group)


    def create_rules_list(self, parent_layout):

        group = QGroupBox("Current Firewall Rules")
        rules_layout = QVBoxLayout(group)

        self.rules_list = QListWidget()

        self.rules_list.setSelectionMode(
            QListWidget.SelectionMode.SingleSelection
        )

        self.rules_list.currentRowChanged.connect(
            self.update_delete_button
        )

        self.refresh_button = QPushButton(
            "Refresh Rules"
        )

        self.refresh_button.clicked.connect(
            self.refresh_rules
        )

        self.delete_button = QPushButton(
            "Delete Selected Rule"
        )

        self.delete_button.setEnabled(False)

        self.delete_button.setStyleSheet("""
            QPushButton {
                background-color: #8D303A;
                color: white;
                border-radius: 5px;
                padding: 9px;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #B33D49;
            }

            QPushButton:disabled {
                background-color: #35465B;
                color: #91A4BA;
            }
        """)

        self.delete_button.clicked.connect(
            self.delete_selected_rule
        )

        rules_layout.addWidget(self.rules_list)
        rules_layout.addWidget(self.refresh_button)
        rules_layout.addWidget(self.delete_button)

        parent_layout.addWidget(group)


    def update_port_input(self, protocol):

        if protocol == "ICMP":

            self.port_input.clear()
            self.port_input.setEnabled(False)

            self.port_input.setPlaceholderText(
                "ICMP does not use ports"
            )

        else:

            self.port_input.setEnabled(True)

            self.port_input.setPlaceholderText(
                "Example: 443 (leave empty for all ports)"
            )


    def add_rule(self):

        protocol = self.protocol_combo.currentText().lower()
        action = self.action_combo.currentText().lower()

        port_text = self.port_input.text().strip()

        port = None

        if port_text:

            try:
                port = int(port_text)

            except ValueError:

                QMessageBox.warning(
                    self,
                    "Invalid Port",
                    "Please enter a valid port number."
                )
                return

        if protocol in ("tcp", "udp") and port is not None:

            if not 1 <= port <= 65535:

                QMessageBox.warning(
                    self,
                    "Invalid Port",
                    "Port must be between 1 and 65535."
                )
                return

        try:

            self.add_rule_button.setEnabled(False)

            result = add_firewall_rule(
                protocol,
                action,
                port
            )

            if not self.refresh_rules():
                raise RuntimeError(
                    "Rule added, but the list could not refresh."
                )

            QMessageBox.information(
                self,
                "Firewall Rule",
                result
            )

        except Exception as error:

            QMessageBox.critical(
                self,
                "Firewall Error",
                str(error)
            )

        finally:

            self.add_rule_button.setEnabled(True)
    def format_rule(self, rule):

        protocol = "UNKNOWN"
        port = "ALL"
        action = "UNKNOWN"

        expressions = rule.get("expr") or []

        for expression in expressions:

            if not isinstance(expression, dict):
                continue

            match = expression.get("match")

            if match:

                left = match.get("left") or {}
                right = match.get("right")

                if isinstance(left, dict):

                    meta = left.get("meta")

                    if isinstance(meta, dict):

                        if meta.get("key") == "l4proto":
                            protocol = str(right).upper()

                    payload = left.get("payload")

                    if isinstance(payload, dict):

                        if payload.get("field") == "dport":

                            port = str(right)

                            protocol = payload.get(
                                "protocol",
                                protocol
                            ).upper()

            if "accept" in expression:
                action = "ALLOW"

            elif "drop" in expression:
                action = "BLOCK"

        handle = rule.get("handle", "?")

        return (
            f"{action} | {protocol} | "
            f"Port: {port} | Handle: {handle}"
        )



    def refresh_rules(self):

        self.rules_list.clear()
        self.delete_button.setEnabled(False)

        try:

            rules = get_firewall_rules()

            if rules is None:
                raise RuntimeError(
                    "Backend returned no rule list."
                )

            for rule in rules:

                if not isinstance(rule, dict):
                    continue

                description = self.format_rule(rule)

                self.rules_list.addItem(description)

                list_item = self.rules_list.item(
                    self.rules_list.count() - 1
                )

                list_item.setData(
                    Qt.ItemDataRole.UserRole,
                    rule.get("handle")
                )

            if self.rules_list.count() == 0:

                self.rules_list.addItem(
                    "No firewall rules found."
                )

            return True

        except Exception as error:

            self.rules_list.addItem(
                "Could not load firewall rules."
            )

            QMessageBox.critical(
                self,
                "Firewall Error",
                f"Could not load firewall rules:\n{error}"
            )

            return False

  

    def update_delete_button(self, row):

        if row < 0:
            self.delete_button.setEnabled(False)
            return

        item = self.rules_list.item(row)

        self.delete_button.setEnabled(
            item is not None
            and item.data(Qt.ItemDataRole.UserRole) is not None
        )


    def load_firewall_policy(self):

        try:

            chains = get_default_policy()

            chain = next(
                (
                    item for item in chains
                    if item["family"] == "inet"
                    and item["table"] == "filter"
                    and item["name"] == "input"
                ),
                None
            )

            if chain is None:
                raise RuntimeError(
                    "Target input chain not found"
                )

            policy = chain["policy"]

            if policy not in ("accept", "drop"):
                raise RuntimeError(
                    "Unknown firewall policy"
                )

            self.current_policy = policy

            self.policy_switch.blockSignals(True)

            self.policy_switch.setChecked(
                policy == "accept"
            )

            self.policy_switch.blockSignals(False)

            self.update_status()

        except Exception as error:

            self.policy_switch.setEnabled(False)

            self.status_label.setText(
                f"Firewall error: {error}"
            )


    def change_firewall_policy(self, checked):

        new_policy = "allow" if checked else "deny"

        self.policy_switch.setEnabled(False)

        try:

            result = set_default_policy(new_policy)

            chain = next(
                (
                    item for item in result
                    if item["family"] == "inet"
                    and item["table"] == "filter"
                    and item["name"] == "input"
                ),
                None
            )

            expected = "accept" if checked else "drop"

            if chain is None or chain["policy"] != expected:
                raise RuntimeError(
                    "Policy change could not be verified"
                )

            self.current_policy = expected

            self.update_status()

        except Exception as error:

            QMessageBox.critical(
                self,
                "Firewall Error",
                str(error)
            )

            self.policy_switch.blockSignals(True)

            self.policy_switch.setChecked(
                self.current_policy == "accept"
            )

            self.policy_switch.blockSignals(False)

        finally:

            self.policy_switch.setEnabled(True)

    def delete_selected_rule(self):

        selected_item = self.rules_list.currentItem()

        if selected_item is None:
            return

        handle = selected_item.data(
            Qt.ItemDataRole.UserRole
        )

        if handle is None:
            QMessageBox.warning(
                self,
                "Delete Rule",
                "Please select a valid firewall rule."
            )
            return

        confirmation = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete "
            f"firewall rule with handle {handle}?",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if confirmation != QMessageBox.StandardButton.Yes:
            return

        self.delete_button.setEnabled(False)

        try:

            result = delete_firewall_rule(handle)

            if not self.refresh_rules():
                raise RuntimeError(
                    "Rule deleted, but the list could not refresh."
                )

            QMessageBox.information(
                self,
                "Rule Deleted",
                result
            )

        except Exception as error:

            QMessageBox.critical(
                self,
                "Delete Error",
                str(error)
            )

            self.refresh_rules()

    

    def update_status(self):

        if self.current_policy == "accept":

            self.status_label.setText(
                "● Firewall policy: ALLOW"
            )

            self.status_label.setStyleSheet(
                "color: #65D6A2; font-size: 16px;"
            )

        else:

            self.status_label.setText(
                "● Firewall policy: DENY"
            )

            self.status_label.setStyleSheet(
                "color: #FF818D; font-size: 16px;"
            )


def main():

    app = QApplication(sys.argv)

    window = FirewallDashboard()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
