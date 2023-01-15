from PyQt5.QtCore import pyqtSignal, QThread
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QWidget, QVBoxLayout, QHBoxLayout, QPushButton

from workers.WorkerSniffer import WorkerSniffer


class SnifferWidget(QWidget):
    worker_sniff = None
    worker_sniff_thread = None
    worker_sniff_requested = pyqtSignal()

    table = None
    combobox_interface_mode = None
    frame_details = []

    def __init__(self, combobox_interface_mode):
        super().__init__()
        self.combobox_interface_mode = combobox_interface_mode
        buttons_layout = QHBoxLayout()
        self.btn_start_sniff = QPushButton("Start", clicked=self.on_start_sniff_clicked)
        self.btn_start_sniff.setFixedWidth(100)
        self.btn_stop_sniff = QPushButton("Stop", clicked=self.on_stop_sniff_clicked)
        self.btn_stop_sniff.setFixedWidth(100)
        buttons_layout.addWidget(self.btn_start_sniff)
        buttons_layout.addWidget(self.btn_stop_sniff)
        main_layout = QVBoxLayout()
        main_layout.addLayout(buttons_layout)
        self.table = self.init_table()
        main_layout.addWidget(self.table)
        self.setLayout(main_layout)

        self.worker_sniff = WorkerSniffer()
        self.worker_sniff_thread = QThread()
        self.worker_sniff.progress.connect(self.on_progress_sniff)
        self.worker_sniff_requested.connect(self.worker_sniff.do_sniff)
        self.worker_sniff.moveToThread(self.worker_sniff_thread)
        self.worker_sniff_thread.start()

    def on_start_sniff_clicked(self):
        print("Start sniff clicked ...")
        self.btn_start_sniff.setEnabled(False)
        self.combobox_interface_mode.setEnabled(False)
        self.frame_details = []
        self.table.setRowCount(0)
        self.worker_sniff.set_stop(False)
        self.worker_sniff_requested.emit()

    def on_stop_sniff_clicked(self):
        print("Stop sniff clicked ...")
        self.worker_sniff.set_stop(True)
        self.load_into_table(self.frame_details)
        self.combobox_interface_mode.setEnabled(True)
        self.btn_start_sniff.setEnabled(True)

    def on_progress_sniff(self, frame):
        print("progress: ", frame)
        self.frame_details.append(frame)
        # self.load_into_table(self.frame_details)
        # row = self.table.rowCount() + 1
        # self.table.setRowCount(row)
        # self.table.setItem(row, 0, QTableWidgetItem(str(frame["type"])))
        # self.table.setItem(row, 1, QTableWidgetItem(frame["mac_source"]))
        # self.table.setItem(row, 2, QTableWidgetItem(frame["mac_dest"]))
        # self.table.setItem(row, 3, QTableWidgetItem(frame["protocol"]))
        # self.table.setItem(row, 4, QTableWidgetItem(frame["ip_source"]))
        # self.table.setItem(row, 5, QTableWidgetItem(frame["ip_dest"]))
        # self.table.setItem(row, 6, QTableWidgetItem(frame["port_source"]))
        # self.table.setItem(row, 7, QTableWidgetItem(frame["port_dest"]))
        # self.table.setItem(row, 8, QTableWidgetItem(frame["sequence_number"]))
        # self.table.setItem(row, 9, QTableWidgetItem(str(frame["ack_number"])))
        # self.table.setItem(row, 10, QTableWidgetItem(frame["payload"]))

    def init_table(self):
        table = QTableWidget(0, 11)
        table.setHorizontalHeaderItem(0, QTableWidgetItem("TYPE"))
        table.setColumnWidth(0, 80)
        table.setHorizontalHeaderItem(1, QTableWidgetItem("MAC_SOURCE"))
        table.setColumnWidth(1, 150)
        table.setHorizontalHeaderItem(2, QTableWidgetItem("MAC_DEST"))
        table.setColumnWidth(2, 150)
        table.setHorizontalHeaderItem(3, QTableWidgetItem("PROTOCOL"))
        table.setColumnWidth(3, 80)
        table.setHorizontalHeaderItem(4, QTableWidgetItem("IP_SOURCE"))
        table.setColumnWidth(4, 150)
        table.setHorizontalHeaderItem(5, QTableWidgetItem("IP_DEST"))
        table.setColumnWidth(5, 150)
        table.setHorizontalHeaderItem(6, QTableWidgetItem("P_SOURCE"))
        table.setColumnWidth(6, 100)
        table.setHorizontalHeaderItem(7, QTableWidgetItem("P_DEST"))
        table.setColumnWidth(7, 100)
        table.setHorizontalHeaderItem(8, QTableWidgetItem("SEQ_NUM"))
        table.setColumnWidth(8, 80)
        table.setHorizontalHeaderItem(9, QTableWidgetItem("ACK_NUM"))
        table.setColumnWidth(9, 120)
        table.setHorizontalHeaderItem(10, QTableWidgetItem("PAYLOAD"))
        table.setColumnWidth(10, 550)
        return table

    def load_into_table(self, frame_details):
        print("Load frame details into table ...")
        self.table.setRowCount(len(frame_details))
        row = 0
        for frame in frame_details:
            self.table.setItem(row, 0, QTableWidgetItem(str(frame["type"])))
            self.table.setItem(row, 1, QTableWidgetItem(str(frame["mac_source"])))
            self.table.setItem(row, 2, QTableWidgetItem(str(frame["mac_dest"])))
            self.table.setItem(row, 3, QTableWidgetItem(str(frame["protocol"])))
            self.table.setItem(row, 4, QTableWidgetItem(str(frame["ip_source"])))
            self.table.setItem(row, 5, QTableWidgetItem(str(frame["ip_dest"])))
            self.table.setItem(row, 6, QTableWidgetItem(str(frame["port_source"])))
            self.table.setItem(row, 7, QTableWidgetItem(str(frame["port_dest"])))
            self.table.setItem(row, 8, QTableWidgetItem(str(frame["sequence_number"])))
            self.table.setItem(row, 9, QTableWidgetItem(str(frame["ack_number"])))
            self.table.setItem(row, 10, QTableWidgetItem(str(frame["payload"])))
            row = row + 1
