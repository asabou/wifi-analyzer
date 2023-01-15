from PyQt5.QtCore import pyqtSignal, Qt, QThread
from PyQt5.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QPushButton, QLabel, QComboBox, QVBoxLayout, \
    QStackedWidget

from ui.AccessPointsWidget import AccessPointsWidget
from ui.ChannelUtilizationWidget import ChannelUtilizationWidget
from ui.SnifferWidget import SnifferWidget
from utils.analyzer_utils import change_mode, is_monitor_mode
from workers.WorkerAccessPoints import WorkerAccessPoints
from workers.WorkerChannelUtilization import WorkerChannelUtilization


class MainWindow(QMainWindow):
    table_widget_access_points = None
    widget_sniffer = None
    table_widget_channel_utilization = None

    worker_acp = None
    worker_acp_thread = None
    worker_acp_requested = pyqtSignal()

    worker_sniff = None
    worker_sniff_thread = None
    worker_sniff_requested = pyqtSignal()

    worker_channel = None
    worker_channel_thread = None
    worker_channel_requested = pyqtSignal()

    stacked_widget = None

    btn_access_points = None
    btn_channel_utilization = None
    btn_channel_graphic = None
    btn_sniffer = None
    combobox_interface_mode = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setWindowTitle("WIFI-Analyzer")
        self.resize(1800, 925)

        self.widget = QWidget()
        self.setCentralWidget(self.widget)
        self.main_layout = QVBoxLayout()
        self.widget.setLayout(self.main_layout)
        self.main_layout.addWidget(self.get_menu_widget(), 0, alignment=Qt.AlignTop)
        self.stacked_widget = QStackedWidget()

        self.table_widget_access_points = AccessPointsWidget()
        self.widget_sniffer = SnifferWidget(self.combobox_interface_mode)
        self.table_widget_channel_utilization = ChannelUtilizationWidget()

        self.stacked_widget.addWidget(self.table_widget_access_points)
        self.stacked_widget.addWidget(self.table_widget_channel_utilization)
        self.stacked_widget.addWidget(self.widget_sniffer)
        self.main_layout.addWidget(self.stacked_widget)

        self.worker_acp = WorkerAccessPoints()
        self.worker_acp_thread = QThread()
        self.worker_acp.completed.connect(self.on_get_ac_details_completed)
        self.worker_acp_requested.connect(self.worker_acp.do_get_ac_details)
        self.worker_acp.moveToThread(self.worker_acp_thread)
        self.worker_acp_thread.start()

        self.worker_channel = WorkerChannelUtilization()
        self.worker_channel_thread = QThread()
        self.worker_channel.completed.connect(self.on_get_channel_utilization_completed)
        self.worker_channel_requested.connect(self.worker_channel.do_get_channel_utilization)
        self.worker_channel.moveToThread(self.worker_channel_thread)
        self.worker_channel_thread.start()

        # self.on_access_points_clicked()
        self.on_channel_utilization_clicked()
        self.show()

    def get_menu_widget(self):
        menu_widget = QWidget()
        menu_layout = QHBoxLayout()
        self.btn_access_points = QPushButton("Access Points", clicked=self.on_access_points_clicked)
        self.btn_channel_utilization = QPushButton("Channel Utilization", clicked=self.on_channel_utilization_clicked)
        self.btn_sniffer = QPushButton("Sniffer", clicked=self.on_sniffer_clicked)
        label_mode = QLabel("Mode:")
        label_mode.setAlignment(Qt.AlignHorizontal_Mask)
        self.combobox_interface_mode = QComboBox()
        self.combobox_interface_mode.addItems(["Monitor", "Managed"])
        self.combobox_interface_mode.currentTextChanged.connect(self.on_interface_mode_text_changed)
        if is_monitor_mode():
            self.combobox_interface_mode.setCurrentIndex(0)
        else:
            self.combobox_interface_mode.setCurrentIndex(1)
        menu_layout.addWidget(self.btn_access_points)
        menu_layout.addWidget(self.btn_channel_utilization)
        menu_layout.addWidget(self.btn_sniffer)
        menu_layout.addWidget(label_mode)
        menu_layout.addWidget(self.combobox_interface_mode)
        menu_widget.setLayout(menu_layout)
        return menu_widget

    def on_get_ac_details_completed(self, acs):
        print("On get ac details completed..")
        self.table_widget_access_points.load_into_table(acs)
        self.combobox_interface_mode.setEnabled(True)
        self.btn_channel_utilization.setEnabled(True)

    def on_get_channel_utilization_completed(self, acs):
        print("On channel utilization completed ...")
        channels = []
        for i in range(1, 14):
            channel = {"channel": i, "stations": 0, "rating": ""}
            for ac in acs:
                if int(ac["channel"]) == i:
                    channel["stations"] = channel["stations"] + 1
            channels.append(channel)
        self.table_widget_channel_utilization.load_into_table(channels)
        self.combobox_interface_mode.setEnabled(True)
        self.btn_access_points.setEnabled(True)

    def on_access_points_clicked(self):
        print("Access Points clicked ...")
        self.combobox_interface_mode.setEnabled(False)
        self.combobox_interface_mode.setCurrentIndex(0)
        self.btn_channel_utilization.setEnabled(False)
        self.stacked_widget.setCurrentIndex(0)
        self.worker_acp_requested.emit()

    def on_channel_utilization_clicked(self):
        print("On Channel Rating clicked ...")
        self.combobox_interface_mode.setEnabled(False)
        self.btn_access_points.setEnabled(False)
        self.stacked_widget.setCurrentIndex(1)
        self.worker_channel_requested.emit()

    def on_sniffer_clicked(self):
        print("On Sniffer clicked ...")
        self.stacked_widget.setCurrentIndex(2)

    def on_interface_mode_text_changed(self, mode):
        print("on mode changed ... ", mode)
        change_mode(mode)
