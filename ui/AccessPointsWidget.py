from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem

from utils.widget_utils import get_power_icon


class AccessPointsWidget(QTableWidget):
    def __init__(self):
        super().__init__()
        self.init_table()

    def init_table(self):
        self.setColumnCount(10)
        self.setHorizontalHeaderItem(0, QTableWidgetItem(""))
        self.setColumnWidth(0, 31)
        self.setHorizontalHeaderItem(1, QTableWidgetItem("ESSID"))
        self.setColumnWidth(1, 150)
        self.setHorizontalHeaderItem(2, QTableWidgetItem("BSSID"))
        self.setColumnWidth(2, 150)
        self.setHorizontalHeaderItem(3, QTableWidgetItem("MANUF"))
        self.setColumnWidth(3, 300)
        self.setHorizontalHeaderItem(4, QTableWidgetItem("POW"))
        self.setColumnWidth(4, 50)
        self.setHorizontalHeaderItem(5, QTableWidgetItem("CH"))
        self.setColumnWidth(5, 50)
        self.setHorizontalHeaderItem(6, QTableWidgetItem("FREQ"))
        self.setColumnWidth(6, 100)
        self.setHorizontalHeaderItem(7, QTableWidgetItem("CARRIER"))
        self.setColumnWidth(7, 150)
        self.setHorizontalHeaderItem(8, QTableWidgetItem("ENCRYPTION"))
        self.setColumnWidth(8, 300)
        self.setHorizontalHeaderItem(9, QTableWidgetItem("ENCODING"))
        self.setColumnWidth(9, 100)
        self.setRowCount(0)

    def load_into_table(self, access_points):
        print("Load access points into table ...")
        self.setRowCount(len(access_points))
        row = 0
        for access_point in access_points:
            self.setCellWidget(row, 0, get_power_icon(access_point["power"]))
            self.setItem(row, 1, QTableWidgetItem(access_point["essid"]))
            self.setItem(row, 2, QTableWidgetItem(access_point["bssid"]))
            self.setItem(row, 3, QTableWidgetItem(access_point["manuf"]))
            self.setItem(row, 4, QTableWidgetItem(access_point["power"]))
            self.setItem(row, 5, QTableWidgetItem(access_point["channel"]))
            self.setItem(row, 6, QTableWidgetItem(access_point["freq"]))
            self.setItem(row, 7, QTableWidgetItem(access_point["carrier"]))
            self.setItem(row, 8, QTableWidgetItem(access_point["encryption"]))
            self.setItem(row, 9, QTableWidgetItem(access_point["encoding"]))
            row = row + 1


