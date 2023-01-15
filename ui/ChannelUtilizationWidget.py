from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem


class ChannelUtilizationWidget(QTableWidget):
    def __init__(self):
        super().__init__()
        self.init_table()

    def init_table(self):
        self.setColumnCount(3)
        self.setHorizontalHeaderItem(0, QTableWidgetItem("Channel"))
        self.setColumnWidth(0, 200)
        self.setHorizontalHeaderItem(1, QTableWidgetItem("Stations"))
        self.setColumnWidth(1, 200)
        self.setHorizontalHeaderItem(2, QTableWidgetItem("Rating"))
        self.setColumnWidth(2, 200)
        self.setRowCount(0)

    def load_into_table(self, channels):
        self.setRowCount(len(channels))
        row = 0
        for channel in channels:
            self.setItem(row, 0, QTableWidgetItem(str(channel["channel"])))
            self.setItem(row, 1, QTableWidgetItem(str(channel["stations"])))
            self.setItem(row, 2, QTableWidgetItem(str(channel["rating"])))
            row = row + 1
