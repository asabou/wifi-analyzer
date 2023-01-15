import sys

from PyQt5.QtWidgets import QApplication

from ui.MainWindow import MainWindow
from utils.analyzer_utils import get_all_frame_details, start_sniff
from utils.widget_utils import get_power_icon

app = QApplication(sys.argv)
window = MainWindow()
sys.exit(app.exec())

# start_sniff()

