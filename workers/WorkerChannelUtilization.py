from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot

from utils.analyzer_utils import get_access_points_details


class WorkerChannelUtilization(QObject):
    completed = pyqtSignal(list)

    @pyqtSlot()
    def do_get_channel_utilization(self):
        print("Worker.do_get_channel_utilization()")
        acs = get_access_points_details()
        self.completed.emit(acs)