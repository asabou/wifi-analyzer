from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot

from utils.analyzer_utils import get_access_points_details


class WorkerAccessPoints(QObject):
    completed = pyqtSignal(list)

    @pyqtSlot()
    def do_get_ac_details(self):
        print("Worker.do_get_ac_details()")
        acs = get_access_points_details()
        self.completed.emit(acs)
