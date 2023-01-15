import scapy.all as scapy
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot

from utils.analyzer_utils import is_monitor_mode, get_mac_frame_details_from_buffer, \
    get_ethernet_frame_details_from_buffer


class WorkerSniffer(QObject):
    progress = pyqtSignal(object)
    is_monitor = None
    stop = False

    @pyqtSlot()
    def do_sniff(self):
        interface = "wlp2s0"
        self.is_monitor = is_monitor_mode()
        if self.is_monitor:
            interface = interface + "mon"
        scapy.sniff(iface=interface, store=False, prn=self.process_pack, stop_filter=self.stop_filter)

        # sniffer = Sniff(interface, count=-1, out_file="./os/pcap.pcap")
        # for len, ts, buf in sniffer.capture():
        #     if is_monitor:
        #         self.progress.emit(get_mac_frame_details_from_buffer(buf))
        #     else:
        #         self.progress.emit(get_ethernet_frame_details_from_buffer(buf))

    def process_pack(self, pack):
        buf = bytes(pack)
        if self.is_monitor:
            self.progress.emit(get_mac_frame_details_from_buffer(buf))
        else:
            self.progress.emit(get_ethernet_frame_details_from_buffer(buf))

    def stop_filter(self, packet):
        return self.stop == True

    def set_stop(self, stop):
        self.stop = stop
