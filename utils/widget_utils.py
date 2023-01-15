from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QLabel

'''
    Description of interval
    [0, 65) = green
    [65, 85) = orange
    [85, inf) = red
'''
def get_power_icon(power):
    path = "./images/rsz_wifi_red.png"
    if power != "":
        power = -int(power)
        if power < 65:
            path = "./images/rsz_wifi_green.png"
        if 65 <= power < 85:
            path = "./images/rsz_wifi_yellow.png"
    label = QLabel()
    pixmap = QPixmap(path)
    label.setPixmap(pixmap)
    return label
