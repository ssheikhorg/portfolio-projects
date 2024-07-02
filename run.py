import sys

from PyQt5.QtWidgets import QApplication

from playlist.playlist import ScheduleManager

if __name__ == '__main__':
    print("Starting application")
    app = QApplication(sys.argv)
    ex = ScheduleManager()
    ex.show()
    print("Application running")
    sys.exit(app.exec_())
