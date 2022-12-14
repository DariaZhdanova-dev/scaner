import ui
import sys

from PyQt5 import QtWidgets as qtw

if __name__ == "__main__":
    app = qtw.QApplication(sys.argv)
    window = ui.MainWindow()
    window.show()
    app.exec()
