import pandas as pd

from PyQt5 import QtWidgets, QtCore, QtGui

from . import main_window_ui as ui
import scaner


class MainWindow(ui.Ui_MainWindow, QtWidgets.QMainWindow, scaner.ScanerAdapter):

    def __init__(self):
        ui.Ui_MainWindow.__init__(self)
        QtWidgets.QMainWindow.__init__(self)
        scaner.ScanerAdapter.__init__(self)

        self.setupUi(self)
        self.showMaximized()

        self.table_update_timer = QtCore.QTimer()
        self.table_update_timer.timeout.connect(self._update_proc_table)
        self.table_update_timer.start(10000)

        self.proc_table_model = PandasModel()
        self.table_view.setModel(self.proc_table_model)

        self.btn_actions = {
            "pe": self._proc_pe,
            "mem": self._proc_memory,
            "capa": self._proc_capa,
            "packer": self._proc_packer
        }
        self.button_pe.clicked.connect(lambda: self._on_button_proc("pe"))
        self.button_packer.clicked.connect(lambda: self._on_button_proc("packer"))
        self.button_capa.clicked.connect(lambda: self._on_button_proc("capa"))
        self.button_memeory.clicked.connect(lambda: self._on_button_proc("mem"))

    def _on_button_proc(self, btn_name: str):
        try:
            pid = int(self.pid_input.text())
            desc = self.btn_actions[btn_name](pid)
            self.desc_text.setText(desc)
        except Exception as ex:
            self.desc_text.setText(f"invalid input\n{ex}")

    def _update_proc_table(self):
        try:
            table = self.get_proc_table()
            self.table_view.setModel(PandasModel(table))
        except Exception as ex:
            print(repr(ex))


class PandasModel(QtCore.QAbstractTableModel):
    def __init__(self, data: pd.DataFrame = pd.DataFrame({}), parent=None):
        QtCore.QAbstractTableModel.__init__(self, parent)
        self._data = data

    def rowCount(self, parent=None):
        return len(self._data.values)

    def columnCount(self, parent=None):
        return self._data.columns.size - 1

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if index.isValid():
            if role == QtCore.Qt.DisplayRole:
                return QtCore.QVariant(str(
                    self._data.iloc[index.row()][index.column()]))
            if role == QtCore.Qt.BackgroundRole and self._data["repr"][index.row()]:
                return QtGui.QBrush(QtCore.Qt.red)

        return QtCore.QVariant()

    def headerData(self, col, orientation, role):
        if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
            return self._data.columns[col]
        return None
