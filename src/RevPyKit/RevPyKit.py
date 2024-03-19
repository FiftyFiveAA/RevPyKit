import PyQt6.QtCore as QtCore
import PyQt6.QtWidgets as QtWidgets
import PyQt6.QtGui as QtGui

import tab1_Analysis
import tab2_HexEditor
import tab3_Example


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        # Variables to know about
        # self.chosen_file  # Will contain the filepath of the selected file

        self.setWindowTitle("RevPyKit")

        # Create a menu bar
        menu = self.menuBar()
        
        # Create the top level dropdowns
        file_menu = menu.addMenu("&File")
        
        # Create the "file" dropdown
        action_file_open = QtGui.QAction("Open", self)
        action_file_open.triggered.connect(self.actionFileOpen)
        file_menu.addAction(action_file_open)

        file_menu.addSeparator()

        # Create layout for the tabs
        self.tab_layout = QtWidgets.QVBoxLayout()
        self.tab_widget = QtWidgets.QTabWidget()
        self.tab_layout.addWidget(self.tab_widget)        

        # Get the widget for tab1
        tab1 = tab1_Analysis.tab1_Analysis(self)
        self.tab_widget.addTab(tab1, "File Analysis")

        # Get the widget for tab2
        tab2 = tab2_HexEditor.tab2_HexEditor(self)
        self.tab_widget.addTab(tab2, "Hex Editor")

        # Get the widget for tab2
        tab3 = tab3_Example.tab3_Example(self)
        self.tab_widget.addTab(tab3, "Example")        

        # Add the widget as the central widget
        self.setCentralWidget(self.tab_widget)


        # set the default window size
        self.resize(1080, 720)
        # Add an icon for the program
        self.setWindowIcon(QtGui.QIcon("images/55aa.png"))
        # Show the UI window
        self.show()


    def clicked(self, checked):
        #print(checked)
        pass

    def mousePressEvent(self, event):
        #print("Mouse pressed!")
        super().mousePressEvent(event)

    def contextMenuEvent(self, e):
        context = QtWidgets.QMenu(self)
        #context.addAction(QtGui.QAction("test 1", self))
        #context.addAction(QtGui.QAction("test 2", self))
        #context.addAction(QtGui.QAction("test 3", self))
        context.exec(e.globalPos())

    def actionFileOpen(self):       
        try:
            # Create a file dialog where the user can choose any file
            chosen_file = QtWidgets.QFileDialog.getOpenFileName(self, "Open file", )[0]
            # If the user didn't hit cancel on the file dialog
            if(chosen_file != ""):
                try:
                    # remove the previous widget if it existed
                    self.statusBar().removeWidget(self.chosen_file_label)
                except Exception as e:
                    pass
                self.chosen_file = chosen_file
                # Create a label with the chosen file path
                self.chosen_file_label = QtWidgets.QLabel(self.chosen_file)
                # Show the chosen file on the bottom of the screen
                self.statusBar().addPermanentWidget(self.chosen_file_label)

        except Exception as e:
            pass

class Color(QtWidgets.QWidget):

    def __init__(self, color):
        super(Color, self).__init__()
        self.setAutoFillBackground(True)

        palette = self.palette()
        palette.setColor(QtGui.QPalette.ColorRole.Window, QtGui.QColor(color))
        self.setPalette(palette)
        

if(__name__ == "__main__"):
    app = QtWidgets.QApplication([])
    app.setStyle("Fusion")

    window = MainWindow()

    app.exec()
