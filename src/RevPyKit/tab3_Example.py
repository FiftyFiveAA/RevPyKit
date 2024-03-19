import PyQt6.QtCore as QtCore
import PyQt6.QtWidgets as QtWidgets
import PyQt6.QtGui as QtGui

def tab3_Example(self):
    ### CHILDREN
    # left layout
    left_layout = QtWidgets.QVBoxLayout()
    
    self.tab_example_button = QtWidgets.QPushButton("Example button")
    self.tab_example_button.clicked.connect(lambda: buttonRefresh(self))
    left_layout.addWidget(self.tab_example_button)

    self.tab_example_label = QtWidgets.QLabel("Example Label")
    left_layout.addWidget(self.tab_example_label)
        
    left_layout.addWidget(Color('red'))
    left_widget = QtWidgets.QWidget()
    left_widget.setLayout(left_layout)
    left_widget.setMinimumWidth(200)
 
    # center layout
    center_layout = QtWidgets.QVBoxLayout()
    center_layout.addWidget(Color('green'))
    center_widget = QtWidgets.QWidget()
    center_widget.setLayout(center_layout)
    center_widget.setMinimumWidth(200)
    # right layout
    right_layout = QtWidgets.QVBoxLayout()
    right_layout.addWidget(Color('red'))
    right_layout.addWidget(Color('yellow'))
    right_layout.addWidget(Color('blue'))
    right_widget = QtWidgets.QWidget()
    right_widget.setLayout(right_layout)
    right_widget.setMinimumWidth(200)
    # bottom layout
    bottom_layout = QtWidgets.QVBoxLayout()
    bottom_layout.addWidget(Color('green'))
    bottom_widget = QtWidgets.QWidget()
    bottom_widget.setLayout(bottom_layout)
    bottom_widget.setMinimumHeight(100)

    # Create the splitters so you can make each section
    # larger or smaller in the UI
    vert_splitter = QtWidgets.QSplitter()
    vert_splitter.addWidget(left_widget)
    vert_splitter.addWidget(center_widget)
    vert_splitter.addWidget(right_widget)
    vert_splitter.setSizes([10, 50, 40])
    vert_splitter.setMinimumHeight(300)
    #print(dir(vert_splitter))
    
    hori_splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
    hori_splitter.addWidget(vert_splitter)
    hori_splitter.addWidget(bottom_widget)
    hori_splitter.setSizes([70, 30])

    ### PARENT
    # the main layout for tab1
    tab2_layout = QtWidgets.QHBoxLayout()
    # Adds 5 px space around the outside
    tab2_layout.setContentsMargins(5,5,5,5)
    # Adds 5 px between each widget
    tab2_layout.setSpacing(5)
    # Add the widgets to our tab1_layout
    tab2_layout.addWidget(hori_splitter)
    tab2_widget = QtWidgets.QWidget()
    # if you don't do this then the background color of the tab is gray
    tab2_widget.setAutoFillBackground(True)
    tab2_widget.setLayout(tab2_layout)

    return tab2_widget

################ REFRESH BUTTON #######################
class buttonRefreshThread(QtCore.QThread):
    finished = QtCore.pyqtSignal()

    def run(self, main_window):
        print("Button clicked")
        main_window.tab_example_label.setText("Clicked")
        
        self.finished.emit()

def buttonRefresh(self):
    try:
        # Start a thread so the UI isn't hanging
        self.buttonRefreshWorker = buttonRefreshThread()
        self.buttonRefreshWorker_thread = QtCore.QThread()

        self.buttonRefreshWorker.moveToThread(self.buttonRefreshWorker_thread)
        self.buttonRefreshWorker.finished.connect(lambda: buttonRefreshFinished(self))
        
        self.buttonRefreshWorker_thread.started.connect(lambda: self.buttonRefreshWorker.run(self))
        self.buttonRefreshWorker_thread.start()

    except Exception as e:
        pass

def buttonRefreshFinished(self):
    # When the Refresh button is finished close the thread properly
    self.buttonRefreshWorker_thread.quit()
    self.buttonRefreshWorker_thread.wait()

class Color(QtWidgets.QWidget):

    def __init__(self, color):
        super(Color, self).__init__()
        self.setAutoFillBackground(True)

        palette = self.palette()
        palette.setColor(QtGui.QPalette.ColorRole.Window, QtGui.QColor(color))
        self.setPalette(palette)


