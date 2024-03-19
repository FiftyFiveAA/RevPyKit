import PyQt6.QtCore as QtCore
import PyQt6.QtWidgets as QtWidgets
import PyQt6.QtGui as QtGui
import datetime
import os

def tab2_HexEditor(self):
    ### CHILDREN
    # top layout
    top_layout = QtWidgets.QVBoxLayout()
    
    self.tab2_Hex_table = QtWidgets.QTableWidget()
    self.tab2_Hex_table.setRowCount(5)
    self.tab2_Hex_table.setColumnCount(18)
    # add column names
    self.tab2_Hex_table.setHorizontalHeaderLabels(["Offset","00","01","02","03","04","05","06","07","08","09","0A","0B","0C","0D","0E","0F","Text"])
    # remove the "index" column for each row. We are going to add our own "offset" column
    self.tab2_Hex_table.verticalHeader().setVisible(False)
    # Stretch the table to fill up the layout
    #self.tab2_Hex_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeMode.Stretch)
    # set the column widths
    # I tried w/ stretch and other strategy's but I settled w/ hardcoding the widths
    self.tab2_Hex_table.setColumnWidth(0,80)
    self.tab2_Hex_table.setColumnWidth(1,20)
    self.tab2_Hex_table.setColumnWidth(2,20)
    self.tab2_Hex_table.setColumnWidth(3,20)
    self.tab2_Hex_table.setColumnWidth(4,20)
    self.tab2_Hex_table.setColumnWidth(5,20)
    self.tab2_Hex_table.setColumnWidth(6,20)
    self.tab2_Hex_table.setColumnWidth(7,20)
    self.tab2_Hex_table.setColumnWidth(8,20)
    self.tab2_Hex_table.setColumnWidth(9,20)
    self.tab2_Hex_table.setColumnWidth(10,20)
    self.tab2_Hex_table.setColumnWidth(11,20)
    self.tab2_Hex_table.setColumnWidth(12,20)
    self.tab2_Hex_table.setColumnWidth(13,20)
    self.tab2_Hex_table.setColumnWidth(14,20)
    self.tab2_Hex_table.setColumnWidth(15,20)
    self.tab2_Hex_table.setColumnWidth(16,20)
    self.tab2_Hex_table.setColumnWidth(17,425)
    
    top_layout.addWidget(self.tab2_Hex_table)
    top_widget = QtWidgets.QWidget()
    top_widget.setLayout(top_layout)

    # bottom layout
    bottom_layout = QtWidgets.QVBoxLayout()
    self.tab3_Hex_load_button = QtWidgets.QPushButton("Load File")
    self.tab3_Hex_load_button.clicked.connect(lambda: loadButton(self))
    self.tab3_Hex_load_button.setMaximumWidth(100)
    self.tab3_Hex_save_button = QtWidgets.QPushButton("Save File")
    self.tab3_Hex_save_button.clicked.connect(lambda: saveButton(self))
    self.tab3_Hex_save_button.setMaximumWidth(100)
    bottom_layout.addWidget(self.tab3_Hex_load_button)
    bottom_layout.addWidget(self.tab3_Hex_save_button)
    bottom_widget = QtWidgets.QWidget()
    bottom_widget.setLayout(bottom_layout)
    bottom_widget.setMinimumHeight(100)

    # Create the splitters so you can make each section
    # larger or smaller in the UI
    
    hori_splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
    hori_splitter.addWidget(top_widget)
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

# Class for Hex Table to ensure edited contents
# are only hexadecimal characters
class HexDelegate(QtWidgets.QStyledItemDelegate):
    def createEditor(self, parent, option, index):

        # Create the line edit as the editor
        editor = QtWidgets.QLineEdit(parent)
        print(index.model().data(index, QtCore.Qt.ItemDataRole.DisplayRole))
        # Don't apply rules to first or last column
        if(index.column() == 0 or index.column() == 17):
            pass
        else:
            # Set validator to accept only two hexadecimal characters
            regex = QtCore.QRegularExpression("[0-9A-Fa-f]{1,2}")
            validator = QtGui.QRegularExpressionValidator(regex, editor)
            editor.setValidator(validator)
        return editor

################ Load File BUTTON #######################
class loadButtonThread(QtCore.QThread):
    finished = QtCore.pyqtSignal()

    def run(self, main_window):
        try:
            #print(self.chosen_file)
##            i = QtWidgets.QTableWidgetItem("Hello")
##            i.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
##            i.setFlags(i.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
##            main_window.tab2_Hex_table.setItem(1,2, i)
##            main_window.tab2_Hex_table.setItem(0,0, QtWidgets.QTableWidgetItem("00000000"))
##            main_window.tab2_Hex_table.setItem(1,0, QtWidgets.QTableWidgetItem("00000010"))
##            main_window.tab2_Hex_table.setItem(0,1, QtWidgets.QTableWidgetItem("ff"))
            #for i in range(0,5):
                #self.tab2_Hex_table.setItem(1,2, QtWidgets.QTableWidgetItem("Hello"))

            try:
                with open(main_window.chosen_file, "rb") as f:
                    file_contents = f.read()

                # number of rows needed in UI
                # Since each row has 16 bytes
                rows_needed = int(len(file_contents)/16) + 1
                main_window.tab2_Hex_table_rows_needed = rows_needed
                main_window.tab2_Hex_table.setRowCount(rows_needed)
                # go through each row and fill out the offset column
                offset = 0
                for row in range(0, rows_needed):
                    offset_str = hex(offset)[2:].upper().zfill(8)
                    i = QtWidgets.QTableWidgetItem(offset_str)
                    i.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
                    i.setFlags(i.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
                    main_window.tab2_Hex_table.setItem(row, 0, i)
                    offset += 16
                
                row_bytes = []
                row_counter = 0
                column_counter = 1
                for byte in file_contents:
                    # convert the byte (int) into a hex string for UI
                    byte_str = hex(byte)[2:].upper().zfill(2)
                    i = QtWidgets.QTableWidgetItem(byte_str)
                    i.setTextAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
                    #i.setFlags(i.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)

                    main_window.tab2_Hex_table.setItem(row_counter, column_counter, i)
                    row_bytes.append(byte)
                    column_counter += 1
                    # reached the end of the column, turn bytes into ascii and go to next row
                    if(column_counter == 17):
                        row_bytes_str = ""
                        # if byte is human readble then show it
                        # else show a period
                        for i in row_bytes:
                            if(i >= 32 and i <= 127):
                                row_bytes_str += chr(i)
                            else:
                                row_bytes_str += "."
                        i = QtWidgets.QTableWidgetItem(row_bytes_str)
                        i.setFlags(i.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
                        main_window.tab2_Hex_table.setItem(row_counter, column_counter, i)
                        # go to next row
                        column_counter = 1
                        row_counter += 1
                        row_bytes = []

                # Make sure each column with hexadecimals when edited
                # only allows hexadecimals
                HexDelegateInstance = HexDelegate()
                for i in range(0,rows_needed):
                    main_window.tab2_Hex_table.setItemDelegateForRow(i, HexDelegateInstance)   
                    
            except Exception as e:
                print(e)

            self.finished.emit()
        except:
            pass

def loadButton(self):
    try:
        # Start a thread so the UI isn't hanging
        self.loadButtonWorker = loadButtonThread()
        self.loadButtonWorker_thread = QtCore.QThread()

        self.loadButtonWorker.moveToThread(self.loadButtonWorker_thread)
        self.loadButtonWorker.finished.connect(lambda: loadButtonFinished(self))
        
        self.loadButtonWorker_thread.started.connect(lambda: self.loadButtonWorker.run(self))
        self.loadButtonWorker_thread.start()

    except Exception as e:
        pass

def loadButtonFinished(self):
    # When the Load button is finished close the thread properly
    self.loadButtonWorker_thread.quit()
    self.loadButtonWorker_thread.wait()
#########################################################

################ Save File BUTTON #######################
class saveButtonThread(QtCore.QThread):
    finished = QtCore.pyqtSignal()

    def run(self, main_window):
        try:
            modified_bytes = b""
            for row in range(0,main_window.tab2_Hex_table_rows_needed):
                for col in range(1, 17):
                    item = main_window.tab2_Hex_table.item(row, col)
                    # Convert cell hex string to bytes
                    try:
                        modified_bytes += bytes.fromhex(item.text())
                    except:
                        pass

            # write our bytes to a file
            file_name = "hex_edit_" + datetime.datetime.now().isoformat() + ".txt"
            file_name = file_name.replace(":",".")
            file_path = os.getcwd() + "\\output\\"
            # make sure output folder exists
            if(not os.path.exists(file_path)):
                os.mkdir(file_path)
            with open(file_path + file_name, "wb") as f:
                f.write(modified_bytes)

            self.finished.emit()
        except:
            pass

def saveButton(self):
    try:
        # Start a thread so the UI isn't hanging
        self.saveButtonWorker = saveButtonThread()
        self.saveButtonWorker_thread = QtCore.QThread()

        self.saveButtonWorker.moveToThread(self.saveButtonWorker_thread)
        self.saveButtonWorker.finished.connect(lambda: saveButtonFinished(self))
        
        self.saveButtonWorker_thread.started.connect(lambda: self.saveButtonWorker.run(self))
        self.saveButtonWorker_thread.start()

    except Exception as e:
        pass

def saveButtonFinished(self):
    # When the Load button is finished close the thread properly
    self.saveButtonWorker_thread.quit()
    self.saveButtonWorker_thread.wait()
###########################################
    

class Color(QtWidgets.QWidget):

    def __init__(self, color):
        super(Color, self).__init__()
        self.setAutoFillBackground(True)

        palette = self.palette()
        palette.setColor(QtGui.QPalette.ColorRole.Window, QtGui.QColor(color))
        self.setPalette(palette)


