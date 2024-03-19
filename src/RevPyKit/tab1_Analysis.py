import PyQt6.QtCore as QtCore
import PyQt6.QtWidgets as QtWidgets
import PyQt6.QtGui as QtGui
import hashlib
import datetime
import os
import json
from tab1_Analysis_PE import analyzePE

def tab1_Analysis(self):
    ### left layout
    left_layout = QtWidgets.QVBoxLayout()

    # Refresh button
    self.tab1_Analysis_refresh_button = QtWidgets.QPushButton("Analyze")
    self.tab1_Analysis_refresh_button.clicked.connect(lambda: buttonRefresh(self))
    self.tab1_Analysis_refresh_button.setMaximumWidth(50)

    # Initialize the label where our text will go
    self.tab1_Analysis_file_label = QtWidgets.QLabel("")
    # make the text copy pasteable
    self.tab1_Analysis_file_label.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
    # enable word wrap
    self.tab1_Analysis_file_label.setWordWrap(True)
    # enable html
    self.tab1_Analysis_file_label.setTextFormat(QtCore.Qt.TextFormat.RichText)

    left_layout.addWidget(self.tab1_Analysis_refresh_button)
    left_layout.addWidget(self.tab1_Analysis_file_label)
    left_widget = QtWidgets.QWidget()
    left_widget.setLayout(left_layout)
    left_widget.setMinimumWidth(200)
    
    ### right layout
    right_layout = QtWidgets.QVBoxLayout()

    # Initialize the label where our text will go
    self.tab1_Analysis_exe_label = QtWidgets.QLabel("")
    
    #self.tab1_Analysis_exe_label.setStyleSheet('''background-color:#262626;''')
    # make the text copy pasteable
    self.tab1_Analysis_exe_label.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
    # enable word wrap
    self.tab1_Analysis_exe_label.setWordWrap(True)
    # enable html
    self.tab1_Analysis_exe_label.setTextFormat(QtCore.Qt.TextFormat.RichText)
    # scroll bars
    self.tab1_Analysis_exe_scrollArea = QtWidgets.QScrollArea()
    self.tab1_Analysis_exe_scrollArea.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
    self.tab1_Analysis_exe_scrollArea.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
    self.tab1_Analysis_exe_scrollArea.setWidgetResizable(True)
    self.tab1_Analysis_exe_scrollArea.setWidget(self.tab1_Analysis_exe_label)

    right_layout.addWidget(self.tab1_Analysis_exe_scrollArea)
    right_widget = QtWidgets.QWidget()
    right_widget.setLayout(right_layout)
    right_widget.setMinimumWidth(200)
    
    ### bottom layout
    bottom_layout = QtWidgets.QHBoxLayout()
    # create the splitter for the string search area
    bottom_hori_splitter = QtWidgets.QSplitter()
    # bottom left side
    bottom_left_side = QtWidgets.QWidget()
    bottom_left_layout = QtWidgets.QVBoxLayout()
            # Extract strings button
    self.tab1_Analysis_search_extract_button = QtWidgets.QPushButton("Extract Strings from File")
    self.tab1_Analysis_search_extract_button.clicked.connect(lambda: buttonSearchExtract(self))
    self.tab1_Analysis_search_extract_button.setMaximumWidth(200)
    bottom_left_layout.addWidget(self.tab1_Analysis_search_extract_button)
            # search description
    self.tab1_Analysis_string_search_description = QtWidgets.QLabel("All of the strings will be stored in the 'output' folder in the cwd")
    bottom_left_layout.addWidget(self.tab1_Analysis_string_search_description)
            # search input field
    bottom_left_search_layout = QtWidgets.QHBoxLayout()
    bottom_left_search_widget = QtWidgets.QWidget()
    self.tab1_Analysis_string_search_value = QtWidgets.QLineEdit("")
                    # customize the search input field a bit
    #self.tab1_Analysis_string_search_value.setStyleSheet('''QLineEdit{border: 1px solid #808080;background-color:#1a1a1a;}''')
    bottom_left_search_layout.addWidget(QtWidgets.QLabel("String Search"))
    bottom_left_search_layout.addWidget(self.tab1_Analysis_string_search_value)
    bottom_left_search_widget.setLayout(bottom_left_search_layout)
    bottom_left_layout.addWidget(bottom_left_search_widget)
            # search for string button
    self.tab1_Analysis_search_button = QtWidgets.QPushButton("Search for String")
    self.tab1_Analysis_search_button.clicked.connect(lambda: buttonSearch(self))
    self.tab1_Analysis_search_button.setMaximumWidth(200)
    bottom_left_layout.addWidget(self.tab1_Analysis_search_button)
            # clear strings from memory button
    self.tab1_Analysis_clear_button = QtWidgets.QPushButton("Clear Strings from Memory (for efficiency)")
    self.tab1_Analysis_clear_button.clicked.connect(lambda: buttonClear(self))
    self.tab1_Analysis_clear_button.setMaximumWidth(250)
    bottom_left_layout.addWidget(self.tab1_Analysis_clear_button)
            # progress bar
    self.tab1_Analysis_progress_bar = QtWidgets.QProgressBar()
    self.tab1_Analysis_progress_bar.setValue(0)
    bottom_left_layout.addWidget(self.tab1_Analysis_progress_bar)
            # set the bottom left layout
    #bottom_left_side.setStyleSheet('''background-color:#262626;''')
    bottom_left_side.setLayout(bottom_left_layout)
    # bottom right side
    bottom_right_side = QtWidgets.QWidget()
    bottom_right_layout = QtWidgets.QVBoxLayout()
    #bottom_right_side.setStyleSheet('''background-color:#262626;''')
    bottom_right_side.setMinimumWidth(335)
            # text area where strings will go, needs to have scroll bar
    self.tab1_Analysis_extractedStrings = QtWidgets.QLabel("")
    self.tab1_Analysis_extractedStrings.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
    self.tab1_Analysis_extractedStrings_scrollArea = QtWidgets.QScrollArea()
    self.tab1_Analysis_extractedStrings_scrollArea.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
    self.tab1_Analysis_extractedStrings_scrollArea.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    self.tab1_Analysis_extractedStrings_scrollArea.setWidgetResizable(True)
    self.tab1_Analysis_extractedStrings_scrollArea.setWidget(self.tab1_Analysis_extractedStrings)
    bottom_right_layout.addWidget(self.tab1_Analysis_extractedStrings_scrollArea)
    bottom_right_side.setLayout(bottom_right_layout)
    # bottom
    bottom_hori_splitter.addWidget(bottom_left_side)
    bottom_hori_splitter.addWidget(bottom_right_side)
    bottom_hori_splitter.setSizes([50,50])
    bottom_layout.addWidget(bottom_hori_splitter)
    bottom_widget = QtWidgets.QWidget()
    bottom_widget.setLayout(bottom_layout)
    bottom_widget.setMinimumHeight(160)

    # Create the splitters so you can make each section
    # larger or smaller in the UI
    vert_splitter = QtWidgets.QSplitter()
    vert_splitter.addWidget(left_widget)
    vert_splitter.addWidget(right_widget)
    vert_splitter.setSizes([20, 80])
    vert_splitter.setMinimumHeight(300)
    
    hori_splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
    hori_splitter.addWidget(vert_splitter)
    hori_splitter.addWidget(bottom_widget)
    hori_splitter.setSizes([70, 30])

    ### PARENT
    # the main layout for tab1
    tab1_layout = QtWidgets.QHBoxLayout()
    # Adds 5 px space around the outside
    tab1_layout.setContentsMargins(5,5,5,5)
    # Adds 5 px between each widget
    tab1_layout.setSpacing(5)
    # Add the widgets to our tab1_layout
    tab1_layout.addWidget(hori_splitter)
    tab1_widget = QtWidgets.QWidget()
    # if you don't do this then the background color of the tab is gray
    tab1_widget.setAutoFillBackground(True)
    tab1_widget.setLayout(tab1_layout)

    return tab1_widget

################ REFRESH BUTTON #######################
class buttonRefreshThread(QtCore.QThread):
    finished = QtCore.pyqtSignal()

    def run(self, main_window):
        try:           
            # Open the file and store the bytes
            with open(main_window.chosen_file, "rb") as f:
                file_contents = f.read()

            # Hash the file
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()

            md5.update(file_contents)
            sha1.update(file_contents)
            sha256.update(file_contents)

            # for the magic bytes always show the first 20 in both hex and ascii
            magic_bytes = file_contents[:20]
            magic_bytes_hex_string = ""
            magic_bytes_hex = ""
            # Go through the first 20 bytes
            for b in magic_bytes:
                # Get the hex representation of the byte w/o the 0x prepended
                # Add a space so it looks nicer in the UI
                magic_bytes_hex += hex(b).replace("0x","").zfill(2).upper() + " "
                # Show the ASCII representation of each byte if possible
                if(chr(b).isascii()):
                    magic_bytes_hex_string += chr(b)
                else:
                    # Show a "." if it's not ASCII
                    magic_bytes_hex_string += "."
                    
            magic_bytes_hex = magic_bytes_hex[:-1]

            # Check the first 20 bytes against our list of file signatures
            file_sig = ""
            # Go through each of our file signatures
            for sig in FILE_SIGNATURES:
                # Get our signature magic bytes "00 ff aa"
                sig_magic_bytes = sig[0].split(" ")
                match = True
                # Go through each byte in our signature
                for i in range(0,len(sig_magic_bytes)):
                    try:
                        if(sig_magic_bytes[i] == "??"):
                            continue
                        if(hex(file_contents[i]).replace("0x","").zfill(2).upper() != sig_magic_bytes[i]):
                            match = False
                            break
                    except:
                        break
                if(match):
                    file_sig = "<b>File Signature Match:</b> " + sig[0] + "<br>"
                    if(sig[1] != ""):
                        file_sig += "<b>File Signature Extension:</b> " + sig[1] + "<br>"
                    file_sig += "<b>File Signature Description:</b> " + sig[2]
                    break

            # Output all the info in HTML format
            contents = "<html>"
            contents += main_window.chosen_file
            contents += "<br><br>"
            contents += "<b>MD5:</b> " + md5.hexdigest().upper()
            contents += "<br>"
            contents += "<b>SHA1:</b> " + sha1.hexdigest().upper()
            contents += "<br>"
            contents += "<b>SHA256:</b> " + sha256.hexdigest().upper()
            contents += "<br><br>"
            contents += "<b>File Size:</b> " + format(len(file_contents), ",d") + " bytes"
            contents += "<br><br>"
            contents += "<b>File Header Hex:</b> " + magic_bytes_hex
            contents += "<br>"
            contents += "<b>File Header ASCII:</b> " + magic_bytes_hex_string
            contents += "<br>"
            contents += file_sig           
            contents += "</html>"

            main_window.tab1_Analysis_file_label.setText(contents)

            # Create dict for our JSON file
            file_analysis_json = {}
            file_analysis_json["Overview"] = {
                "fileName": main_window.chosen_file,
                "MD5": md5.hexdigest().upper(),
                "SHA1": sha1.hexdigest().upper(),
                "SHA256": sha256.hexdigest().upper(),
                "fileSize": format(len(file_contents), ",d") + " bytes",
                }
        except Exception as e:
            pass

        # If the file is a PE then parse some basic information
        try:
            exe_analysis = ""
            if(file_contents[0:2] == b"MZ"):
                exe_analysis = ""
                # Call our other python script to extract the PE fields
                exe_analysis, exe_analysis_json = analyzePE(file_contents)
                # Show the contents on the top right panel
                main_window.tab1_Analysis_exe_label.setText(exe_analysis)
                # Update our dict/JSON file w/ our PE info
                file_analysis_json["PE"] = exe_analysis_json
            ### Add other files of focus here ###
            #elif():
                #pass

            # write our dict to a JSON file
            file_name = "file_analysis_" + datetime.datetime.now().isoformat() + ".txt"
            file_name = file_name.replace(":",".")
            file_path = os.getcwd() + "\\output\\"
            # make sure output folder exists
            if(not os.path.exists(file_path)):
                os.mkdir(file_path)
            with open(file_path + file_name, "w") as f:
                f.write(json.dumps(file_analysis_json, indent=4))
            
        except Exception as e:
            print(e)
            main_window.tab1_Analysis_exe_label.setText(exe_analysis)

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

################ REFRESH BUTTON #######################

################ EXTRACT STRINGS BUTTON #######################
class buttonSearchExtractThread(QtCore.QThread):
    finished = QtCore.pyqtSignal()

    def run(self, main_window):
        # only extract strings of at least this length
        MINIMUM_STRING_LENGTH = 5
        try:
            # if a file has been chosen then open it
            if(main_window.chosen_file):
                with open(main_window.chosen_file, "rb") as f:
                    file_contents = f.read()
                # we are going to update self which in this case is called main_window
                # other tabs, and functionality on the analysis tab can use these strings
                # we are going to parse and put in this set
                main_window.tab1_Analysis_extractedStrings_set = set()
                # now we have a byte array stored in file_contents which we need to extract
                # all the strings from

                # set the progress bar to 0
                progess = 0
                main_window.tab1_Analysis_progress_bar.setValue(0)
                # total number of tasks
                total_tasks = 3  # number of tasks we're going to do
                task_weight = 1/total_tasks  # this is used for our progress bar calculations
                completed_tasks = 0

                def updateProgress(main_window, completed_tasks, task_weight, file_content_len, char_counter):
                    # set the progress to the number of completed tasks
                    progress = int((completed_tasks * task_weight) * 100)
                    # get our progress of going through the file
                    progress_percentage = 1 - ((file_content_len-char_counter)/file_content_len)
                    # add in our file progress to our total number of tasks
                    progress += int((progress_percentage*task_weight) * 100)
                    # set the value of our progress bar
                    main_window.tab1_Analysis_progress_bar.setValue(progress)
                    
                # ASCII ##################################################
                ### Human Readable Character Range
                ascii_start_range = 0x20  # space
                ascii_end_range = 0x7e  # ~
                ### we'll use this variable to track partially collected strings
                char_collector = ""
                char_counter = 0
                ### Go through each byte in the file
                for byte in file_contents:
                    # if byte is human readable (ASCII)
                    if(byte >= ascii_start_range and byte <= ascii_end_range):
                        char_collector += chr(byte)
                    else:
                        # we've reached a non human readable byte
                        # check if our char collector has enough readable bytes
                        if(len(char_collector) >= MINIMUM_STRING_LENGTH):
                            # add the extracted string to our list
                            main_window.tab1_Analysis_extractedStrings_set.add(char_collector)
                        # reset the char collector
                        char_collector = ""
                    char_counter += 1
                    # every 1000 bytes update the progress bar
                    if(char_counter % 1000 == 0):
                        updateProgress(main_window, completed_tasks, task_weight, len(file_contents), char_counter)
                ### ASCII Test complete
                updateProgress(main_window, completed_tasks, task_weight, len(file_contents), char_counter)
                completed_tasks += 1

                # UTF-16BE ##################################################
                ### Human Readable Character Range
                ascii_start_range = 0x20  # space
                ascii_end_range = 0x7e  # ~
                ### we'll use this variable to track partially collected strings
                char_collector = ""
                char_counter = 0
                ### Go through every 2 bytes in the file
                counter = 0
                ### Create a boolean variable that will flip to true when we find to bytes that match what we're looking for ex: 0044
                skip = False
                try:
                    for i in range(0,len(file_contents)):
                        # if we found a valid sequence of bytes then skip this round
                        # AKA step forward 2 bytes
                        if(skip == True):
                            skip = False
                            continue
                        # if byte is human readable UTF-16BE English
                        if(file_contents[i] == 0 and file_contents[i+1] >= ascii_start_range and file_contents[i+1] <= ascii_end_range):
                            char_collector += chr(file_contents[i+1])
                            skip = True
##                            if(len(char_collector) > 2):
##                                print(char_collector + "\n\n")
                        else:
                            # we've reached a non human readable byte
                            # check if our char collector has enough readable bytes
                            if(len(char_collector) >= MINIMUM_STRING_LENGTH):
                                # add the extracted string to our list
                                main_window.tab1_Analysis_extractedStrings_set.add(char_collector)
                            # reset the char collector
                            char_collector = ""

                        char_counter += 1
                        # every 1000 bytes update the progress bar
                        if(char_counter % 1000 == 0):
                            updateProgress(main_window, completed_tasks, task_weight, len(file_contents), char_counter)
                except Exception as e:
                    pass
                ### ASCII Test complete
                updateProgress(main_window, completed_tasks, task_weight, len(file_contents), char_counter)
                completed_tasks += 1

                # UTF-16LE ##################################################
                ### Human Readable Character Range
                ascii_start_range = 0x20  # space
                ascii_end_range = 0x7e  # ~
                ### we'll use this variable to track partially collected strings
                char_collector = ""
                char_counter = 0
                ### Go through every 2 bytes in the file
                counter = 0
                ### Create a boolean variable that will flip to true when we find to bytes that match what we're looking for ex: 0044
                skip = False
                try:
                    for i in range(0,len(file_contents)):
                        # if we found a valid sequence of bytes then skip this round
                        # AKA step forward 2 bytes
                        if(skip == True):
                            skip = False
                            continue
                        # if byte is human readable UTF-16LE English
                        if(file_contents[i+1] == 0 and file_contents[i] >= ascii_start_range and file_contents[i] <= ascii_end_range):
                            char_collector += chr(file_contents[i])
                            skip = True
                        else:
                            # we've reached a non human readable byte
                            # check if our char collector has enough readable bytes
                            if(len(char_collector) >= MINIMUM_STRING_LENGTH):
                                # add the extracted string to our list
                                main_window.tab1_Analysis_extractedStrings_set.add(char_collector)
                            # reset the char collector
                            char_collector = ""

                        char_counter += 1
                        # every 1000 bytes update the progress bar
                        if(char_counter % 1000 == 0):
                            updateProgress(main_window, completed_tasks, task_weight, len(file_contents), char_counter)
                except Exception as e:
                    pass
                ### ASCII Test complete
                updateProgress(main_window, completed_tasks, task_weight, len(file_contents), char_counter)
                completed_tasks += 1


                # Update the UI w/ our first 1000 strings
                # the UI gets to slow if there's more than that
                # save the rest of the strings to a file
                strings = []
                i = 0
                for string in main_window.tab1_Analysis_extractedStrings_set:
                    i += 1
                    if(i == 1000):
                        break
                    strings.append(string)
                    
                main_window.tab1_Analysis_extractedStrings.setText("\n".join(strings))
                file_name = "strings_" + datetime.datetime.now().isoformat() + ".txt"
                file_name = file_name.replace(":",".")
                file_path = os.getcwd() + "\\output\\"
                # make sure output folder exists
                if(not os.path.exists(file_path)):
                    os.mkdir(file_path)
                with open(file_path + file_name, "w") as f:
                    for string in main_window.tab1_Analysis_extractedStrings_set:
                        f.write(string + "\n")

                # set the progress bar to 100%
                main_window.tab1_Analysis_progress_bar.setValue(100)
        except Exception as e:
            pass
        
        self.finished.emit()

def buttonSearchExtract(self):
    try:
        # Start a thread so the UI isn't hanging
        self.buttonSearchExtractWorker = buttonSearchExtractThread()
        self.buttonSearchExtractWorker_thread = QtCore.QThread()

        self.buttonSearchExtractWorker.moveToThread(self.buttonSearchExtractWorker_thread)
        self.buttonSearchExtractWorker.finished.connect(lambda: buttonSearchExtractFinished(self))
        
        self.buttonSearchExtractWorker_thread.started.connect(lambda: self.buttonSearchExtractWorker.run(self))
        self.buttonSearchExtractWorker_thread.start()

    except Exception as e:
        pass

def buttonSearchExtractFinished(self):
    # When the Refresh button is finished close the thread properly
    self.buttonSearchExtractWorker_thread.quit()
    self.buttonSearchExtractWorker_thread.wait()
################ EXTRACT STRINGS BUTTON #######################
    
################ SEARCH BUTTON #######################
class buttonSearchThread(QtCore.QThread):
    finished = QtCore.pyqtSignal()

    def run(self, main_window):
        try:           
            # get the value to search for
            searchTerm = main_window.tab1_Analysis_string_search_value.text()
            # Clear the UI of strings
            main_window.tab1_Analysis_extractedStrings.setText("")
            matched_strings = []
            # iterate through our list of extracted strings
            for string in main_window.tab1_Analysis_extractedStrings_set:
                if(searchTerm.lower() in string.lower()):
                    matched_strings.append(string)
            # update the UI
            main_window.tab1_Analysis_extractedStrings.setText("\n".join(matched_strings[:1000]))

            file_name = "strings_" + datetime.datetime.now().isoformat() + ".txt"
            file_name = file_name.replace(":",".")
            file_path = os.getcwd() + "\\output\\"
            # make sure output folder exists
            if(not os.path.exists(file_path)):
                os.mkdir(file_path)
            with open(file_path + file_name, "w") as f:
                for string in matched_strings:
                    f.write(string + "\n")

        except Exception as e:
            print(e)
        
        self.finished.emit()

def buttonSearch(self):
    try:
        # Start a thread so the UI isn't hanging
        self.buttonSearchWorker = buttonSearchThread()
        self.buttonSearchWorker_thread = QtCore.QThread()

        self.buttonSearchWorker.moveToThread(self.buttonSearchWorker_thread)
        self.buttonSearchWorker.finished.connect(lambda: buttonSearchFinished(self))
        
        self.buttonSearchWorker_thread.started.connect(lambda: self.buttonSearchWorker.run(self))
        self.buttonSearchWorker_thread.start()

    except Exception as e:
        pass

def buttonSearchFinished(self):
    # When the Refresh button is finished close the thread properly
    self.buttonSearchWorker_thread.quit()
    self.buttonSearchWorker_thread.wait()
################ SEARCH BUTTON #######################


################ CLEAR BUTTON #######################
class buttonClearThread(QtCore.QThread):
    finished = QtCore.pyqtSignal()

    def run(self, main_window):
        try:           
            main_window.tab1_Analysis_extractedStrings_set = set()

        except Exception as e:
            pass
        
        self.finished.emit()

def buttonClear(self):
    try:
        # Start a thread so the UI isn't hanging
        self.buttonClearWorker = buttonClearThread()
        self.buttonClearWorker_thread = QtCore.QThread()

        self.buttonClearWorker.moveToThread(self.buttonClearWorker_thread)
        self.buttonClearWorker.finished.connect(lambda: buttonClearFinished(self))
        
        self.buttonClearWorker_thread.started.connect(lambda: self.buttonClearWorker.run(self))
        self.buttonClearWorker_thread.start()

    except Exception as e:
        pass

def buttonClearFinished(self):
    # When the Refresh button is finished close the thread properly
    self.buttonClearWorker_thread.quit()
    self.buttonClearWorker_thread.wait()
################ CLEAR BUTTON #######################

    
class Color(QtWidgets.QWidget):

    def __init__(self, color):
        super(Color, self).__init__()
        self.setAutoFillBackground(True)

        palette = self.palette()
        palette.setColor(QtGui.QPalette.ColorRole.Window, QtGui.QColor(color))
        self.setPalette(palette)


FILE_SIGNATURES = [["23 21", "", "Script or data to be passed to the program following the shebang (#!)[1]"],
["00 00 02 00 06 04 06 00 08 00 00 00 00 00", "wk1", "Lotus 1-2-3 spreadsheet (v1) file"],
["00 00 1A 00 00 10 04 00 00 00 00 00", "wk3", "Lotus 1-2-3 spreadsheet (v3) file"],
["00 00 1A 00 02 10 04 00 00 00 00 00", "wk4", "Lotus 1-2-3 spreadsheet (v4, v5) file"],
["00 00 1A 00 05 10 04", "", "Lotus 1-2-3 spreadsheet (v9) file"],
["00 00 03 F3", "", "Amiga Hunk executable file"],
["00 00 49 49 58 50 52", "qxd", "Quark Express document"],
["00 00 4D 4D 58 50 52", "", "Quark Express document"],
["50 57 53 33", "psafe3", "Password Gorilla Password Database"],
["D4 C3 B2 A1", "pcap", "Libpcap File Format[2]"],
["A1 B2 C3 D4", "pcap", "Libpcap File Format[2]"],
["4D 3C B2 A1", "pcap", "Libpcap File Format (nanosecond-resolution)[2]"],
["A1 B2 3C 4D", "pcap", "Libpcap File Format (nanosecond-resolution)[2]"],
["0A 0D 0D 0A", "pcapng", "PCAP Next Generation Dump File Format[3]"],
["ED AB EE DB", "rpm", "RedHat Package Manager (RPM) package[4]"],
["53 51 4C 69 74 65 20 66", "sqlitedb", "SQLite Database[5]"],
["6F 72 6D 61 74 20 33 00", "sqlitedb", "SQLite Database[5]"],
["53 50 30 31", "bin", "Amazon Kindle Update Package[6]"],
["49 57 41 44", "wad", "internal WAD (main resource file of Doom)[7]"],
["BE BA FE CA", "DBA", "Palm Desktop Calendar Archive"],
["00 01 42 44", "DBA", "Palm Desktop To Do Archive"],
["00 01 44 54", "TDA", "Palm Desktop Calendar Archive"],
["54 44 46 24", "TDF$", "Telegram Desktop File"],
["54 44 45 46", "TDEF", "Telegram Desktop Encrypted File"],
["00 01 00 00", "", "Palm Desktop Data File (Access format)"],
["00 00 01 00", "ico", "Computer icon encoded in ICO file format[8]"],
["69 63 6e 73", "icns", "Apple Icon Image format"],
["1F 9D", "tar.z", "compressed file (often tar zip) using Lempel-Ziv-Welch algorithm"],
["1F A0", "tar.z", "Compressed file (often tar zip) using LZH algorithm"],
["42 41 43 4B 4D 49 4B 45", "bac", "AmiBack Amiga Backup data file"],
["44 49 53 4B", "bac", "AmiBack Amiga Backup data file"],
["49 4E 44 58", "idx", "AmiBack Amiga Backup index file"],
["62 70 6C 69 73 74", "plist", "Binary Property List file"],
["42 5A 68", "bz2", "Compressed file using Bzip2 algorithm"],
["47 49 46 38 37 61", "gif", "Image file encoded in the Graphics Interchange Format (GIF)[9]"],
["47 49 46 38 39 61", "gif", "Image file encoded in the Graphics Interchange Format (GIF)[9]"],
["49 49 2A 00", "tif", "Tagged Image File Format (TIFF)[10]"],
["4D 4D 00 2A", "tif", "Tagged Image File Format (TIFF)[10]"],
["49 49 2A 00 10 00 00 00", "cr2", "Canon RAW Format Version 2[11]"],
["43 52", "cr2", "Canon RAW Format Version 2[11]"],
["80 2A 5F D7", "cin", "Kodak Cineon image"],
["52 4E 43 01", "", "Compressed file using Rob Northen Compression (version 1 and 2) algorithm"],
["52 4E 43 02", "", "Compressed file using Rob Northen Compression (version 1 and 2) algorithm"],
["4E 55 52 55 49 4D 47", "nui", "nuru ASCII/ANSI image and palette files"],
["4E 55 52 55 50 41 4C", "nui", "nuru ASCII/ANSI image and palette files"],
["53 44 50 58", "dpx", "SMPTE DPX image"],
["58 50 44 53", "dpx", "SMPTE DPX image"],
["76 2F 31 01", "exr", "OpenEXR image"],
["42 50 47 FB", "bpg", "Better Portable Graphics format[13]"],
["FF D8 FF DB", "jpg", "JPEG raw or in the JFIF or Exif file format"],
["FF D8 FF E0 00 10 4A 46 49 46 00 01", "jpg", "JPEG raw or in the JFIF or Exif file format"],
["FF D8 FF EE", "jpg", "JPEG raw or in the JFIF or Exif file format"],
["FF D8 FF E1 ?? ?? 45 78 69 66 00 00", "jpg", "JPEG raw or in the JFIF or Exif file format"],
["FF D8 FF E0", "jpg", "JPEG raw or in the JFIF or Exif file format[14]"],
["00 00 00 0C 6A 50 20 20 0D 0A 87 0A", "jp2", "JPEG 2000 format"],
["FF 4F FF 51", "jp2", "JPEG 2000 format"],
["71 6f 69 66", "qoi", "QOI - The “Quite OK Image Format”[16]"],
["46 4F 52 4D ?? ?? ?? ?? 49 4C 42 4D", "ilbm", "IFF Interleaved Bitmap Image"],
["46 4F 52 4D ?? ?? ?? ?? 38 53 56 58", "8svx", "IFF 8-Bit Sampled Voice"],
["46 4F 52 4D ?? ?? ?? ?? 41 43 42 4D", "acbm", "Amiga Contiguous Bitmap"],
["46 4F 52 4D ?? ?? ?? ?? 41 4E 42 4D", "anbm", "IFF Animated Bitmap"],
["46 4F 52 4D ?? ?? ?? ?? 41 4E 49 4D", "anim", "IFF CEL Animation"],
["46 4F 52 4D ?? ?? ?? ?? 46 41 58 58", "faxx", "IFF Facsimile Image"],
["46 4F 52 4D ?? ?? ?? ?? 46 54 58 54", "ftxt", "IFF Formatted Text"],
["46 4F 52 4D ?? ?? ?? ?? 53 4D 55 53", "smus", "IFF Simple Musical Score"],
["46 4F 52 4D ?? ?? ?? ?? 43 4D 55 53", "cmus", "IFF Musical Score"],
["46 4F 52 4D ?? ?? ?? ?? 59 55 56 4E", "yuvn", "IFF YUV Image"],
["46 4F 52 4D ?? ?? ?? ?? 46 41 4E 54", "iff", "Amiga Fantavision Movie"],
["46 4F 52 4D ?? ?? ?? ?? 41 49 46 46", "aiff", "Audio Interchange File Format"],
["4C 5A 49 50", "lz", "lzip compressed file[17]"],
["30 37 30 37 30 37", "cpio", "cpio archive file[18]"],
["4D 5A", "exe", "DOS MZ executable and its descendants (including NE and PE)"],
["5A 4D", "exe", "DOS ZM executable and its descendants (rare)"],
["50 4B 03 04", "zip", "zip file format and formats based on it, such as EPUB, JAR, ODF, OOXML"],
["50 4B 05 06", "zip", "zip file format and formats based on it, such as EPUB, JAR, ODF, OOXML"],
["50 4B 07 08", "zip", "zip file format and formats based on it, such as EPUB, JAR, ODF, OOXML"],
["52 61 72 21 1A 07 00", "rar", "Roshal ARchive compressed archive v1.50 onwards[19]"],
["52 61 72 21 1A 07 01 00", "rar", "Roshal ARchive compressed archive v5.00 onwards[20]"],
["7F 45 4C 46", "", "Executable and Linkable Format"],
["89 50 4E 47 0D 0A 1A 0A", "png", "Image encoded in the Portable Network Graphics format[21]"],
["C9", "com", "CP/M 3 and higher with overlays[22]"],
["CA FE BA BE", "class", "Java class file, Mach-O Fat Binary"],
["EF BB BF", "txt", "UTF-8 byte order mark, commonly seen in text files.[23][24][25]"],
["FF FE", "txt", "UTF-16LE byte order mark, commonly seen in text files.[23][24][25]"],
["FE FF", "txt", "UTF-16BE byte order mark, commonly seen in text files.[23][24][25]"],
["FF FE 00 00", "txt", "UTF-32LE byte order mark for text[23][25]"],
["00 00 FE FF", "txt", "UTF-32BE byte order mark for text[23][25]"],
["2B 2F 76 38", "", "UTF-7 byte order mark for text[26][25]"],
["2B 2F 76 39", "", "UTF-7 byte order mark for text[26][25]"],
["2B 2F 76 2B", "", "UTF-7 byte order mark for text[26][25]"],
["2B 2F 76 2F", "", "UTF-7 byte order mark for text[26][25]"],
["0E FE FF", "txt", "SCSU byte order mark for text[26][25]"],
["DD 73 66 73", "", "UTF-EBCDIC byte order mark for text[26][25]"],
["FE ED FA CE", "", "Mach-O binary (32-bit)"],
["FE ED FA CF", "", "Mach-O binary (64-bit)"],
["FE ED FE ED", "", "JKS JavakeyStore"],
["CE FA ED FE", "", "Mach-O binary (reverse byte ordering scheme, 32-bit)[27]"],
["CF FA ED FE", "", "Mach-O binary (reverse byte ordering scheme, 64-bit)[27]"],
["25 21 50 53", "ps", "PostScript document"],
["25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 30 20 45 50 53 46 2D 33 2E 30", "eps", "Encapsulated PostScript file version 3.0[28]"],
["25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 31 20 45 50 53 46 2D 33 2E 30", "eps", "Encapsulated PostScript file version 3.1[28]"],
["49 54 53 46 03 00 00 00 60 00 00 00", "chm", "MS Windows HtmlHelp Data"],
["3F 5F", "hlp", "Windows 3.x/95/98 Help file"],
["25 50 44 46 2D", "pdf", "PDF document[29]"],
["30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C", "asf", "Advanced Systems Format[30]"],
["24 53 44 49 30 30 30 31", "", "System Deployment Image, a disk image format used by Microsoft"],
["4F 67 67 53", "ogg", "Ogg, an open source media container format"],
["38 42 50 53", "psd", "Photoshop Document file, Adobe Photoshop's native file format"],
["52 49 46 46 ?? ?? ?? ?? 57 41 56 45", "wav", "Waveform Audio File Format[31]"],
["52 49 46 46 ?? ?? ?? ?? 41 56 49 20", "avi", "Audio Video Interleave video format[32]"],
["FF FB", "mp3", "MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which is appended at the end of the file)"],
["FF F3", "mp3", "MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which is appended at the end of the file)"],
["FF F2", "mp3", "MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which is appended at the end of the file)"],
["49 44 33", "mp3", "MP3 file with an ID3v2 container"],
["42 4D", "bmp", "BMP file, a bitmap format used mostly in the Windows world"],
["6D 61 69 6E 2E 62 73", "mgw", "Nintendo Game & Watch image file"],
["4E 45 53", "nes", "Nintendo Entertainment System image file"],
["47 53 52 2D 31 35 34 31", "g64", "Commodore 64 1541 disk image (G64 format)"],
["43 36 34 20 74 61 70 65 20 69 6D 61 67 65 20 66 69 6C 65", "t64", "Commodore 64 tape image"],
["43 36 34 20 43 41 52 54 52 49 44 47 45 20 20 20", "crt", "Commodore 64 cartridge image"],
["53 49 4D 50 4C 45 20 20", "fits", "Flexible Image Transport System (FITS)[34]"],
["66 4C 61 43", "flac", "Free Lossless Audio Codec[35]"],
["4D 54 68 64", "mid", "MIDI sound file[36]"],
["D0 CF 11 E0 A1 B1 1A E1", "doc", "Compound File Binary Format, a container format defined by Microsoft COM. It can contain the equivalent of files and directories. It is used by Windows Installer and for documents in older versions of Microsoft Office.[37] It can be used by other programs as well that rely on the COM and OLE API's."],
["64 65 78 0A 30 33 35 00", "dex", "Dalvik Executable"],
["4B 44 4D", "vmdk", "VMDK files[38][39]"],
["23 20 44 69 73 6B 20 44 65 73 63 72 69 70 74 6F", "vmdk", "VMware 4 Virtual Disk description file (split disk)"],
["43 72 32 34", "crx", "Google Chrome extension[40] or packaged app[41]"],
["41 47 44 33", "fh8", "FreeHand 8 document[42][43]"],
["05 07 00 00 42 4F 42 4F", "cwk", "AppleWorks 5 document"],
["06 07 E1 00 42 4F 42 4F", "cwk", "AppleWorks 6 document"],
["45 52 02 00 00 00", "toast", "Roxio Toast disc image file"],
["8B 45 52 02 00 00 00", "toast", ""],
["78 61 72 21", "xar", "eXtensible ARchive format[44]"],
["50 4D 4F 43 43 4D 4F 43", "dat", "Windows Files And Settings Transfer Repository[45] See also USMT 3.0 (Win XP)[46] and USMT 4.0 (Win 7)[47] User Guides"],
["4E 45 53 1A", "nes", "Nintendo Entertainment System ROM file[48]"],
["4F 41 52 ??", "oar", "OAR file archive format, where ?? is the format version."],
["74 6F 78 33", "tox", "Open source portable voxel file[50]"],
["4D 4C 56 49", "MLV", "Magic Lantern Video file[51]"],
["44 43 4D 01 50 41 33 30", "", "Windows Update Binary Delta Compression file[52]"],
["37 7A BC AF 27 1C", "7z", "7-Zip File Format"],
["1F 8B", "gz", "GZIP compressed file[53]"],
["FD 37 7A 58 5A 00", "xz", "XZ compression utility"],
["04 22 4D 18", "lz4", "LZ4 Frame Format[54]"],
["4D 53 43 46", "cab", "Microsoft Cabinet file"],
["53 5A 44 44 88 F0 27 33", "", "Microsoft compressed file in Quantum format, used prior to Windows XP. File can be decompressed using Extract.exe or Expand.exe distributed with earlier versions of Windows. After compression, the last character of the original filename extension is replaced with an underscore, e.g. ‘Setup.exe’ becomes ‘Setup.ex_’."],
["46 4C 49 46", "flif", "Free Lossless Image Format"],
["1A 45 DF A3", "mkv", "Matroska media container, including WebM"],
["4D 49 4C 20", "stg", "SEAN : Session Analysis Training file. Also used in compatible software Rpw : Rowperfect for Windows and RP3W : ROWPERFECT3 for Windows."],
["41 54 26 54 46 4F 52 4D", "djvu", "DjVu document"],
["30 82", "der", "DER encoded X.509 certificate"],
["2D 2D 2D 2D 2D 42 45 47 49 4E 20 43 45 52 54 49 46 49 43 41 54 45 2D 2D 2D 2D 2D", "crt", "PEM encoded X.509 certificate"],
["2D 2D 2D 2D 2D 42 45 47 49 4E 20 43 45 52 54 49 46 49 43 41 54 45 20 52 45 51 55 45 53 54 2D 2D 2D 2D 2D", "csr", "PEM encoded X.509 Certificate Signing Request"],
["2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D", "key", "PEM encoded X.509 PKCS#8 private key"],
["2D 2D 2D 2D 2D 42 45 47 49 4E 20 44 53 41 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D", "key", "PEM encoded X.509 PKCS#1 DSA private key"],
["2D 2D 2D 2D 2D 42 45 47 49 4E 20 52 45 41 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D", "key", "PEM encoded X.509 PKCS#1 RSA private key"],
["50 75 54 54 59 2D 55 73 65 72 2D 4B 65 79 2D 46 69 6C 65 2D 32 3A", "ppk", "PuTTY private key file version 2"],
["50 75 54 54 59 2D 55 73 65 72 2D 4B 65 79 2D 46 69 6C 65 2D 33 3A", "ppk", "PuTTY private key file version 3"],
["2D 2D 2D 2D 2D 42 45 47 49 4E 20 4F 50 45 4E 53 53 48 20 50 52 49 56 41 54 45 20 4B 45 59 2D 2D 2D 2D 2D", "", "OpenSSH private key file"],
["2D 2D 2D 2D 2D 42 45 47 49 4E 20 53 53 48 32 20 4B 45 59 2D 2D 2D 2D 2D", "pub", "OpenSSH public key file"],
["77 4F 46 46", "woff", "WOFF File Format 1.0"],
["77 4F 46 32", "woff2", "WOFF File Format 2.0"],
["3C 3F 78 6D 6C 20", "xml", "eXtensible Markup Language[24][56]"],
["3C 00 3F 00 78 00 6D 00 6C 00 20", "xml", "eXtensible Markup Language[24][56]"],
["00 3C 00 3F 00 78 00 6D 00 6C 00 20", "xml", "eXtensible Markup Language[24][56]"],
["3C 00 00 00 3F 00 00 00", "xml", "eXtensible Markup Language[24][56]"],
["00 00 00 3C 00 00 00 3F", "xml", "eXtensible Markup Language[24][56]"],
["4C 6F A7 94 93 40", "xml", "eXtensible Markup Language[24][56]"],
["00 61 73 6D", "wasm", "WebAssembly binary format[57]"],
["CF 84 01", "lep", "Lepton compressed JPEG image[58]"],
["43 57 53", "swf", "Adobe Flash .swf"],
["46 57 53", "swf", "Adobe Flash .swf"],
["21 3C 61 72 63 68 3E 0A", "deb", "linux deb file"],
["52 49 46 46 ?? ?? ?? ?? 57 45 42 50", "webp", "Google WebP image file, where ?? ?? ?? ?? is the file size. More information on WebP File Header"],
["27 05 19 56", "", "U-Boot / uImage. Das U-Boot Universal Boot Loader.[59]"],
["7B 5C 72 74 66 31", "rtf", "Rich Text Format"],
["54 41 50 45", "", "Microsoft Tape Format"],
["47", "ts", "MPEG Transport Stream (MPEG-2 Part 1)[60]"],
["00 00 01 BA", "m2p", "MPEG Program Stream (MPEG-1 Part 1 (essentially identical) and MPEG-2 Part 1)"],
["00 00 01 B3", "mpg", "MPEG-1 video and MPEG-2 video (MPEG-1 Part 2 and MPEG-2 Part 2)"],
["78 01", "zlib", "No Compression (no preset dictionary)"],
["78 5E", "zlib", "Best speed (no preset dictionary)"],
["78 9C", "zlib", "Default Compression (no preset dictionary)"],
["78 DA", "zlib", "Best Compression (no preset dictionary)"],
["78 20", "zlib", "No Compression (with preset dictionary)"],
["78 7D", "zlib", "Best speed (with preset dictionary)"],
["78 BB", "zlib", "Default Compression (with preset dictionary)"],
["78 F9", "zlib", "Best Compression (with preset dictionary)"],
["62 76 78 32", "lzfse", "LZFSE - Lempel-Ziv style data compression algorithm using Finite State Entropy coding. OSS by Apple.[61]"],
["4F 52 43", "orc", "Apache ORC (Optimized Row Columnar) file format"],
["4F 62 6A 01", "avro", "Apache Avro binary file format"],
["53 45 51 36", "rc", "RCFile columnar file format"],
["3C 72 6F 62 6C 6F 78 21", "rbxl", "Roblox place file [62]"],
["65 87 78 56", "p25", "PhotoCap Object Templates"],
["55 55 AA AA", "pcv", "PhotoCap Vector"],
["78 56 34", "pbt", "PhotoCap Template"],
["50 41 52 31", "", "Apache Parquet columnar file format"],
["45 4D 58 32", "ez2", "Emulator Emaxsynth samples"],
["45 4D 55 33", "ez3", "Emulator III synth samples"],
["1B 4C 75 61", "luac", "Lua bytecode[63]"],
["62 6F 6F 6B 00 00 00 00", "alias", "macOS file Alias[64] (Symbolic link)"],
["6D 61 72 6B 00 00 00 00", "alias", "macOS file Alias[64] (Symbolic link)"],
["5B 5A 6F 6E 65 54 72 61", "Identifier", "Microsoft Zone Identifier for URL Security Zones[65]"],
["52 65 63 65 69 76 65 64", "eml", "Email Message var5[citation needed]"],
["20 02 01 62 A0 1E AB 07", "tde", "Tableau Datasource"],
["37 48 03 02 00 00 00 00", "kdb", "KDB file"],
["85 ?? ?? 03", "pgp", "PGP file [66]"],
["28 B5 2F FD", "zst", "Zstandard compress[67][68]"],
["52 53 56 4B 44 41 54 41", "rs", "QuickZip rs compressed archive[69][70]"],
["3A 29 0A", "sml", "Smile file"],
["4A 6F 79 21", "", "Preferred Executable Format"],
["31 0A 30 30", "srt", "SubRip File"],
["34 12 AA 55", "vpk", "VPK file, used to store game data for some Source Engine games"],
["60 EA", "arj", "ARJ"],
["49 53 63 28", "cab", "InstallShield CAB Archive File"],
["4B 57 41 4A", "", "Windows 3.1x Compressed File"],
["53 5A 44 44", "", "Windows 9x Compressed File"],
["5A 4F 4F", "zoo", "Zoo (file format)"],
["50 31 0A", "pbm", "Portable bitmap ASCII"],
["50 34 0A", "pbm", "Portable bitmap binary"],
["50 32 0A", "pgm", "Portable Gray Map ASCII"],
["50 35 0A", "pgm", "Portable Gray Map binary"],
["50 33 0A", "ppm", "Portable Pixmap ASCII"],
["50 36 0A", "ppm", "Portable Pixmap binary"],
["D7 CD C6 9A", "wmf", "Windows Metafile"],
["67 69 6D 70 20 78 63 66", "xcf", "XCF (file format)"],
["2F 2A 20 58 50 4D 20 2A", "xpm", "X PixMap"],
["41 46 46", "aff", "Advanced Forensics Format"],
["45 56 46 32", "Ex01", "EnCase EWF version 2 format"],
["45 56 46", "e01", "EnCase EWF version 1 format"],
["51 46 49", "qcow", "qcow file format"],
["52 49 46 46 ?? ?? ?? ?? 41 43 4F 4E", "ani", "Animated cursor"],
["52 49 46 46 ?? ?? ?? ?? 43 44 44 41", "cda", ".cda file"],
["52 49 46 46 ?? ?? ?? ?? 51 4C 43 4D", "qcp", "Qualcomm PureVoice file format"],
["52 49 46 58 ?? ?? ?? ?? 46 47 44 4D", "dcr", "Adobe Shockwave[71][72][73]"],
["58 46 49 52 ?? ?? ?? ?? 4D 44 47 46", "dcr", "Adobe Shockwave[71][72][73]"],
["52 49 46 58 ?? ?? ?? ?? 4D 56 39 33", "dir", "Macromedia Director file format[74][72][73]"],
["58 46 49 52 ?? ?? ?? ?? 33 39 56 4D", "dir", "Macromedia Director file format[74][72][73]"],
["46 4C 56", "flv", "Flash Video file"],
["3C 3C 3C 20 4F 72 61 63", "vdi", "VirtualBox Virtual Hard Disk file format"],
["6C 65 20 56 4D 20 56 69", "vdi", "VirtualBox Virtual Hard Disk file format"],
["72 74 75 61 6C 42 6F 78", "vdi", "VirtualBox Virtual Hard Disk file format"],
["20 44 69 73 6B 20 49 6D", "vdi", "VirtualBox Virtual Hard Disk file format"],
["61 67 65 20 3E 3E 3E", "vdi", "VirtualBox Virtual Hard Disk file format"],
["63 6F 6E 6E 65 63 74 69", "vhd", "Windows Virtual PC Virtual Hard Disk file format"],
["76 68 64 78 66 69 6C 65", "vhdx", "Windows Virtual PC Windows 8 Virtual Hard Disk file format"],
["49 73 5A 21", "isz", "Compressed ISO image"],
["44 41 41", "daa", "Direct Access Archive PowerISO"],
["4C 66 4C 65", "evt", "Windows Event Viewer file format"],
["45 6C 66 46 69 6C 65", "evtx", "Windows Event Viewer XML file format"],
["50 4D 43 43", "grp", "Windows 3.x Program Manager Program Group file format"],
["4B 43 4D 53", "icm", "ICC profile"],
["72 65 67 66", "dat", "Windows Registry file"],
["21 42 44 4E", "pst", "Microsoft Outlook Personal Storage Table file"],
["44 52 41 43 4F", "drc", "3D model compressed with Google Draco[75]"],
["47 52 49 42", "grib", "Gridded data (commonly weather observations or forecasts) in the WMO GRIB or GRIB2 format[76]"],
["42 4C 45 4E 44 45 52", "blend", "Blender File Format[77]"],
["00 00 00 0C 4A 58 4C 20 0D 0A 87 0A", "jxl", "Image encoded in the JPEG XL format[78]"],
["00 01 00 00 00", "ttf", "TrueType font"],
["4F 54 54 4F", "otf", "OpenType font[79]"],
["23 25 4D 6F 64 75 6C 65", "", "Modulefile for Environment Modules[80]"],
["4D 53 57 49 4D 00 00 00", "wim", "Windows Imaging Format file"],
["21 2D 31 53 4C 4F 42 1F", "slob", "Slob (sorted list of blobs) is a read-only, compressed data store with dictionary-like interface[81]"],
["AC ED", "", "Serialized Java Data[82]"],
["43 72 65 61 74 69 76 65 20 56 6F 69 63 65 20 46 69 6C 65 1A 1A 00", "voc", "Creative Voice file"],
["2E 73 6E 64", "au", "Au audio file format"],
["DB 0A CE 00", "", "OpenGL Iris Perfomer .PFB (Performer Fast Binary)[83]"],
["48 5a 4c 52 00 00 00 18", "hazelrules", "Noodlesoft Hazel [84]"],
["46 4C 68 64", "flp", "FL Studio Project File"],
["31 30 4C 46", "flm", "FL Studio Mobile Project File"],
["52 4b 4d 43 32 31 30", "", "Vormetric Encryption DPM Version 2.1 Header[85]"],
["00 01 00 00 4D 53 49 53 41 4D 20 44 61 74 61 62 61 73 65", "mny", "Microsoft Money file"],
["00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42", "accdb", "Microsoft Access 2007 Database"],
["00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42", "mdb", "Microsoft Access Database"],
["01 FF 02 04 03 02", "drw", "Micrografx vector graphic file"],
["02 64 73 73", "dss", "Digital Speech Standard (Olympus, Grundig, & Phillips) v2"],
["03 64 73 73", "dss", "Digital Speech Standard (Olympus, Grundig, & Phillips) v3"],
["03 00 00 00 41 50 50 52", "adx", "Approach index file"],
["06 06 ED F5 D8 1D 46 E5 BD 31 EF E7 FE 74 B7 1D", "indd", "Adobe InDesign document"],
["06 0E 2B 34 02 05 01 01 0D 01 02 01 01 02", "mxf", "Material Exchange Format file"],
["07 53 4B 46", "skf", "SkinCrafter skin file"],
["07 64 74 32 64 64 74 64", "dtd", "DesignTools 2D Design file"],
["0A 16 6F 72 67 2E 62 69 74 63 6F 69 6E 2E 70 72", "wallet", "MultiBit Bitcoin wallet file"],
["0D 44 4F 43", "doc", "DeskMate Document file"],
["0E 4E 65 72 6F 49 53 4F", "nri", "Nero CD Compilation"],
["0E 57 4B 53", "wks", "DeskMate Worksheet"],
["0F 53 49 42 45 4C 49 55 53", "sib", "Sibelius Music - Score file"],
["23 20 4D 69 63 72 6F 73 6F 66 74 20 44 65 76 65 6C 6F 70 65 72 20 53 74 75 64 69 6F", "dsp", "Microsoft Developer Studio project file"],
["23 21 41 4D 52", "amr", "Adaptive Multi-Rate ACELP (Algebraic Code Excited Linear Prediction) Codec, commonly audio format with GSM cell phones."],
["23 21 53 49 4C 4B 0A", "sil", "Audio compression format developed by Skype"],
["23 3F 52 41 44 49 41 4E 43 45 0A", "hdr", "Radiance High Dynamic Range image file"],
["23 40 7E 5E", "vbe", "VBScript Encoded script"],
["0D F0 1D C0", "cdb", "MikroTik WinBox Connection Database (Address Book)"],
["23 45 58 54 4D 33 55", "m3um3u8", "Multimedia playlist"],
["6D 64 66 00", "m", "M2 Archive, used by game developer M2"],
["4B 50 4B 41", "pak", "Capcom RE Engine game data archives"],
["41 52 43", "arc", "Capcom MT Framework game data archives"],
["D0 4F 50 53", "pl", "Interleaf PrinterLeaf / WorldView document format (now Broadvision QuickSilver)"],
["52 41 46 36 34", "", "Report Builder file from Digital Metaphors"],
["56 49 53 33", "", "Resource file Visionaire 3.x Engine"],
["4D 53 48 7C", "hl7", "Health Level Seven (HL7) Standard for electronic data exchange [1]"],
["70 77 72 64 61 74 61", "pwrdata", "SAP Power Monitor (version 1.1.0 and higher) data file"],
["1a 08", "arc", "ARC archive file"],
["2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 47 50 20 50 55 42 4c 49 43 20 4b 45 49 20 42 4c 4f 43 4b 2d 2d 2d 2d 2d", "asc", "Armored PGP public key"],
["3a 42 61 73 65 20", "cnt", "Windows 3.x - Windows 95 Help Contents"],
["52 49 46 46 ?? ?? ?? ?? 56 44 52 4d", "vdr", "VirtualDub"],
["52 59 46 46 ?? ?? ?? ?? 54 52 49 44", "trd", "TrID"],
["52 49 46 46 ?? ?? ?? ?? 73 68 77 34", "shw", "Corel SHOW! 4.0"],
["52 49 46 46 ?? ?? ?? ?? 73 68 77 35", "shw", "Corel SHOW! 5.0"],
["52 49 46 46 ?? ?? ?? ?? 73 68 72 35", "shr", "Corel SHOW! 5.0 player"],
["52 49 46 46 ?? ?? ?? ?? 73 68 62 35", "shb", "Corel SHOW! 5.0 background"],
["58 46 49 52 ?? ?? ?? ?? 4d 44 47 46", "dcr", "Macromedia ShockWave"],
["52 49 46 46 ?? ?? ?? ?? 52 4d 4d 50", "mmm", "MacroMind Multimedia Movie or Microsoft Multimedia Movie"]]
