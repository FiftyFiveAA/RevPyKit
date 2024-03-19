import time
import struct

# This file is responsible for analying Windows PEs
# Based off the following documentation: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

def analyzePE(file_contents):
    # exe_analysis_json will by a dict that will eventually be turned into our JSON file
    exe_analysis_json = {}
    # exe_analysis is a string of HTML the will be used to populate the UI
    exe_analysis = "<html><head><style>p{margin: 0; padding: 0;}</style><style>body{margin:10px;}</style></head><body>"
    ### MS-DOS MZ Header (128 bytes)
    exe_analysis += "<b>MS-DOS MZ HEADER (128 bytes) 0x00-0x7f</b>" + "<br>"
    # e_lfanew is at offset 0x3c and contains the start of the PE Header
    e_lfanew = file_contents[0x3c:0x3c+4][::-1]
    exe_analysis += "e_lfanew: 0x" + e_lfanew.hex() + "<br>"
    exe_analysis_json["MS DOS MZ Header"] = {
        "e_lfanew": "0x" + e_lfanew.hex()
        }
    e_lfanew = struct.unpack(">I", e_lfanew)[0]
    exe_analysis += "<br>"
    ### PE FILE HEADER
    exe_analysis += "<b>PE FILE HEADER (24 bytes) " + hex(e_lfanew) + "-" + hex(e_lfanew+24) + "</b>" + "<br>"
    # mMagic
    mMagic = file_contents[e_lfanew:e_lfanew+4]
    exe_analysis += "mMagic: 0x" + mMagic.hex() + " (" + mMagic.decode("utf-8") + ")<br>"
    if(mMagic != b"PE\x00\x00"):
        raise ValueError("invalid magic bytes")
    # the [::-1] swaps the byte order because everything is little endian
    mMachine = file_contents[e_lfanew+4:e_lfanew+6][::-1]
    mNumberOfSections = file_contents[e_lfanew+6:e_lfanew+8][::-1]
    mTimeDateStamp = file_contents[e_lfanew+8:e_lfanew+12][::-1]
    mPointerToSymbolTable = file_contents[e_lfanew+12:e_lfanew+16][::-1]
    mNumberOfSymbols = file_contents[e_lfanew+16:e_lfanew+20][::-1]
    mSizeOfOptionalHeader = file_contents[e_lfanew+20:e_lfanew+22][::-1]
    mCharacteristics = file_contents[e_lfanew+22:e_lfanew+24][::-1]
    # convert mMachine to human readable  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    documented_machines = {b"\x00\x00": "MACHINE_UNKNOWN",
                           b"\x01\x84": "Alpha",
                           b"\x02\x84": "Alpha64",
                           b"\x01\xd3": "Matsushita AM33",
                           b"\x86\x64": "x64",
                           b"\x01\xc0": "ARM little endian",
                           b"\xaa\x64": "ARM64 little endian",
                           b"\x01\xc4": "ARM Thumb-2 little endian",
                           b"\x02\x84": "AXP 64",
                           b"\x0e\xbc": "EFI byte code",
                           b"\x01\x4c": "Intel 386",
                           b"\x02\x00": "Intel Itanium",
                           b"\x62\x32": "LoongArch 32-bit",
                           b"\x62\x64": "LoongArch 64-bit",
                           b"\x90\x41": "Mitsubishi M32R little endian",
                           b"\x02\x66": "MIPS16",
                           b"\x03\x66": "MIPS with FPU",
                           b"\x04\x66": "MIPS16 with FPU",
                           b"\x01\xf0": "Power PC little endian",
                           b"\x01\xf1": "Power PC with floating point support",
                           b"\x01\x66": "MIPS little endian",
                           b"\x50\x32": "RISC-V 32-bit",
                           b"\x50\x64": "RISC-V 64-bit",
                           b"\x51\x28": "RISC-V 128-bit",
                           b"\x01\xa2": "Hitachi SH3",
                           b"\x01\xa3": "Hitachi SH3 DSP",
                           b"\x01\xa6": "Hitachi SH4",
                           b"\x01\xa8": "Hitachi SH5",
                           b"\x01\xc2": "Thumb",
                           b"\x01\x69": "MIPS little-endian WCE v2"}
    try:
        mMachineText = documented_machines[mMachine]
    except:
        mMachineText = "UNDOCUMENTED: " + mMachine.hex()
    exe_analysis += "mMachine: 0x" + mMachine.hex() + " (" + mMachineText + ")<br>"
    exe_analysis += "mNumberOfSections: 0x" + mNumberOfSections.hex() + "<br>"
    # convert the time stamp to human readable
    timestamp_int = struct.unpack(">I", mTimeDateStamp)[0]
    timestamp_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp_int))
    exe_analysis += "mTimeDateStamp: 0x" + mTimeDateStamp.hex() + " (" + timestamp_str + " UTC" + ")<br>"
    exe_analysis += "mPointerToSymbolTable: 0x" + mPointerToSymbolTable.hex() + "<br>"
    exe_analysis += "mNumberOfSymbols: 0x" + mNumberOfSymbols.hex() + "<br>"
    exe_analysis += "mSizeOfOptionalHeader: 0x" + mSizeOfOptionalHeader.hex() + "<br>"
    documented_characteristics = {b"\x00\x01": "<b>IMAGE_FILE_RELOCS_STRIPPED</b>: Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.",
                                  b"\x00\x02": "<b>IMAGE_FILE_EXECUTABLE_IMAGE</b>: Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.",
                                  b"\x00\x04": "<b>IMAGE_FILE_LINE_NUMS_STRIPPED</b>: COFF line numbers have been removed. This flag is deprecated and should be zero.",
                                  b"\x00\x08": "<b>IMAGE_FILE_LOCAL_SYMS_STRIPPED</b>: COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.",
                                  b"\x00\x10": "<b>IMAGE_FILE_AGGRESSIVE_WS_TRIM</b>: Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.",
                                  b"\x00\x20": "<b>IMAGE_FILE_LARGE_ADDRESS_ AWARE</b>: Application can handle > 2-GB addresses.",
                                  b"\x00\x40": "<b>This flag is reserved for future use.</b>",
                                  b"\x00\x80": "<b>IMAGE_FILE_BYTES_REVERSED_LO</b>: Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.",
                                  b"\x01\x00": "<b>IMAGE_FILE_32BIT_MACHINE</b>: Machine is based on a 32-bit-word architecture.",
                                  b"\x02\x00": "<b>IMAGE_FILE_DEBUG_STRIPPED</b>: Debugging information is removed from the image file.",
                                  b"\x04\x00": "<b>IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP</b>: If the image is on removable media, fully load it and copy it to the swap file.",
                                  b"\x08\x00": "<b>IMAGE_FILE_NET_RUN_FROM_SWAP</b>: If the image is on network media, fully load it and copy it to the swap file.",
                                  b"\x10\x00": "<b>IMAGE_FILE_SYSTEM</b>: The image file is a system file, not a user program.",
                                  b"\x20\x00": "<b>IMAGE_FILE_DLL</b>: The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.",
                                  b"\x40\x00": "<b>IMAGE_FILE_UP_SYSTEM_ONLY</b>: The file should be run only on a uniprocessor machine.",
                                  b"\x80\x00": "<b>IMAGE_FILE_BYTES_REVERSED_HI</b>: Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero."
                                  }

    exe_analysis_json["PE File Header"] = {
            "mMagic": "0x" + mMagic.hex(),
            "mMachine": "0x" + mMachine.hex(),
            "mNumberOfSections": "0x" + mNumberOfSections.hex(),
            "mTimeDateStamp": "0x" + mTimeDateStamp.hex(),
            "mPointerToSymbolTable": "0x" + mPointerToSymbolTable.hex(),
            "mNumberOfSymbols": "0x" + mNumberOfSymbols.hex(),
            "mSizeOfOptionalHeader": "0x" + mSizeOfOptionalHeader.hex(),
            "mCharacteristics": {},
        }
    
    exe_analysis += "mCharacteristics:"                
    for characteristic in documented_characteristics:     
        try:
            # Check for which of the documented characteristics is in the EXE
            mCharacteristics_int = struct.unpack(">H", mCharacteristics)[0]
            characteristic_int = struct.unpack(">H", characteristic)[0]
            if(mCharacteristics_int & characteristic_int):
                exe_analysis += "<p style='margin-left:20px'>" + documented_characteristics[characteristic] + "</p>"
                c_name = documented_characteristics[characteristic].split("</b>: ")[0].replace("<b>","")
                c_value = documented_characteristics[characteristic].split("</b>: ")[1]
                exe_analysis_json["PE File Header"]["mCharacteristics"][c_name] = c_value
        except:
            pass
    exe_analysis += "<br>"
    


    ### PE OPTIONAL HEADER
    optional_header = e_lfanew+24
    optional_header_end = e_lfanew+24+struct.unpack(">H", mSizeOfOptionalHeader)[0]
    exe_analysis += "<p><b>PE OPTIONAL HEADER (" + str(struct.unpack(">H", mSizeOfOptionalHeader)[0]) + " bytes) " + hex(optional_header)+ "-" + hex(optional_header_end) + "</b><br>"

    mMagic = file_contents[optional_header:optional_header+2][::-1]
    mMajorLinkerVersion = file_contents[optional_header+2]
    mMinorLinkerVersion = file_contents[optional_header+3]
    mSizeOfCode = file_contents[optional_header+4:optional_header+8][::-1]
    mSizeOfInitializedData = file_contents[optional_header+8:optional_header+12][::-1]
    mSizeOfUninitializedData = file_contents[optional_header+12:optional_header+16][::-1]
    mAddressOfEntryPoint = file_contents[optional_header+16:optional_header+20][::-1]
    mBaseOfCode = file_contents[optional_header+20:optional_header+24][::-1]
    arch = ""
    if(mMagic == b"\x01\x0b"):
        mBaseofData = file_contents[optional_header+24:optional_header+28][::-1]
        arch = "x86"
    else:
        arch = "x64"
    if(arch == "x86"):
        mImageBase = file_contents[optional_header+28:optional_header+32][::-1]
    elif(arch == "x64"):
        mImageBase = file_contents[optional_header+24:optional_header+32][::-1]
    mSectionAlignment = file_contents[optional_header+32:optional_header+36][::-1]
    mFileAlignment = file_contents[optional_header+36:optional_header+40][::-1]
    mMajorOperatingSystemVersion = file_contents[optional_header+40:optional_header+42][::-1]
    mMinorOperatingSystemVersion = file_contents[optional_header+42:optional_header+44][::-1]
    mMajorImageVersion = file_contents[optional_header+44:optional_header+46][::-1]
    mMinorImageVersion = file_contents[optional_header+46:optional_header+48][::-1]
    mMajorSubsystemVersion = file_contents[optional_header+48:optional_header+50][::-1]
    mMinorSubsystemVersion = file_contents[optional_header+50:optional_header+52][::-1]
    mWin32VersionValue = file_contents[optional_header+52:optional_header+56][::-1]
    mSizeOfImage = file_contents[optional_header+56:optional_header+60][::-1]
    mSizeOfHeaders = file_contents[optional_header+60:optional_header+64][::-1]
    mCheckSum = file_contents[optional_header+64:optional_header+68][::-1]
    mSubsystem = file_contents[optional_header+68:optional_header+70][::-1]
    mDllCharacteristics = file_contents[optional_header+70:optional_header+72][::-1]
    if(arch == "x86"):
        mSizeOfStackReserve = file_contents[optional_header+72:optional_header+76][::-1]
    elif(arch == "x64"):
        mSizeOfStackReserve = file_contents[optional_header+72:optional_header+80][::-1]
    if(arch == "x86"):
        mSizeOfStackCommit = file_contents[optional_header+76:optional_header+80][::-1]
    elif(arch == "x64"):
        mSizeOfStackCommit = file_contents[optional_header+80:optional_header+88][::-1]
    if(arch == "x86"):
        mSizeOfHeapReserve = file_contents[optional_header+80:optional_header+84][::-1]
    elif(arch == "x64"):
        mSizeOfHeapReserve = file_contents[optional_header+88:optional_header+96][::-1]
    if(arch == "x86"):
        mSizeOfHeapCommit = file_contents[optional_header+84:optional_header+88][::-1]
    elif(arch == "x64"):
        mSizeOfHeapCommit = file_contents[optional_header+96:optional_header+104][::-1]
    if(arch == "x86"):
        mLoaderFlags = file_contents[optional_header+88:optional_header+92][::-1]
    elif(arch == "x64"):
        mLoaderFlags = file_contents[optional_header+104:optional_header+108][::-1]
    if(arch == "x86"):
        mNumberOfRvaAndSizes = file_contents[optional_header+92:optional_header+96][::-1]
    elif(arch == "x64"):
        mNumberOfRvaAndSizes = file_contents[optional_header+108:optional_header+112][::-1]

    mMagicText = ""
    if(mMagic == b"\x01\x0b"):
        mMagicText = "PE32 (32 bit)"
    elif(mMagic == b"\x02\x0b"):
        mMagicText = "PE32+ (64 bit)"
    elif(mMagic == b"\x01\x07"):
        mMagicText = "ROM image"
    exe_analysis += "mMagic: 0x" + mMagic.hex() + " (" + mMagicText + ")<br>"
    exe_analysis += "mMajorLinkerVersion: " + hex(mMajorLinkerVersion) + "<br>"
    exe_analysis += "mMinorLinkerVersion: " + hex(mMinorLinkerVersion) + "<br>"
    exe_analysis += "mSizeOfCode: 0x" + mSizeOfCode.hex() + "<br>"
    exe_analysis += "mSizeOfInitializedData: 0x" + mSizeOfInitializedData.hex() + "<br>"
    exe_analysis += "mSizeOfUninitializedData: 0x" + mSizeOfUninitializedData.hex() + "<br>"
    exe_analysis += "mAddressOfEntryPoint: 0x" + mAddressOfEntryPoint.hex() + "<br>"
    exe_analysis += "mBaseOfCode: 0x" + mBaseOfCode.hex() + "<br>"
    if(mMagic == b"\x01\x0b"):
        exe_analysis += "mBaseofData: 0x" + mBaseofData.hex() + "<br>"
    exe_analysis += "mImageBase: 0x" + mImageBase.hex() + "<br>"
    exe_analysis += "mSectionAlignment: 0x" + mSectionAlignment.hex() + "<br>"
    exe_analysis += "mFileAlignment: 0x" + mFileAlignment.hex() + "<br>"
    exe_analysis += "mMajorOperatingSystemVersion: 0x" + mMajorOperatingSystemVersion.hex() + "<br>"
    exe_analysis += "mMinorOperatingSystemVersion: 0x" + mMinorOperatingSystemVersion.hex() + "<br>"
    exe_analysis += "mMajorImageVersion: 0x" + mMajorImageVersion.hex() + "<br>"
    exe_analysis += "mMinorImageVersion: 0x" + mMinorImageVersion.hex() + "<br>"
    exe_analysis += "mMajorSubsystemVersion: 0x" + mMajorSubsystemVersion.hex() + "<br>"
    exe_analysis += "mMinorSubsystemVersion: 0x" + mMinorSubsystemVersion.hex() + "<br>"
    exe_analysis += "mWin32VersionValue: 0x" + mWin32VersionValue.hex() + "<br>"
    exe_analysis += "mSizeOfImage: 0x" + mSizeOfImage.hex() + "<br>"
    exe_analysis += "mSizeOfHeaders: 0x" + mSizeOfHeaders.hex() + "<br>"
    exe_analysis += "mCheckSum: 0x" + mCheckSum.hex() + "<br>"

    exe_analysis_json["PE Optional Header"] = {
            "mMagic": "0x" + mMagic.hex(),
            "mMajorLinkerVersion": hex(mMajorLinkerVersion),
            "mMinorLinkerVersion": hex(mMinorLinkerVersion),
            "mSizeOfCode": "0x" + mSizeOfCode.hex(),
            "mSizeOfInitializedData": "0x" + mSizeOfInitializedData.hex(),
            "mSizeOfUninitializedData": "0x" + mSizeOfUninitializedData.hex(),
            "mAddressOfEntryPoint": "0x" + mAddressOfEntryPoint.hex(),
            "mBaseOfCode": "0x" + mBaseOfCode.hex(),
            "mImageBase": "0x" + mImageBase.hex(),
            "mSectionAlignment": "0x" + mSectionAlignment.hex(),
            "mFileAlignment": "0x" + mFileAlignment.hex(),
            "mMajorOperatingSystemVersion": "0x" + mMajorOperatingSystemVersion.hex(),
            "mMinorOperatingSystemVersion": "0x" + mMinorOperatingSystemVersion.hex(),
            "mMajorImageVersion": "0x" + mMajorImageVersion.hex(),
            "mMinorImageVersion": "0x" + mMinorImageVersion.hex(),
            "mMajorSubsystemVersion": "0x" + mMajorSubsystemVersion.hex(),
            "mMinorSubsystemVersion": "0x" + mMinorSubsystemVersion.hex(),
            "mWin32VersionValue": "0x" + mWin32VersionValue.hex(),
            "mSizeOfImage": "0x" + mSizeOfImage.hex(),
            "mSizeOfHeaders": "0x" + mSizeOfHeaders.hex(),
            "mCheckSum": "0x" + mCheckSum.hex(),
            }
            
    if(struct.unpack(">H", mSubsystem)[0] == 0):
        subsystem = "Unknown"
    elif(struct.unpack(">H", mSubsystem)[0] == 1):
        subsystem = "NATIVE: Device Drivers and native Windows processes"
    elif(struct.unpack(">H", mSubsystem)[0] == 2):
        subsystem = "GUI"
    elif(struct.unpack(">H", mSubsystem)[0] == 3):
        subsystem = "CUI: Windows character subsystem"
    elif(struct.unpack(">H", mSubsystem)[0] == 5):
        subsystem = "OS/2 character subsystem"
    elif(struct.unpack(">H", mSubsystem)[0] == 7):
        subsystem = "POSIX character subsystem"
    elif(struct.unpack(">H", mSubsystem)[0] == 8):
        subsystem = "Native Wind9x driver"
    elif(struct.unpack(">H", mSubsystem)[0] == 9):
        subsystem = "Windows CE"
    elif(struct.unpack(">H", mSubsystem)[0] == 10):
        subsystem = "EFI: Extensible Firmware Interface application"
    elif(struct.unpack(">H", mSubsystem)[0] == 11):
        subsystem = "EFI driver with boot services"
    elif(struct.unpack(">H", mSubsystem)[0] == 12):
        subsystem = "EFI driver with run-time services"
    elif(struct.unpack(">H", mSubsystem)[0] == 13):
        subsystem = "EFI ROM image"
    elif(struct.unpack(">H", mSubsystem)[0] == 14):
        subsystem = "XBOX"
    elif(struct.unpack(">H", mSubsystem)[0] == 16):
        subsystem = "Windows boot application"
    else:
        subsystem = "UNDOCUMENTED"
    exe_analysis += "mSubsystem: 0x" + mSubsystem.hex() + " (" + subsystem + ")<br>"
    exe_analysis_json["PE Optional Header"]["mSubsystem"] = "0x" + mSubsystem.hex()
    exe_analysis_json["PE Optional Header"]["mDllCharacteristics"] = {}
    
    exe_analysis += "mDllCharacteristics: 0x" + mDllCharacteristics.hex() + "<p style='margin-left:20px'>"
    if(struct.unpack(">H", mDllCharacteristics)[0] & 0x20):
        exe_analysis += "<b>HIGH_ENTROPY_VA</b>: Image can handle a high entropy 64-bit virtual address space.<br>"
        exe_analysis_json["PE Optional Header"]["mDllCharacteristics"]["HIGH_ENTROPY_VA"] = "Image can handle a high entropy 64-bit virtual address space."
    if(struct.unpack(">H", mDllCharacteristics)[0] & 0x40):
        exe_analysis += "<b>DYNAMIC_BASE</b>: DLL can be relocated at load time.<br>"
        exe_analysis_json["PE Optional Header"]["mDllCharacteristics"]["DYNAMIC_BASE"] = "DLL can be relocated at load time."
    if(struct.unpack(">H", mDllCharacteristics)[0] & 0x80):
        exe_analysis += "<b>FORCE_INTEGRITY</b>: Code Integrity checks are enforced.<br>"
        exe_analysis_json["PE Optional Header"]["mDllCharacteristics"]["FORCE_INTEGRITY"] = "Code Integrity checks are enforced."
    if(struct.unpack(">H", mDllCharacteristics)[0] & 0x100):
        exe_analysis += "<b>NX_COMPAT</b>: Image is NX compatible.<br>"
        exe_analysis_json["PE Optional Header"]["mDllCharacteristics"]["NX_COMPAT"] = "Image is NX compatible."
    if(struct.unpack(">H", mDllCharacteristics)[0] & 0x200):
        exe_analysis += "<b>NO_ISOLATION</b>: Isolation aware, but do not isolate the image.<br>"
        exe_analysis_json["PE Optional Header"]["mDllCharacteristics"]["NO_ISOLATION"] = "Isolation aware, but do not isolate the image."
    if(struct.unpack(">H", mDllCharacteristics)[0] & 0x400):
        exe_analysis += "<b>NO_SEH</b>: Does not use structured exception (SE) handling. No SE handler may be called in this image.<br>"
        exe_analysis_json["PE Optional Header"]["mDllCharacteristics"]["NO_SEH"] = "Does not use structured exception (SE) handling. No SE handler may be called in this image."
    if(struct.unpack(">H", mDllCharacteristics)[0] & 0x800):
        exe_analysis += "<b>NO_BIND</b>: Do not bind the image.<br>"
        exe_analysis_json["PE Optional Header"]["mDllCharacteristics"]["NO_BIND"] = "Do not bind the image."
    if(struct.unpack(">H", mDllCharacteristics)[0] & 0x1000):
        exe_analysis += "<b>APPCONTAINER</b>: Image must execute in an AppContainer.<br>"
        exe_analysis_json["PE Optional Header"]["mDllCharacteristics"]["APPCONTAINER"] = "Image must execute in an AppContainer."
    if(struct.unpack(">H", mDllCharacteristics)[0] & 0x2000):
        exe_analysis += "<b>WDM_DRIVER</b>: A WDM driver.<br>"
        exe_analysis_json["PE Optional Header"]["mDllCharacteristics"]["WDM_DRIVER"] = "A WDM driver."
    if(struct.unpack(">H", mDllCharacteristics)[0] & 0x4000):
        exe_analysis += "<b>GUARD_CF</b>: Image supports Control Flow Guard.<br>"
        exe_analysis_json["PE Optional Header"]["mDllCharacteristics"]["GUARD_CF"] = "Image supports Control Flow Guard."
    if(struct.unpack(">H", mDllCharacteristics)[0] & 0x8000):
        exe_analysis += "<b>TERMINAL_SERVER_AWARE</b>: Terminal Server aware.<br>"
        exe_analysis_json["PE Optional Header"]["mDllCharacteristics"]["TERMINAL_SERVER_AWARE"] = "Terminal Server aware."
    exe_analysis += "</p><p>"
    exe_analysis += "mSizeOfStackReserve: 0x" + mSizeOfStackReserve.hex() + "<br>"
    exe_analysis += "mSizeOfStackCommit: 0x" + mSizeOfStackCommit.hex() + "<br>"
    exe_analysis += "mSizeOfHeapReserve: 0x" + mSizeOfHeapReserve.hex() + "<br>"
    exe_analysis += "mSizeOfHeapCommit: 0x" + mSizeOfHeapCommit.hex() + "<br>"
    exe_analysis += "mLoaderFlags: 0x" + mLoaderFlags.hex() + "<br>"
    exe_analysis += "mNumberOfRvaAndSizes: 0x" + mNumberOfRvaAndSizes.hex() + "<br></p>"
    
    exe_analysis_json["PE Optional Header"]["mSizeOfStackReserve"] = "0x" + mSizeOfStackReserve.hex()
    exe_analysis_json["PE Optional Header"]["mSizeOfStackCommit"] = "0x" + mSizeOfStackCommit.hex()
    exe_analysis_json["PE Optional Header"]["mSizeOfHeapReserve"] = "0x" + mSizeOfHeapReserve.hex()
    exe_analysis_json["PE Optional Header"]["mSizeOfHeapCommit"] = "0x" + mSizeOfHeapCommit.hex()
    exe_analysis_json["PE Optional Header"]["mLoaderFlags"] = "0x" + mLoaderFlags.hex()
    exe_analysis_json["PE Optional Header"]["mNumberOfRvaAndSizes"] = "0x" + mNumberOfRvaAndSizes.hex()

    if(arch == "x86"):
        exe_analysis += "<p><b>PE OPTIONAL HEADER DATA DIRECTORIES (128 bytes) " + hex(optional_header+96)+ "-" + hex(optional_header+216) + "</b><br>"
        mExportTable = file_contents[optional_header+96:optional_header+104]
        mImportTable = file_contents[optional_header+104:optional_header+112]
        mResourceTable = file_contents[optional_header+112:optional_header+120]
        mExceptionTable = file_contents[optional_header+120:optional_header+128]
        mCertificateTable = file_contents[optional_header+128:optional_header+136]
        mBaseRelocationTable = file_contents[optional_header+136:optional_header+144]
        mDebugTable = file_contents[optional_header+144:optional_header+152]
        mArchitectureTable = file_contents[optional_header+152:optional_header+160]
        mGlobalPtrTable = file_contents[optional_header+160:optional_header+168]
        mTLSTable = file_contents[optional_header+168:optional_header+176]
        mLoadConfigTable = file_contents[optional_header+176:optional_header+184]
        mBoundImportTable = file_contents[optional_header+184:optional_header+192]
        mIAT = file_contents[optional_header+192:optional_header+200]
        mDelayImportDescriptor = file_contents[optional_header+200:optional_header+208]
        mCLRRuntimeHeader = file_contents[optional_header+208:optional_header+216]
        mReservedZero = file_contents[optional_header+216:optional_header+224]
    elif(arch == "x64"):
        exe_analysis += "<p><b>PE OPTIONAL HEADER DATA DIRECTORIES (128 bytes) " + hex(optional_header+112)+ "-" + hex(optional_header+232) + "</b><br>"
        mExportTable = file_contents[optional_header+112:optional_header+120]
        mImportTable = file_contents[optional_header+120:optional_header+128]
        mResourceTable = file_contents[optional_header+128:optional_header+136]
        mExceptionTable = file_contents[optional_header+136:optional_header+144]
        mCertificateTable = file_contents[optional_header+144:optional_header+152]
        mBaseRelocationTable = file_contents[optional_header+152:optional_header+160]
        mDebugTable = file_contents[optional_header+160:optional_header+168]
        mArchitectureTable = file_contents[optional_header+168:optional_header+176]
        mGlobalPtrTable = file_contents[optional_header+176:optional_header+184]
        mTLSTable = file_contents[optional_header+184:optional_header+192]
        mLoadConfigTable = file_contents[optional_header+192:optional_header+200]
        mBoundImportTable = file_contents[optional_header+200:optional_header+208]
        mIAT = file_contents[optional_header+208:optional_header+216]
        mDelayImportDescriptor = file_contents[optional_header+216:optional_header+224]
        mCLRRuntimeHeader = file_contents[optional_header+224:optional_header+232]
        mReservedZero = file_contents[optional_header+232:optional_header+240]

    mExportTableRVA = mExportTable[0:4][::-1]
    mExportTableSize = mExportTable[4:8][::-1]
    mImportTableRVA = mImportTable[0:4][::-1]
    mImportTableSize = mImportTable[4:8][::-1]
    mResourceTableRVA = mResourceTable[0:4][::-1]
    mResourceTableSize = mResourceTable[4:8][::-1]
    mExceptionTableRVA = mExceptionTable[0:4][::-1]
    mExceptionTableSize = mExceptionTable[4:8][::-1]
    mCertificateTableRVA = mCertificateTable[0:4][::-1]
    mCertificateTableSize = mCertificateTable[4:8][::-1]
    mBaseRelocationTableRVA = mBaseRelocationTable[0:4][::-1]
    mBaseRelocationTableSize = mBaseRelocationTable[4:8][::-1]
    mDebugTableRVA = mDebugTable[0:4][::-1]
    mDebugTableSize = mDebugTable[4:8][::-1]
    mArchitectureTableRVA = mArchitectureTable[0:4][::-1]
    mArchitectureTableSize = mArchitectureTable[4:8][::-1]
    mGlobalPtrTableRVA = mGlobalPtrTable[0:4][::-1]
    mGlobalPtrTableSize = mGlobalPtrTable[4:8][::-1]
    mTLSTableRVA = mTLSTable[0:4][::-1]
    mTLSTableSize = mTLSTable[4:8][::-1]
    mLoadConfigTableRVA = mLoadConfigTable[0:4][::-1]
    mLoadConfigTableSize = mLoadConfigTable[4:8][::-1]
    mBoundImportTableRVA = mBoundImportTable[0:4][::-1]
    mBoundImportTableSize = mBoundImportTable[4:8][::-1]
    mIATRVA = mIAT[0:4][::-1]
    mIATSize = mIAT[4:8][::-1]
    mDelayImportDescriptorRVA = mDelayImportDescriptor[0:4][::-1]
    mDelayImportDescriptorSize = mDelayImportDescriptor[4:8][::-1]
    mCLRRuntimeHeaderRVA = mCLRRuntimeHeader[0:4][::-1]
    mCLRRuntimeHeaderSize = mCLRRuntimeHeader[4:8][::-1]
    mReservedZeroRVA = mReservedZero[0:4][::-1]
    mReservedZeroSize = mReservedZero[4:8][::-1]

    exe_analysis += "Export Table RVA: 0x" + mExportTableRVA.hex() + "    Size: 0x" + mExportTableSize.hex() + "<br>"
    exe_analysis += "Import Table RVA: 0x" + mImportTableRVA.hex() + "    Size: 0x" + mImportTableSize.hex() + "<br>"
    exe_analysis += "Resource Table RVA: 0x" + mResourceTableRVA.hex() + "    Size: 0x" + mResourceTableSize.hex() + "<br>"
    exe_analysis += "Exception Table RVA: 0x" + mExceptionTableRVA.hex() + "    Size: 0x" + mExceptionTableSize.hex() + "<br>"
    exe_analysis += "Certificate/Security Table RVA: 0x" + mCertificateTableRVA.hex() + "    Size: 0x" + mCertificateTableSize.hex() + "<br>"
    exe_analysis += "Base Relocation Table RVA: 0x" + mBaseRelocationTableRVA.hex() + "    Size: 0x" + mBaseRelocationTableSize.hex() + "<br>"
    exe_analysis += "Debug Table RVA: 0x" + mDebugTableRVA.hex() + "    Size: 0x" + mDebugTableSize.hex() + "<br>"
    exe_analysis += "Architecture Table RVA: 0x" + mArchitectureTableRVA.hex() + "    Size: 0x" + mArchitectureTableSize.hex() + "<br>"
    exe_analysis += "Global PTR Table RVA: 0x" + mGlobalPtrTableRVA.hex() + "    Size: 0x" + mGlobalPtrTableSize.hex() + "<br>"
    exe_analysis += "TLS Table RVA: 0x" + mTLSTableRVA.hex() + "    Size: 0x" + mTLSTableSize.hex() + "<br>"
    exe_analysis += "Load Config Table RVA: 0x" + mLoadConfigTableRVA.hex() + "    Size: 0x" + mLoadConfigTableSize.hex() + "<br>"
    exe_analysis += "Bound Import Table RVA: 0x" + mBoundImportTableRVA.hex() + "    Size: 0x" + mBoundImportTableSize.hex() + "<br>"
    exe_analysis += "Import Address Table (IAT) RVA: 0x" + mIATRVA.hex() + "    Size: 0x" + mIATSize.hex() + "<br>"
    exe_analysis += "Delay Import Descriptor RVA: 0x" + mDelayImportDescriptorRVA.hex() + "    Size: 0x" + mDelayImportDescriptorSize.hex() + "<br>"
    exe_analysis += "CLR Runtime Header RVA: 0x" + mCLRRuntimeHeaderRVA.hex() + "    Size: 0x" + mCLRRuntimeHeaderSize.hex() + "<br>"
    exe_analysis += "Reserved Must be ZERO RVA: 0x" + mReservedZeroRVA.hex() + "    Size: 0x" + mReservedZeroSize.hex() + "<br>"
    exe_analysis += "</p>"

    exe_analysis_json["PE Optional Header Data Directories"] = {}
    exe_analysis_json["PE Optional Header Data Directories"]["mExportTableRVA"] = "0x" + mExportTableRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mExportTableSize"] = "0x" + mExportTableSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mImportTableRVA"] = "0x" + mImportTableRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mImportTableSize"] = "0x" + mImportTableSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mResourceTableRVA"] = "0x" + mResourceTableRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mResourceTableSize"] = "0x" + mResourceTableSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mExceptionTableRVA"] = "0x" + mExceptionTableRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mExceptionTableSize"] = "0x" + mExceptionTableSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mCertificateTableRVA"] = "0x" + mCertificateTableRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mCertificateTableSize"] = "0x" + mCertificateTableSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mBaseRelocationTableRVA"] = "0x" + mBaseRelocationTableRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mBaseRelocationTableSize"] = "0x" + mBaseRelocationTableSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mDebugTableRVA"] = "0x" + mDebugTableRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mDebugTableSize"] = "0x" + mDebugTableSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mArchitectureTableRVA"] = "0x" + mArchitectureTableRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mArchitectureTableSize"] = "0x" + mArchitectureTableSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mGlobalPtrTableRVA"] = "0x" + mGlobalPtrTableRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mGlobalPtrTableSize"] = "0x" + mGlobalPtrTableSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mTLSTableRVA"] = "0x" + mTLSTableRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mTLSTableSize"] = "0x" + mTLSTableSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mLoadConfigTableRVA"] = "0x" + mLoadConfigTableRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mLoadConfigTableSize"] = "0x" + mLoadConfigTableSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mBoundImportTableRVA"] = "0x" + mBoundImportTableRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mBoundImportTableSize"] = "0x" + mBoundImportTableSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mIATRVA"] = "0x" + mIATRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mIATSize"] = "0x" + mIATSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mDelayImportDescriptorRVA"] = "0x" + mDelayImportDescriptorRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mDelayImportDescriptorSize"] = "0x" + mDelayImportDescriptorSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mCLRRuntimeHeaderRVA"] = "0x" + mCLRRuntimeHeaderRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mCLRRuntimeHeaderSize"] = "0x" + mCLRRuntimeHeaderSize.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mReservedZeroRVA"] = "0x" + mReservedZeroRVA.hex()
    exe_analysis_json["PE Optional Header Data Directories"]["mReservedZeroSize"] = "0x" + mReservedZeroSize.hex()

    documented_section_flags = {b"\x00\x00\x00\x00": "<b>Reserved for future use</b>:  ",
                                  b"\x00\x00\x00\x01": "<b>Reserved for future use</b>:  ",
                                  b"\x00\x00\x00\x02": "<b>Reserved for future use</b>:  ",
                                  b"\x00\x00\x00\x04": "<b>Reserved for future use</b>:  ",
                                  b"\x00\x00\x00\x08": "<b>IMAGE_SCN_TYPE_NO_PAD</b>: The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.",
                                  b"\x00\x00\x00\x10": "<b>Reserved for future use</b>:  ",
                                  b"\x00\x00\x00\x20": "<b>IMAGE_SCN_CNT_CODE</b>: The section contains executable code.",
                                  b"\x00\x00\x00\x40": "<b>IMAGE_SCN_CNT_INITIALIZED_DATA</b>: The section contains initialized data.",
                                  b"\x00\x00\x00\x80": "<b>IMAGE_SCN_CNT_UNINITIALIZED_ DATA</b>: The section contains uninitialized data.",
                                  b"\x00\x00\x01\x00": "<b>IMAGE_SCN_LNK_OTHER</b>: Reserved for future use.",
                                  b"\x00\x00\x02\x00": "<b>IMAGE_SCN_LNK_INFO</b>: The section contains comments or other information. The .drectve section has this type. This is valid for object files only.",
                                  b"\x00\x00\x04\x00": "<b>Reserved for future use</b>:  ",
                                  b"\x00\x00\x08\x00": "<b>IMAGE_SCN_LNK_REMOVE</b>: The section will not become part of the image. This is valid only for object files.",
                                  b"\x00\x00\x10\x00": "<b>IMAGE_SCN_LNK_COMDAT</b>: The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.",
                                  b"\x00\x00\x80\x00": "<b>IMAGE_SCN_GPREL</b>: The section contains data referenced through the global pointer (GP).",
                                  b"\x00\x02\x00\x00": "<b>IMAGE_SCN_MEM_PURGEABLE</b>: Reserved for future use",
                                  b"\x00\x04\x00\x00": "<b>IMAGE_SCN_MEM_LOCKED</b>: Reserved for future use",
                                  b"\x00\x08\x00\x00": "<b>IMAGE_SCN_MEM_PRELOAD</b>: Reserved for future use",
                                  b"\x00\x10\x00\x00": "<b>IMAGE_SCN_ALIGN_1BYTES</b>: Align data on a 1-byte boundary. Valid only for object files.",
                                  b"\x00\x20\x00\x00": "<b>IMAGE_SCN_ALIGN_2BYTES</b>: Align data on a 2-byte boundary. Valid only for object files.",
                                  b"\x00\x30\x00\x00": "<b>IMAGE_SCN_ALIGN_4BYTES</b>: Align data on a 4-byte boundary. Valid only for object files.",
                                  b"\x00\x40\x00\x00": "<b>IMAGE_SCN_ALIGN_8BYTES</b>: Align data on an 8-byte boundary. Valid only for object files.",
                                  b"\x00\x50\x00\x00": "<b>IMAGE_SCN_ALIGN_16BYTES</b>: Align data on a 16-byte boundary. Valid only for object files.",
                                  b"\x00\x60\x00\x00": "<b>IMAGE_SCN_ALIGN_32BYTES</b>: Align data on a 32-byte boundary. Valid only for object files.",
                                  b"\x00\x70\x00\x00": "<b>IMAGE_SCN_ALIGN_64BYTES</b>: Align data on a 64-byte boundary. Valid only for object files.",
                                  b"\x00\x80\x00\x00": "<b>IMAGE_SCN_ALIGN_128BYTES</b>: Align data on a 128-byte boundary. Valid only for object files.",
                                  b"\x00\x90\x00\x00": "<b>IMAGE_SCN_ALIGN_256BYTES</b>: Align data on a 256-byte boundary. Valid only for object files.",
                                  b"\x00\xa0\x00\x00": "<b>IMAGE_SCN_ALIGN_512BYTES</b>: Align data on a 512-byte boundary. Valid only for object files.",
                                  b"\x00\xb0\x00\x00": "<b>IMAGE_SCN_ALIGN_1024BYTES</b>: Align data on a 1024-byte boundary. Valid only for object files.",
                                  b"\x00\xc0\x00\x00": "<b>IMAGE_SCN_ALIGN_2048BYTES</b>: Align data on a 2048-byte boundary. Valid only for object files.",
                                  b"\x00\xd0\x00\x00": "<b>IMAGE_SCN_ALIGN_4096BYTES</b>: Align data on a 4096-byte boundary. Valid only for object files.",
                                  b"\x00\xe0\x00\x00": "<b>IMAGE_SCN_ALIGN_8192BYTES</b>: Align data on an 8192-byte boundary. Valid only for object files.",
                                  b"\x01\x00\x00\x00": "<b>IMAGE_SCN_LNK_NRELOC_OVFL</b>: The section contains extended relocations.",
                                  b"\x02\x00\x00\x00": "<b>IMAGE_SCN_MEM_DISCARDABLE</b>: The section can be discarded as needed.",
                                  b"\x04\x00\x00\x00": "<b>IMAGE_SCN_MEM_NOT_CACHED</b>: The section cannot be cached.",
                                  b"\x08\x00\x00\x00": "<b>IMAGE_SCN_MEM_NOT_PAGED</b>: The section is not pageable.",
                                  b"\x10\x00\x00\x00": "<b>IMAGE_SCN_MEM_SHARED</b>: The section can be shared in memory.",
                                  b"\x20\x00\x00\x00": "<b>IMAGE_SCN_MEM_EXECUTE</b>: The section can be executed as code.",
                                  b"\x40\x00\x00\x00": "<b>IMAGE_SCN_MEM_READ</b>: The section can be read.",
                                  b"\x80\x00\x00\x00": "<b>IMAGE_SCN_MEM_WRITE</b>: The section can be written to.",
                                  }                       
    if(arch == "x86"):
        exe_analysis += "<p><b>PE SECTION HEADERS (" + str(struct.unpack(">H", mNumberOfSections)[0]*40) + " bytes) " + hex(optional_header+224)+ "-" + hex((struct.unpack(">H", mNumberOfSections)[0]*40)+optional_header+224) + "</b><br>"
        start_section_header = optional_header+224
    elif(arch == "x64"):
        exe_analysis += "<p><b>PE SECTION HEADERS (" + str(struct.unpack(">H", mNumberOfSections)[0]*40) + " bytes) " + hex(optional_header+240)+ "-" + hex((struct.unpack(">H", mNumberOfSections)[0]*40)+optional_header+240) + "</b><br>"
        start_section_header = optional_header+240

    exe_analysis_json["PE Section Headers"] = []
    
    num_sections_int = struct.unpack(">H", mNumberOfSections)[0]
    sections = []
    # go through each section header which is 40 bytes
    section_header_offset = 0
    for i in range(0, num_sections_int):
        sName = file_contents[start_section_header+section_header_offset:start_section_header+section_header_offset+8]
        sVirtualSize = file_contents[start_section_header+section_header_offset+8:start_section_header+section_header_offset+12][::-1]
        sVirtualAddress = file_contents[start_section_header+section_header_offset+12:start_section_header+section_header_offset+16][::-1]
        sSizeOfRawData = file_contents[start_section_header+section_header_offset+16:start_section_header+section_header_offset+20][::-1]
        sPointerToRawData = file_contents[start_section_header+section_header_offset+20:start_section_header+section_header_offset+24][::-1]
        sPointerToRelocations = file_contents[start_section_header+section_header_offset+24:start_section_header+section_header_offset+28][::-1]
        sPointerToLinenumbers = file_contents[start_section_header+section_header_offset+28:start_section_header+section_header_offset+32][::-1]
        sNumberOfRelocations = file_contents[start_section_header+section_header_offset+32:start_section_header+section_header_offset+34][::-1]
        sNumberOfLinenumbers = file_contents[start_section_header+section_header_offset+34:start_section_header+section_header_offset+36][::-1]
        sCharacteristics = file_contents[start_section_header+section_header_offset+36:start_section_header+section_header_offset+40][::-1] 
        section_header_offset += 40

        # To extract the import we need the Import directory Table
        # Originally I thought this was always in ".idata" but that's not true
        # look at kernel32.dll as an example
        #if(sName.decode('latin-1').replace("\u0000","") == ".idata"):
        if(struct.unpack(">I", mImportTableRVA)[0] >= struct.unpack(">I", sVirtualAddress)[0] and
           struct.unpack(">I", mImportTableRVA)[0] <= struct.unpack(">I", sVirtualAddress)[0] + struct.unpack(">I", sVirtualSize)[0]):
            offset = struct.unpack(">I", mImportTableRVA)[0] - struct.unpack(">I", sVirtualAddress)[0]
            start_importDirectoryTable = struct.unpack(">I", sPointerToRawData)[0] + offset
        # Do the same for the Export Directory Table
        if(struct.unpack(">I", mExportTableRVA)[0] >= struct.unpack(">I", sVirtualAddress)[0] and
           struct.unpack(">I", mExportTableRVA)[0] <= struct.unpack(">I", sVirtualAddress)[0] + struct.unpack(">I", sVirtualSize)[0]):
            offset = struct.unpack(">I", mExportTableRVA)[0] - struct.unpack(">I", sVirtualAddress)[0]
            start_exportDirectoryTable = struct.unpack(">I", sPointerToRawData)[0] + offset
        # Store some section information so we can do lookups later
        sections.append({"VirtualSize":struct.unpack(">I", sVirtualSize)[0],
                         "VirtualAddress":struct.unpack(">I", sVirtualAddress)[0],
                         "SizeOfRawData":struct.unpack(">I", sSizeOfRawData)[0],
                         "PointerToRawData":struct.unpack(">I", sPointerToRawData)[0]})

        exe_analysis += "Name: <b>" + sName.decode('latin-1') + "</b><br>"
        exe_analysis += "Virtual Size: 0x" + sVirtualSize.hex() + "<br>"
        exe_analysis += "Virtual Address: 0x" + sVirtualAddress.hex() + "<br>"
        exe_analysis += "Size of Raw Data: 0x" + sSizeOfRawData.hex() + "<br>"
        exe_analysis += "Pointer to Raw Data: 0x" + sPointerToRawData.hex() + "<br>"
        exe_analysis += "Pointer to Relocations: 0x" + sPointerToRelocations.hex() + "<br>"
        exe_analysis += "Pointer to Line numbers: 0x" + sPointerToLinenumbers.hex() + "<br>"
        exe_analysis += "Number of Relocations: 0x" + sNumberOfRelocations.hex() + "<br>"
        exe_analysis += "Number of Line numbers: 0x" + sNumberOfLinenumbers.hex() + "<br>"
        exe_analysis += "Characteristics: 0x" + sCharacteristics.hex()

        exe_analysis_json_section = {}

        exe_analysis_json_section["Name"] = sName.decode('latin-1').replace("\u0000","")
        exe_analysis_json_section["Virtual Size"] = "0x" + sVirtualSize.hex()
        exe_analysis_json_section["Virtual Address"] = "0x" + sVirtualAddress.hex()
        exe_analysis_json_section["Size of Raw Data"] = "0x" + sSizeOfRawData.hex()
        exe_analysis_json_section["Pointer to Raw Data"] = "0x" + sPointerToRawData.hex()
        exe_analysis_json_section["Pointer to Relocations"] = "0x" + sPointerToRelocations.hex()
        exe_analysis_json_section["Pointer to Line numbers"] = "0x" + sPointerToLinenumbers.hex()
        exe_analysis_json_section["Number of Relocations"] = "0x" + sNumberOfRelocations.hex()
        exe_analysis_json_section["Number of Line numbers"] = "0x" + sNumberOfLinenumbers.hex()
        exe_analysis_json_section["Characteristics"] = {}
        
        for section_flag in documented_section_flags:
            try:
                # Check for the documented section flags
                section_flag_int = struct.unpack(">I", section_flag)[0]
                sCharacteristics_int = struct.unpack(">I", sCharacteristics)[0]
                if(section_flag_int & sCharacteristics_int):
                    exe_analysis += "<p style='margin-left:20px'>" + documented_section_flags[section_flag] + "</p>"
                    c_name = documented_section_flags[section_flag].split("</b>:")[0].replace("<b>","")
                    c_value = documented_section_flags[section_flag].split("</b>: ")[1]
                    exe_analysis_json_section["Characteristics"][c_name] = c_value
            except:
                pass
        exe_analysis += "<br>"
        exe_analysis_json["PE Section Headers"].append(exe_analysis_json_section)

    ### IMPORTS #############################################
    # Try to extract the imports
    moreImportDirectories = True
    importDirectoryTableOffset = 0
    importDirectoryTables = []
    imports = {}
    try:
        while(moreImportDirectories):
            importLookupTableRVA = file_contents[start_importDirectoryTable + importDirectoryTableOffset:
                                                 start_importDirectoryTable + importDirectoryTableOffset + 4][::-1]
            importLookupTimeDate = file_contents[start_importDirectoryTable + importDirectoryTableOffset + 4:
                                                 start_importDirectoryTable + importDirectoryTableOffset + 8][::-1]
            importLookupForwarderChain = file_contents[start_importDirectoryTable + importDirectoryTableOffset + 8:
                                                 start_importDirectoryTable + importDirectoryTableOffset + 12][::-1]
            importLookupNameRVA = file_contents[start_importDirectoryTable + importDirectoryTableOffset + 12:
                                                 start_importDirectoryTable + importDirectoryTableOffset + 16][::-1]
            importLookupIATRVA = file_contents[start_importDirectoryTable + importDirectoryTableOffset + 16:
                                                 start_importDirectoryTable + importDirectoryTableOffset + 20][::-1]

            # check if all entries are 0s in which case we have reached the end
            if(importLookupTableRVA.hex() == "00000000" and
               importLookupTimeDate.hex() == "00000000" and
               importLookupForwarderChain.hex() == "00000000" and
               importLookupNameRVA.hex() == "00000000" and
               importLookupIATRVA.hex() == "00000000"):
                moreImportDirectories = False
                continue
                
            # so we are going to ignore the forwarderchain possiblity
            # We'll just focus on the Name RVA of the DLL and the Import Lookup Table RVA
            # Things are a little tricky now because what we have are RVAs
            # which require a bit of work to turn into file offsets
            importLookupTableRVA_int = struct.unpack(">I", importLookupTableRVA)[0]
            importLookupNameRVA_int = struct.unpack(">I", importLookupNameRVA)[0]
 
            for s in sections:
                # Check if Name table is in section
                if(importLookupNameRVA_int >= s["VirtualAddress"] and importLookupNameRVA_int <= s["VirtualAddress"] + s["VirtualSize"]):
                    dll_name = ""
                    offset = 0
                    while(1):
                        if(file_contents[s["PointerToRawData"] + offset + (importLookupNameRVA_int - s["VirtualAddress"])] == 0):
                            break
                        dll_name += chr(file_contents[s["PointerToRawData"] + offset + (importLookupNameRVA_int - s["VirtualAddress"])])
                        offset += 1
                    imports[dll_name] = []
                        
                # Check if Lookup table is in section
                if(importLookupTableRVA_int >= s["VirtualAddress"] and importLookupTableRVA_int <= s["VirtualAddress"] + s["VirtualSize"]):
                    offset = 0
                    importLookupTable_file_offset = s["PointerToRawData"] + (importLookupTableRVA_int - s["VirtualAddress"])
                    while(1):
                        if(arch == "x86"):
                            # each entry is 32 bits AKA 4 Bytes
                            lookupTableEntry = file_contents[importLookupTable_file_offset + offset: importLookupTable_file_offset + offset + 4]
                            
                            if(struct.unpack(">I", lookupTableEntry[::-1])[0] == 0):
                                break
                            # check if importing by ordinal
                            # Doing a little trick here because if bit is masked 0x80000000
                            if(lookupTableEntry[::-1].hex()[0] == "8"):
                                # the last two bytes are the ordinal number
                                ordinal_num = lookupTableEntry[::-1][-2:]
                                ordinal_num = struct.unpack(">H", ordinal_num)[0]
                            else:
                                # importing by name
                                # techincally you should only get the last 31 bits
                                # but the rest need to be zero so this should be fine
                                hint_name_table_RVA = lookupTableEntry[::-1][-4:]
                                hint_name_table_RVA = struct.unpack(">I", hint_name_table_RVA)[0]
                                
                            
                            # if the entry is 0's then we've reached end of table
                            if(struct.unpack(">I", lookupTableEntry[::-1])[0] == 0):
                                break
                            offset += 4
                        elif(arch == "x64"):
                            # each entry is 64 bits AKA 8 Bytes
                            lookupTableEntry = file_contents[importLookupTable_file_offset + offset: importLookupTable_file_offset + offset + 8]

                            if(struct.unpack(">Q", lookupTableEntry[::-1])[0] == 0):
                                break
                            # check if importing by ordinal
                            # Doing a little trick here because if bit is masked 0x8000000000000000
                            if(lookupTableEntry[::-1].hex()[0] == "8"):
                                # the last two bytes are the ordinal number
                                ordinal_num = lookupTableEntry[::-1][-2:]
                                ordinal_num = struct.unpack(">H", ordinal_num)[0]
                            else:
                                # importing by name
                                # techincally you should only get the last 31 bits
                                # but the rest need to be zero so this should be fine
                                hint_name_table_RVA = lookupTableEntry[::-1][-4:]
                                hint_name_table_RVA = struct.unpack(">I", hint_name_table_RVA)[0]

                            # if the entry is 0's then we've reached end of table
                            if(struct.unpack(">Q", lookupTableEntry[::-1])[0] == 0):
                                break
                            offset += 8

                        # If it's imported by ordinal
                        try:
                            if(ordinal_num):
                                imports[dll_name].append(ordinal_num)
                        except:
                            pass
                        # elif it's imported by name
                        try:
                            if(hint_name_table_RVA):
                                #print(hint_name_table_RVA)
                                # we need to find the file offset
                                # for this hint name table RVA which is currently an int
                                # to do this let's search through each section
                                for s_2 in sections:
                                    if(hint_name_table_RVA >= s_2["VirtualAddress"] and hint_name_table_RVA <= s_2["VirtualAddress"] + s_2["VirtualSize"]):
                                        hint_name_table_file_offset = s_2["PointerToRawData"] + (hint_name_table_RVA - s_2["VirtualAddress"])
                                # we're going to ignore this hint. It's basically used
                                # for efficiency when looking up the function in the
                                # DLLs export table
                                hint_name_table_hint = file_contents[hint_name_table_file_offset:hint_name_table_file_offset+2]
                                # get the name of the function
                                hint_offset = 0
                                func_name = ""
                                while(1):
                                    func_name_char = file_contents[hint_name_table_file_offset+2+hint_offset]
                                    if(func_name_char == 0):
                                        break
                                    func_name += chr(func_name_char)
                                    hint_offset += 1
                                # Append the function to the DLL dict
                                imports[dll_name].append(func_name)
                                    
                        except:
                            pass     
             
            # each import directory in 20 bytes so move to the next
            importDirectoryTableOffset += 20
              
    except Exception as e:
        pass
    exe_analysis_json["Imports"] = imports
    exe_analysis += "<b>Imports</b><br><p>"
    for dll in exe_analysis_json["Imports"]:
        for func in exe_analysis_json["Imports"][dll]:
            exe_analysis += dll + "-> " + str(func) + "<br>"
    exe_analysis += "</p>"
    ### END IMPORTS #############################################

    ### EXPORTS #############################################
    # Try to extract the exports
    # start_exportDirectoryTable
    exports = {}
    try:
        eExportFlags = struct.unpack(">I", file_contents[start_exportDirectoryTable:start_exportDirectoryTable+4][::-1])[0]
        eTimeDate = struct.unpack(">I", file_contents[start_exportDirectoryTable+4:start_exportDirectoryTable+8][::-1])[0]
        eMajorVersion = struct.unpack(">H", file_contents[start_exportDirectoryTable+8:start_exportDirectoryTable+10][::-1])[0]
        eMinorVersion = struct.unpack(">H", file_contents[start_exportDirectoryTable+10:start_exportDirectoryTable+12][::-1])[0]
        eNameRVA = struct.unpack(">I", file_contents[start_exportDirectoryTable+12:start_exportDirectoryTable+16][::-1])[0]
        eOrdinalBase = struct.unpack(">I", file_contents[start_exportDirectoryTable+16:start_exportDirectoryTable+20][::-1])[0]
        eAddressTableEntries = struct.unpack(">I", file_contents[start_exportDirectoryTable+20:start_exportDirectoryTable+24][::-1])[0]
        eNumNamePointers = struct.unpack(">I", file_contents[start_exportDirectoryTable+24:start_exportDirectoryTable+28][::-1])[0]
        eExportAddressTableRVA = struct.unpack(">I", file_contents[start_exportDirectoryTable+28:start_exportDirectoryTable+32][::-1])[0]
        eNamePointerRVA = struct.unpack(">I", file_contents[start_exportDirectoryTable+32:start_exportDirectoryTable+36][::-1])[0]
        eOrdinalTableRVA = struct.unpack(">I", file_contents[start_exportDirectoryTable+36:start_exportDirectoryTable+40][::-1])[0]

        # Go through each section so we can turn these RVAs into
        # file offsets
        for s in sections:
            if(eExportAddressTableRVA >= s["VirtualAddress"] and eExportAddressTableRVA <= s["VirtualAddress"] + s["VirtualSize"]):
                eExportAddressTable_file_offset = s["PointerToRawData"] + (eExportAddressTableRVA - s["VirtualAddress"])
                
            if(eNamePointerRVA >= s["VirtualAddress"] and eNamePointerRVA <= s["VirtualAddress"] + s["VirtualSize"]):
                eNamePointer_file_offset = s["PointerToRawData"] + (eNamePointerRVA - s["VirtualAddress"])
                
            if(eOrdinalTableRVA >= s["VirtualAddress"] and eOrdinalTableRVA <= s["VirtualAddress"] + s["VirtualSize"]):
                eOrdinalTable_file_offset = s["PointerToRawData"] + (eOrdinalTableRVA - s["VirtualAddress"])

        offset = 0
        for i in range(0, eAddressTableEntries):
            exports[i] = {}
            ### Parse the Export Address Table ###
            exportAddressTable_RVA_or_Forwarder_RVA = struct.unpack(">I", file_contents[eExportAddressTable_file_offset + offset:eExportAddressTable_file_offset + 4 + offset][::-1])[0]
            # Check if it's a Forwarder RVA
            if(exportAddressTable_RVA_or_Forwarder_RVA >= struct.unpack(">I", mExportTableRVA[::-1])[0] and exportAddressTable_RVA_or_Forwarder_RVA <= struct.unpack(">I", mExportTableRVA[::-1])[0] + struct.unpack(">I", mExportTableSize[::-1])[0]):
                # Then it's a forwarder RVA
                forwarder_string = ""
                for s in sections:
                    if(exportAddressTable_RVA_or_Forwarder_RVA >= s["VirtualAddress"] and exportAddressTable_RVA_or_Forwarder_RVA <= s["VirtualAddress"] + s["VirtualSize"]):
                        forwarder_string_file_offset = s["PointerToRawData"] + (exportAddressTable_RVA_or_Forwarder_RVA - s["VirtualAddress"])
                try:
                    index = 0
                    while(1):
                        char = file_contents[forwarder_string_file_offset + index]
                        if(char == 0):
                            break
                        elif(char >= 32 and char <= 126):
                            forwarder_string += chr(char)
                        else:
                            break
                        index += 1
                    exports[i]["ExportAddressTable"] = ["ForwarderRVA", forwarder_string]
                except:
                    pass
            # else it's a RVA to the function
            else:
                exports[i]["ExportAddressTable"] = ["ExportRVA", exportAddressTable_RVA_or_Forwarder_RVA]

            ### Parse the Export Name Pointer Table ###
            pointer_value = struct.unpack(">I", file_contents[eNamePointer_file_offset + offset:eNamePointer_file_offset + 4 + offset][::-1])[0]
            # Then it's a forwarder RVA
            for s in sections:
                if(pointer_value >= s["VirtualAddress"] and pointer_value <= s["VirtualAddress"] + s["VirtualSize"]):
                    pointer_file_offset = s["PointerToRawData"] + (pointer_value - s["VirtualAddress"])
            export_func_name_value = ""
            try:
                index = 0
                while(1):
                    char = file_contents[pointer_file_offset + index]
                    if(char == 0):
                        break
                    elif(char >= 32 and char <= 126):
                        export_func_name_value += chr(char)
                    else:
                        break
                    index += 1
                exports[i]["ExportNameTable"] = export_func_name_value
            except:
                pass
            ### Parse the Export Ordinal Table ###
            exports[i]["Ordinal"] = eOrdinalBase + i
            #ord_table_file_offset = struct.unpack(">I", file_contents[eOrdinalTable_file_offset + offset:eOrdinalTable_file_offset + 4 + offset][::-1])[0]
            # eOrdinalBase is the starting ord number (usually 1)
            # each ord is 16 bits
            #print(eOrdinalBase)
##            try:
##                biased_ordinal = eOrdinalBase + struct.unpack(">H", file_contents[ord_table_file_offset:ord_table_file_offset+2][::-1])[0]
##                exports[i]["ExportOrdinalTable"] = biased_ordinal
##            except:
##                pass

            offset += 4
        
    except Exception as e:
        pass

    try:
        exe_analysis_json["Exports"] = exports
        exe_analysis += "<b>Exports</b><br><p>Ordinal->Function Name->RVA of Code if applicable<br>"
        for index in exe_analysis_json["Exports"]:
            try:
                exe_analysis += str(exe_analysis_json["Exports"][index]["Ordinal"]) + "-> " + exe_analysis_json["Exports"][index]["ExportNameTable"] + " ->" + hex(exe_analysis_json["Exports"][index]["ExportAddressTable"][1]) + "<br>"
            except Exception as e:
                exe_analysis += str(exe_analysis_json["Exports"]["Ordinal"]) + "-> " + exe_analysis_json["Exports"]["ExportNameTable"] + "<br>"
        exe_analysis += "</p>"
    except:
        pass
    ### END EXPORTS #############################################
    
    exe_analysis += "</body></html>"
    return exe_analysis, exe_analysis_json
