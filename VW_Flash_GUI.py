import glob
import json
import logging
import logging.config
import os
import os.path as path
import sys
import threading
from datetime import datetime
from logging import Formatter
from pathlib import Path
from zipfile import ZipFile

import serial
import serial.tools.list_ports
import wx
from udsoncan import InvalidResponseException

from lib import binfile
from lib import constants
from lib import dq381_flash_utils
from lib import dsg_flash_utils
from lib import extract_flash
from lib import flash_uds
from lib import haldex_flash_utils
from lib import simos_flash_utils
from lib import simos_hsl
from lib.constants import BlockData
from lib.modules import (
    simos8,
    simos10,
    simos12,
    simos122,
    simos18,
    simos1810,
    simos184,
    dq250mqb,
    dq381,
    simos16,
    haldex4motion,
)

DEFAULT_STMIN = 350000

if sys.platform == "win32":
    try:
        import winreg
    except:
        print("module winreg not found")

# Get an instance of logger, which we'll pull from the config file
logger = logging.getLogger("VWFlash")

try:
    currentPath = path.dirname(path.abspath(__file__))
except NameError:  # We are the main py2exe script, not a module
    currentPath = path.dirname(path.abspath(sys.argv[0]))

logging.config.fileConfig(path.join(currentPath, "logging.ini"))
loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]


def write_config(paths):
    with open("gui_config.json", "w") as config_file:
        json.dump(paths, config_file)


def module_selection_is_dq250(selection_index):
    return selection_index == 2


def module_selection_is_dq381(selection_index):
    return selection_index == 3


def module_selection_is_haldex(selected_index):
    return selected_index == 4


def split_interface_name(interface_string: str):
    parts = interface_string.split("_", 1)
    interface = parts[0]
    interface_name = parts[1] if len(parts) > 1 else None
    return interface, interface_name


def get_dlls_from_registry():
    # Interfaces is a list of tuples (name: str, interface specifier: str)
    interfaces = []
    try:
        base_key = winreg.OpenKeyEx(
            winreg.HKEY_LOCAL_MACHINE, r"Software\\PassThruSupport.04.04\\"
        )
    except:
        logger.error("No J2534 DLLs found in HKLM PassThruSupport. Continuing anyway.")
        return interfaces

    for i in range(winreg.QueryInfoKey(base_key)[0]):
        try:
            device_key = winreg.OpenKeyEx(base_key, winreg.EnumKey(base_key, i))
            name = winreg.QueryValueEx(device_key, "Name")[0]
            function_library = winreg.QueryValueEx(device_key, "FunctionLibrary")[0]
            interfaces.append((name, "J2534_" + function_library))
        except:
            logger.error(
                "Found a J2534 interface, but could not enumerate the registry entry. Continuing."
            )
    return interfaces


def socketcan_ports():
    return [("SocketCAN can0", "SocketCAN_can0")]


def poll_interfaces():
    # this is a list of tuples (name: str, interface_specifier: str) where interface_specifier is something like USBISOTP_/dev/ttyUSB0
    interfaces = []

    if sys.platform == "win32":
        interfaces += get_dlls_from_registry()
    if sys.platform == "linux":
        interfaces += socketcan_ports()

    serial_ports = serial.tools.list_ports.comports()
    for port in serial_ports:
        interfaces.append(
            (port.name + " : " + port.description, "USBISOTP_" + port.device)
        )
    return interfaces


class TextCtrlHandler(logging.Handler):
    def __init__(self, text_ctrl):
        super().__init__()
        self.text_ctrl = text_ctrl

    def emit(self, record):
        log_entry = self.format(record)
        wx.CallAfter(self.text_ctrl.AppendText, log_entry + "\n")


class UnlockDialog(wx.Dialog):
    def __init__(self, parent, title):
        super(UnlockDialog, self).__init__(parent, title=title, size=(500, 120))
        self.parent = parent
        # Setup panel & sizers
        panel = wx.Panel(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.AddSpacer(5)
        # Setup UI elements
        self.file_picker = wx.FilePickerCtrl(panel, wildcard="*.frf")
        self.flash_button = wx.Button(panel, wx.ID_OK, label="Unlock ECU")
        self.cancel_button = wx.Button(panel, wx.ID_CANCEL, label="Cancel")
        # Add elements to sizers
        button_sizer.Add(self.flash_button)
        button_sizer.Add(self.cancel_button, flag=wx.LEFT)
        sizer.Add(self.file_picker, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=5)
        sizer.Add(button_sizer, flag=wx.ALIGN_CENTER | wx.TOP, border=5)
        panel.SetSizer(sizer)
        # Bind button clicks
        self.flash_button.Bind(wx.EVT_BUTTON, self.on_button)
        self.cancel_button.Bind(wx.EVT_BUTTON, self.on_button)

    def on_button(self, event):
        if self.IsModal():
            if event.EventObject.Id == wx.ID_OK:
                self.parent.selected_unlock = self.file_picker.GetPath()
                self.EndModal(1)
            else:
                self.EndModal(-1)
        else:
            self.Close()


class StminDialog(wx.Dialog):
    def __init__(self, parent, title, current_value):
        super(StminDialog, self).__init__(parent, title=title, size=(300, 120))
        panel = wx.Panel(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.slider = wx.Slider(
            panel, value=current_value // 1000, minValue=0, maxValue=1000
        )
        self.label = wx.StaticText(panel, label=str(current_value // 1000))
        self.ok_btn = wx.Button(panel, wx.ID_OK, label="Save")
        self.cancel_btn = wx.Button(panel, wx.ID_CANCEL, label="Cancel")
        button_sizer.Add(self.ok_btn)
        button_sizer.Add(self.cancel_btn, flag=wx.Left)
        sizer.Add(self.slider, flag=wx.EXPAND | wx.LEFT | wx.RIGHT)
        sizer.Add(self.label, flag=wx.ALIGN_CENTER)
        sizer.Add(button_sizer, flag=wx.ALIGN_RIGHT | wx.BOTTOM)
        panel.SetSizer(sizer)
        self.ok_btn.Bind(wx.EVT_BUTTON, self.on_button)
        self.cancel_btn.Bind(wx.EVT_BUTTON, self.on_button)
        self.slider.Bind(wx.EVT_SLIDER, self.on_slider)

    def on_slider(self, event):
        self.label.SetLabelText(str(self.slider.GetValue()))

    def on_button(self, event):
        if self.IsModal():
            if event.EventObject.Id == wx.ID_OK:
                self.EndModal(self.slider.GetValue() * 1000)
            else:
                self.EndModal(-1)
        else:
            self.Close()


def log_to_window(text):
    """Append a string to the feedback text control with added timestamp"""
    logger.info(text)


class FlashPanel(wx.Panel):
    input_blocks: dict[str, constants.BlockData]

    def __init__(self, parent):
        super().__init__(parent)

        self.hsl_logger = None

        try:
            with open("gui_config.json", "r") as config_file:
                self.options = json.load(config_file)
        except:
            logger.critical("No config file present, creating one")
            self.options = {
                "cal": os.path.expanduser("~"),
                "flashpack": "",
                "bins": "",
                "logging_path": path.join(currentPath, "logs"),
                "interface": "",
                "singlecsv": False,
                "logmode": "22",
                "activitylevel": "INFO",
            }
            write_config(self.options)

        self.flash_utils = simos_flash_utils

        self.interfaces = poll_interfaces()

        # Pick first interface if none already selected.
        if (len(self.options["interface"])) == 0:
            if len(self.interfaces) > 0:
                self.options["interface"] = self.interfaces[0][1]
                write_config(self.options)

        self.feedback_text = wx.TextCtrl(
            self, size=(-1, 300), style=wx.TE_READONLY | wx.TE_LEFT | wx.TE_MULTILINE
        )

        for a_logger in loggers:
            if a_logger.name in logging.root.manager.loggerDict:
                handler = TextCtrlHandler(self.feedback_text)
                handler.setFormatter(
                    Formatter(
                        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S",
                    )
                )
                a_logger.addHandler(handler)

        logger.info(f"Currently selected interface is: {self.options["interface"]}")
        logger.info(f"Currently selected logging path is: {self.options["logging_path"]}")

        main_sizer = wx.BoxSizer(wx.VERTICAL)
        folder_sizer = wx.BoxSizer(wx.HORIZONTAL)
        actions_sizer = wx.BoxSizer(wx.HORIZONTAL)
        selections_sizer = wx.BoxSizer(wx.HORIZONTAL)

        # Create a drop down menu

        self.flash_info = simos18.s18_flash_info
        available_modules = [
            "Simos 18.1/6",
            "Simos 18.10",
            "DQ250-MQB DSG",
            "DQ381 DSG UNTESTED",
            "Haldex (4motion) UNTESTED",
        ]
        self.module_choice = wx.Choice(self, choices=available_modules)
        self.module_choice.SetSelection(0)
        self.module_choice.Bind(wx.EVT_CHOICE, self.on_module_changed)

        available_actions = [
            "Calibration Flash Unlocked",
            "FlashPack ZIP flash",
            "Full Flash Unlocked (BIN/FRF)",
            "Flash Stock (Re-Lock) / Unmodified BIN/FRF",
        ]
        self.action_choice = wx.Choice(self, choices=available_actions)
        self.action_choice.SetSelection(0)
        self.action_choice.Bind(wx.EVT_CHOICE, self.update_bin_listing)

        self.progress_bar = wx.Gauge(self, range=100, style=wx.GA_HORIZONTAL)

        self.row_obj_dict = {}

        self.list_ctrl = wx.ListCtrl(
            self,
            size=(-1, 250),
            style=wx.LC_REPORT | wx.BORDER_SUNKEN | wx.LC_SINGLE_SEL,
        )
        self.list_ctrl.InsertColumn(0, "Filename", width=400)
        self.list_ctrl.InsertColumn(1, "Modify time", width=100)

        self.list_ctrl.Bind(
            wx.EVT_LIST_ITEM_SELECTED, lambda evt: self.set_item_style(evt, True)
        )
        self.list_ctrl.Bind(
            wx.EVT_LIST_ITEM_DESELECTED, lambda evt: self.set_item_style(evt, False)
        )

        flash_button = wx.Button(self, label="Flash")
        flash_button.Bind(wx.EVT_BUTTON, self.on_flash)

        dtc_button = wx.Button(self, label="Read Trouble Codes")
        dtc_button.Bind(wx.EVT_BUTTON, self.on_read_dtcs)

        get_info_button = wx.Button(self, label="Get Ecu Info")
        get_info_button.Bind(wx.EVT_BUTTON, self.on_get_info)

        self.start_logger_button = wx.Button(self, label="Start Logger")
        self.start_logger_button.Bind(wx.EVT_BUTTON, self.GetParent().on_start_logger)

        self.stop_logger_button = wx.Button(self, label="Stop Logger")
        self.stop_logger_button.Bind(wx.EVT_BUTTON, self.GetParent().on_stop_logger)

        actions_sizer.Add(self.module_choice, 0, wx.LEFT, 5)
        actions_sizer.Add(get_info_button, 0, wx.LEFT | wx.RIGHT, 5)
        actions_sizer.Add(dtc_button, 0, wx.RIGHT, 5)
        actions_sizer.Add(self.start_logger_button, 0, wx.RIGHT, 5)
        actions_sizer.Add(self.stop_logger_button, 0, wx.RIGHT, 5)

        selections_sizer.Add(self.action_choice, 0, wx.EXPAND | wx.ALL, 5)
        selections_sizer.Add(flash_button, 0, wx.EXPAND | wx.ALL, 5)

        main_sizer.Add(self.feedback_text, 0, wx.ALL | wx.EXPAND, 5)
        main_sizer.Add(actions_sizer, 0, wx.TOP, 5)
        main_sizer.Add(folder_sizer, 0, wx.ALIGN_LEFT, 5)
        main_sizer.Add(self.list_ctrl, 0, wx.ALL | wx.EXPAND, 5)
        main_sizer.Add(self.progress_bar, 0, wx.EXPAND, 5)
        main_sizer.Add(selections_sizer)

        self.SetSizer(main_sizer)

        if self.options["cal"] != "":
            self.current_flashfile_folder_path = self.options["cal"]
            self.update_bin_listing()

    def set_item_style(self, event, selected):
        self.list_ctrl.SetItemFont(
            event.GetIndex(), wx.Font(wx.FontInfo().Bold(selected))
        )

    def on_module_changed(self, event):
        module_number = self.module_choice.GetSelection()
        self.flash_info = [
            simos18.s18_flash_info,
            simos1810.s1810_flash_info,
            dq250mqb.dsg_flash_info,
            dq381.dsg_flash_info,
            haldex4motion.haldex_flash_info,
        ][module_number]

    def on_get_info(self, event):
        (interface, interface_path) = split_interface_name(self.options["interface"])
        try:
            ecu_info = flash_uds.read_ecu_data(
                self.flash_info,
                interface=interface,
                callback=self.update_callback,
                interface_path=interface_path,
            )

            [log_to_window(did + " : " + ecu_info[did] + "\n") for did in ecu_info]
        except InvalidResponseException:
            wx.LogError(
                "Failed to establish a connection with the car. Make sure your PC is connected to the car's OBD port"
            )
        except Exception as e:
            wx.LogError(f"An unexpected error occurred: {str(e)}")

    def on_read_dtcs(self, event):
        (interface, interface_path) = split_interface_name(self.options["interface"])
        try:
            dtcs = flash_uds.read_dtcs(
                self.flash_info,
                interface=interface,
                callback=self.update_callback,
                interface_path=interface_path,
            )
            [log_to_window(str(dtc) + " : " + dtcs[dtc] + "\n") for dtc in dtcs]
        except InvalidResponseException:
            wx.LogError(
                "Failed to establish a connection with the car. Make sure your PC is connected to the car's OBD port, either via USB or Bluetooth"
            )
        except Exception as e:
            wx.LogError(f"An unexpected error occurred: {str(e)}")

    def flash_unlock(self, selected_file):
        if (
            module_selection_is_dq250(self.module_choice.GetSelection())
            or module_selection_is_dq381(self.module_choice.GetSelection())
            or module_selection_is_haldex(self.module_choice.GetSelection())
        ):
            log_to_window("SKIPPED: Unlocking is unnecessary for Haldex/DSG\n")
            return

        input_bytes = Path(selected_file).read_bytes()
        if str.endswith(selected_file, ".frf"):
            log_to_window("Extracting FRF for unlock...\n")
            (
                flash_data,
                allowed_boxcodes,
            ) = extract_flash.extract_flash_from_frf(
                input_bytes,
                self.flash_info,
                is_dsg=module_selection_is_dq250(self.module_choice.GetSelection()),
            )
            self.input_blocks = {}
            for i in self.flash_info.block_names_frf.keys():
                filename = self.flash_info.block_names_frf[i]
                self.input_blocks[filename] = constants.BlockData(
                    i, flash_data[filename]
                )

            cal_block = self.input_blocks[self.flash_info.block_names_frf[5]]
            file_box_code = str(
                cal_block.block_bytes[
                    self.flash_info.box_code_location[5][
                        0
                    ] : self.flash_info.box_code_location[5][1]
                ].decode()
            )
            if (
                file_box_code.strip()
                != self.flash_info.patch_info.patch_box_code.split("_")[0].strip()
            ):
                log_to_window(
                    f"Boxcode mismatch for unlocking. Got box code {file_box_code} but expected {self.flash_info.patch_info.patch_box_code}. Please don't try to be clever. Supply the correct file and the process will work."
                )
                return

            self.input_blocks["UNLOCK_PATCH"] = constants.BlockData(
                self.flash_info.patch_info.patch_block_index + 5,
                Path(self.flash_info.patch_info.patch_filename).read_bytes(),
            )
            key_order = list(
                map(lambda index: self.flash_info.block_names_frf[index], [1, 2, 3, 4, 5])
            )
            key_order.insert(4, "UNLOCK_PATCH")
            input_blocks_with_patch = {k: self.input_blocks[k] for k in key_order}
            self.input_blocks = input_blocks_with_patch
            self.flash_bin(get_info=False)
        else:
            log_to_window(
                "File did not appear to be a valid FRF. Unlocking is possible only with a specific FRF file for your ECU family.\n"
            )

    def flash_bin_file(self, selected_file, patch_cboot=False):
        input_bytes = Path(self.row_obj_dict[selected_file]).read_bytes()
        if str.endswith(self.row_obj_dict[selected_file], ".frf"):
            log_to_window("Extracting FRF...\n")
            (
                flash_data,
                allowed_boxcodes,
            ) = extract_flash.extract_flash_from_frf(
                input_bytes,
                self.flash_info,
                is_dsg=module_selection_is_dq250(self.module_choice.GetSelection()),
            )
            self.input_blocks = {}
            for i in self.flash_info.block_names_frf.keys():
                filename = self.flash_info.block_names_frf[i]
                self.input_blocks[filename] = constants.BlockData(
                    i, flash_data[filename]
                )
            self.flash_bin(get_info=False, should_patch_cboot=patch_cboot)
        elif len(input_bytes) == self.flash_info.binfile_size:
            self.input_blocks = binfile.blocks_from_bin(
                self.row_obj_dict[selected_file],
                self.flash_info,
                module_selection_is_haldex(self.module_choice.GetSelection()),
            )
            self.flash_bin(get_info=False, should_patch_cboot=patch_cboot)
        else:
            log_to_window("File did not appear to be a valid BIN or FRF\n")

    def flash_flashpack(self, selected_file: str):
        # We're expecting a "FlashPack" ZIP
        with ZipFile(self.row_obj_dict[selected_file], "r") as zip_archive:
            if "file_list.json" not in zip_archive.namelist():
                log_to_window("SKIPPING: No file listing found in archive\n")

            else:
                with zip_archive.open("file_list.json") as file_list_json:
                    file_list = json.load(file_list_json)

                self.input_blocks = {}
                for filename in file_list:
                    self.input_blocks[filename] = simos_flash_utils.BlockData(
                        int(file_list[filename]), zip_archive.read(filename)
                    )

                self.flash_bin(get_info=False)

    def flash_cal(self, selected_file: str):
        # Flash a Calibration block only
        self.input_blocks = {}

        input_bytes = Path(self.row_obj_dict[selected_file]).read_bytes()
        if len(input_bytes) == self.flash_info.binfile_size:
            log_to_window("Extracting Calibration from full binary...\n")
            if module_selection_is_dq250(self.module_choice.GetSelection()):
                log_to_window("Extracting Driver from full binary...\n")
            input_blocks = binfile.blocks_from_bin(
                self.row_obj_dict[selected_file], self.flash_info
            )
            # Filter to only CAL block.
            self.input_blocks = {
                k: v
                for k, v in input_blocks.items()
                if (v.block_number == self.flash_info.block_name_to_number["CAL"])
                or (
                    module_selection_is_dq250(self.module_choice.GetSelection())
                    and v.block_number == self.flash_info.block_name_to_number["DRIVER"]
                )
            }
        else:
            if module_selection_is_dq250(self.module_choice.GetSelection()):
                # Populate DSG Driver block from a fixed file name if it's a CAL only bin
                dsg_driver_path = path.join(self.options["cal"], "FD_2.DRIVER.bin")
                log_to_window("Loading DSG Driver from: " + dsg_driver_path + "\n")
                self.input_blocks["FD_2.DRIVER.bin"] = constants.BlockData(
                    self.flash_info.block_name_to_number["DRIVER"],
                    Path(dsg_driver_path).read_bytes(),
                )
            self.input_blocks[self.row_obj_dict[selected_file]] = constants.BlockData(
                self.flash_info.block_name_to_number["CAL"],
                input_bytes,
            )

        self.flash_bin()

    def on_flash(self, event):
        selected_file = self.list_ctrl.GetFirstSelected()
        if selected_file == -1:
            log_to_window("SKIPPING: Select a file to flash!\n")
            return

        file_name = str(self.row_obj_dict[selected_file])

        module = self.module_choice.GetSelection()

        logger.critical("Selected: " + file_name)

        modal_response = wx.MessageDialog(
            None,
            "Are you sure you want to flash: "
            + file_name.rsplit("\\", 1)[-1]
            + "\n"
            + "To module: "
            + self.module_choice.GetString(module)
            + "?",
            "Confirm Flash",
            wx.YES_NO | wx.NO_DEFAULT | wx.ICON_WARNING | wx.CENTRE,
        ).ShowModal()

        if modal_response != wx.ID_YES:
            logger.info("User cancelled flash.")
            return

        choice = self.action_choice.GetSelection()
        if choice == 0:
            # "Flash Calibration"
            self.flash_cal(selected_file)

        elif choice == 1:
            # "Flash Flashpack"
            self.flash_flashpack(selected_file)

        elif choice == 2:
            # Flash BIN/FRF (unlocked)
            self.flash_bin_file(selected_file, patch_cboot=True)

        elif choice == 3:
            # Flash to stock
            self.flash_bin_file(selected_file, patch_cboot=False)

    def update_bin_listing(self, event=None):
        self.list_ctrl.ClearAll()

        self.list_ctrl.InsertColumn(0, "Filename", width=500)
        self.list_ctrl.InsertColumn(1, "Modify Time", width=140)

        if self.action_choice.GetSelection() == 0:
            # Calibration Flash
            bins = glob.glob(self.current_flashfile_folder_path + "/*.bin")
            self.options["cal"] = self.current_flashfile_folder_path
        elif self.action_choice.GetSelection() == 1:
            # Flashpack
            bins = glob.glob(self.current_flashfile_folder_path + "/*.zip")
            self.options["flashpacks"] = self.current_flashfile_folder_path
        elif self.action_choice.GetSelection() == 2:
            # Full BIN/FRF Unlocked
            bins = glob.glob(self.current_flashfile_folder_path + "/*.bin")
            bins.extend(glob.glob(self.current_flashfile_folder_path + "/*.frf"))
            self.options["bins"] = self.current_flashfile_folder_path
        else:
            # Unmodified flash
            bins = glob.glob(self.current_flashfile_folder_path + "/*.bin")
            bins.extend(glob.glob(self.current_flashfile_folder_path + "/*.frf"))
            self.options["bins"] = self.current_flashfile_folder_path

        write_config(self.options)
        bins.sort(key=path.getmtime, reverse=True)

        bin_objects = []
        index = 0
        for bin_file in bins:
            self.list_ctrl.InsertItem(index, path.basename(bin_file))
            self.list_ctrl.SetItem(
                index,
                1,
                str(
                    datetime.fromtimestamp(path.getmtime(bin_file)).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                ),
            )

            bin_objects.append(bin_file)
            self.row_obj_dict[index] = bin_file
            index += 1

    def threaded_callback(self, step, status, progress):
        self.GetParent().statusbar.SetStatusText(step)
        self.progress_bar.SetValue(round(float(progress)))
        log_to_window(step + " - " + status + " - " + str(progress))

    def update_callback(self, **kwargs):
        if "flasher_step" in kwargs:
            wx.CallAfter(
                self.threaded_callback,
                kwargs["flasher_step"],
                kwargs["flasher_status"],
                kwargs["flasher_progress"],
            )
        else:
            wx.CallAfter(self.threaded_callback, kwargs["logger_status"], "0", 0)

    def flash_bin(self, get_info=True, should_patch_cboot=False):
        (interface, interface_path) = split_interface_name(self.options["interface"])
        if module_selection_is_dq250(self.module_choice.GetSelection()):
            self.flash_utils = dsg_flash_utils
        elif module_selection_is_dq381(self.module_choice.GetSelection()):
            self.flash_utils = dq381_flash_utils
        elif module_selection_is_haldex(self.module_choice.GetSelection()):
            self.flash_utils = haldex_flash_utils
        else:
            self.flash_utils = simos_flash_utils

        log_to_window(
            "Starting to flash the following software components : \n"
            + binfile.input_block_info(self.input_blocks, self.flash_info)
            + "\n"
        )

        if get_info:
            try:
                ecu_info = flash_uds.read_ecu_data(
                    self.flash_info,
                    interface=interface,
                    callback=self.update_callback,
                    interface_path=interface_path,
                )

                [
                    log_to_window(did + " : " + ecu_info[did] + "\n")
                    for did in ecu_info
                ]
            except InvalidResponseException:
                wx.LogError(
                    "Failed to establish a connection with the car. Make sure your PC is connected to the car's OBD port"
                )
                ecu_info = None
            except Exception as e:
                wx.LogError(f"An unexpected error occurred: {str(e)}")
                ecu_info = None

        else:
            ecu_info = None

        for filename in self.input_blocks:
            file_box_code = str(
                self.input_blocks[filename]
                .block_bytes[
                    self.flash_info.box_code_location[
                        self.input_blocks[filename].block_number
                    ][0] : self.flash_info.box_code_location[
                        self.input_blocks[filename].block_number
                    ][
                        1
                    ]
                ]
                .decode()
            )

            if (
                ecu_info is not None
                and (
                    module_selection_is_dq250(self.module_choice.GetSelection())
                    or module_selection_is_dq381(self.module_choice.GetSelection())
                    or module_selection_is_haldex(self.module_choice.GetSelection())
                )
                is not True
                and ecu_info["VW Spare Part Number"].strip() != file_box_code.strip()
            ):
                log_to_window(
                    "Attempting to flash a file that doesn't match box codes, exiting!: "
                    + ecu_info["VW Spare Part Number"]
                    + " != "
                    + file_box_code
                    + "\n"
                )
                return

        stmin_override = self.options.get("stmin_override", DEFAULT_STMIN)

        flasher_thread = threading.Thread(
            target=self.flash_utils.flash_bin,
            args=(
                self.flash_info,
                self.input_blocks,
                self.update_callback,
                interface,
                should_patch_cboot,
                interface_path,
                stmin_override,
            ),
        )
        flasher_thread.daemon = True
        flasher_thread.start()


def try_extract_frf(frf_data: bytes):
    flash_infos = [
        simos18.s18_flash_info,
        simos1810.s1810_flash_info,
        dq250mqb.dsg_flash_info,
        dq381.dsg_flash_info,
        haldex4motion.haldex_flash_info,
        simos184.s1841_flash_info,
        simos16.s16_flash_info,
        simos12.s12_flash_info,
        simos122.s122_flash_info,
        simos10.s10_flash_info,
        simos8.s8_flash_info,
    ]
    for flash_info in flash_infos:
        try:
            (flash_data, allowed_boxcodes) = extract_flash.extract_flash_from_frf(
                frf_data,
                flash_info,
                is_dsg=(flash_info is dq250mqb.dsg_flash_info),
            )
            output_blocks = {}
            for i in flash_info.block_names_frf.keys():
                filename = flash_info.block_names_frf[i]
                output_blocks[filename] = constants.BlockData(
                    i, flash_data[filename], flash_info.number_to_block_name[i]
                )
            return [output_blocks, flash_info]
        except:
            pass


def extract_frf_task(frf_path: str, output_path: str, callback):
    frf_name = str.removesuffix(frf_path, ".frf")
    [output_blocks, flash_info] = try_extract_frf(Path(frf_path).read_bytes())
    outfile_data = binfile.bin_from_blocks(output_blocks, flash_info)
    callback(50)
    Path(output_path, Path(frf_name).name + ".bin").write_bytes(outfile_data)

    for filename in output_blocks:
        output_block: constants.BlockData = output_blocks[filename]
        binary_data = output_block.block_bytes
        output_filename = (
            filename.rstrip(".bin") + "." + output_block.block_name + ".bin"
        )
        Path(output_path, output_filename).write_bytes(binary_data)
    callback(100)


def extract_bin_task(bin_path: str, output_path: str, flash_info, callback, flash_utils=simos_flash_utils):
    input_blocks = binfile.blocks_from_bin(bin_path, flash_info)
    logger.info(binfile.input_block_info(input_blocks, flash_info))

    output_blocks = flash_utils.checksum_and_patch_blocks(
        flash_info,
        input_blocks,
        should_patch_cboot=False
    )

    for filename in output_blocks:
        output_block: BlockData = output_blocks[filename]
        binary_data = output_block.block_bytes
        block_number = output_block.block_number
        file_name = filename.rstrip(".bin") + "." + output_block.block_name + ".bin"
        Path(output_path, file_name).write_bytes(binary_data)

    callback(100)

class VWFlashFrame(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, parent=None, title="VW_Flash GUI", size=(640, 770))
        self.panel = FlashPanel(self)
        self.create_menu()
        self.statusbar = self.CreateStatusBar(1)
        self.statusbar.SetStatusText("Choose a bin file directory")
        self.hsl_logger = self.panel.hsl_logger = None
        self.selected_unlock = None
        self.Show()

    def create_menu(self):
        menu_bar = wx.MenuBar()

        file_menu = wx.Menu()
        open_folder_menu_item = file_menu.Append(
            wx.ID_ANY, "Open Folder...", "Open a folder with bins"
        )
        extract_frf_menu_item = file_menu.Append(
            wx.ID_ANY, "Extract FRF...", "Extract an FRF file"
        )
        extract_bin_menu_item = file_menu.Append(
            wx.ID_ANY, "Extract BIN...", "Extract a FULL BIN file"
        )

        menu_bar.Append(file_menu, "&File")
        self.Bind(
            event=wx.EVT_MENU, handler=self.on_open_folder, source=open_folder_menu_item,
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_select_extract_frf,
            source=extract_frf_menu_item,
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_select_extract_bin,
            source=extract_bin_menu_item
        )

        unlock_ecu_menu_item = file_menu.Append(
            wx.ID_ANY,
            "Unlock ECU...",
            "Choose the FRF file for unlocking the selected ECU",
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_select_unlock,
            source=unlock_ecu_menu_item,
        )

        interface_menu = wx.Menu()

        select_interface_menu_item = interface_menu.Append(
            wx.ID_ANY, "Select Interface...", "Select a CAN or PassThru Interface"
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_select_interface,
            source=select_interface_menu_item,
        )

        set_stmin_menu_item = interface_menu.Append(
            wx.ID_ANY,
            "Change STMIN_TX...",
            "Change the transmit framing delay for interface",
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_select_stmin,
            source=set_stmin_menu_item,
        )

        menu_bar.Append(interface_menu, "&Interface")

        logger_menu = wx.Menu()
        logger_path_menu_item = logger_menu.Append(
            wx.ID_ANY,
            "Select logging path...",
            "Select folder for logging configuration and data.",
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.select_logger_path,
            source=logger_path_menu_item,
        )

        logging_modes = ["22", "22-MED", "3E", "HSL"]
        logging_modes_menu = wx.Menu()
        for mode in logging_modes:
            radio_item = logging_modes_menu.AppendRadioItem(
                wx.ID_ANY, mode, "Logging Mode: " + mode
            )
            radio_item.Check(self.panel.options.get("logmode", "22") == mode)

            self.Bind(
                wx.EVT_MENU,
                lambda evt, temp=mode: self.on_select_logging_mode(temp),
                source=radio_item,
            )

        logger_menu.AppendSubMenu(
            logging_modes_menu, "&Logging Mode", "Select Logging Mode"
        )
        menu_bar.Append(logger_menu, "&Logger")

        self.SetMenuBar(menu_bar)

    def on_open_folder(self, event):
        title = "Choose a directory of flash files:"
        dlg = wx.DirDialog(self, title, style=wx.DD_DEFAULT_STYLE, defaultPath=self.panel.current_flashfile_folder_path)
        if dlg.ShowModal() == wx.ID_OK:
            self.panel.current_flashfile_folder_path = dlg.GetPath()
            self.panel.update_bin_listing()
        dlg.Destroy()

    def on_select_logging_mode(self, event, mode):
        self.panel.options["logmode"] = mode
        write_config(self.panel.options)

    def on_select_unlock(self, event):
        module = self.panel.module_choice.GetSelection()
        if module not in [0, 1]:
            log_to_window("This module does not require unlocking!\n")
            return

        dlg = UnlockDialog(
            self, "Select unlock FRF for " + self.panel.module_choice.GetString(module)
        )
        res = dlg.ShowModal()
        if res > 0:
            if self.selected_unlock == "":
                log_to_window("No FRF selected, aborting unlock!\n")
                return
            self.panel.flash_unlock(self.selected_unlock)
        dlg.Destroy()

    def on_select_stmin(self, event):
        title = "Change STMIN_TX:"
        stmin_override = self.panel.options.get("stmin_override", DEFAULT_STMIN)
        dlg = StminDialog(self, title, stmin_override)
        res = dlg.ShowModal()
        if res > 0:
            self.panel.options["stmin_override"] = res
            write_config(self.panel.options)
        dlg.Destroy()

    def select_logger_path(self, event):
        title = "Choose a directory for logging:"
        dlg = wx.DirDialog(self, title, style=wx.DD_DEFAULT_STYLE, defaultPath=self.panel.options["logging_path"])
        if dlg.ShowModal() == wx.ID_OK:
            self.panel.options["logging_path"] = dlg.GetPath()
            write_config(self.panel.options)
        dlg.Destroy()

    def on_start_logger(self, event):
        if self.hsl_logger is not None:
            return

        if self.panel.options["logging_path"] == "":
            return

        (interface, interface_path) = split_interface_name(
            self.panel.options["interface"]
        )
        self.hsl_logger = simos_hsl.hsl_logger(
            runServer=False,
            interactive=False,
            mode=self.panel.options["logmode"],
            level=self.panel.options["activitylevel"],
            path=self.panel.options["logging_path"] + "/",
            callbackFunction=self.panel.update_callback,
            interface=interface,
            singleCSV=self.panel.options["singlecsv"],
            interfacePath=interface_path,
            displayGauges=False,
        )

        logger_thread = threading.Thread(target=self.hsl_logger.startLogger)
        logger_thread.daemon = True
        logger_thread.start()

        return

    def on_stop_logger(self, event):

        if self.hsl_logger is not None:
            self.hsl_logger.stop()
            self.hsl_logger = None

    def on_select_interface(self, event):
        progress_dialog = wx.ProgressDialog(
            "Scanning for devices...",
            "Checking J2534 and serial...",
            maximum=100,
            parent=self,
            style=wx.PD_APP_MODAL | wx.PD_AUTO_HIDE,
        )

        progress_dialog.Show()
        self.panel.interfaces = poll_interfaces()
        progress_dialog.Update(100)

        dialog_interfaces = []
        self.panel.interfaces = list(
            filter(lambda interfaces: interfaces[0] is not None, self.panel.interfaces)
        )
        for interface in self.panel.interfaces:
            dialog_interfaces.append(interface[0])

        dlg = wx.SingleChoiceDialog(
            self, "Select an Interface", "Select an interface", dialog_interfaces
        )

        if dlg.ShowModal() == wx.ID_OK:
            self.panel.options["interface"] = self.panel.interfaces[dlg.GetSelection()][
                1
            ]
            write_config(self.panel.options)
            logger.info("User selected interface: " + self.panel.options["interface"])
        dlg.Destroy()

    def on_select_extract_frf(self, event):
        title = "Choose an FRF file:"
        dlg = wx.FileDialog(self, title, style=wx.FD_DEFAULT_STYLE, wildcard="*.frf")
        if dlg.ShowModal() == wx.ID_OK:
            frf_file = dlg.GetPath()
            dlg.Destroy()
            title = "Choose an output directory:"
            dlg = wx.DirDialog(self, title)
            if dlg.ShowModal() == wx.ID_OK:
                output_dir = dlg.GetPath()
                progress_dialog = wx.ProgressDialog(
                    "Extracting FRF",
                    "Decrypting and unpacking...",
                    maximum=100,
                    parent=self,
                    style=wx.PD_APP_MODAL | wx.PD_AUTO_HIDE,
                )
                callback = lambda progress: wx.CallAfter(
                    progress_dialog.Update, progress
                )
                frf_thread = threading.Thread(
                    target=extract_frf_task,
                    args=(frf_file, output_dir, callback),
                )
                frf_thread.start()
                progress_dialog.Pulse()
                progress_dialog.Show()

    def on_select_extract_bin(self, event):
        title = "Choose an BIN file:"
        dlg = wx.FileDialog(self, title, style=wx.FD_DEFAULT_STYLE, wildcard="*.bin")
        if dlg.ShowModal() == wx.ID_OK:
            bin_file = dlg.GetPath()
            dlg.Destroy()
            title = "Choose an output directory:"
            dlg = wx.DirDialog(self, title)
            if dlg.ShowModal() == wx.ID_OK:
                output_dir = dlg.GetPath()
                progress_dialog = wx.ProgressDialog(
                    "Extracting FULL BIN",
                    "Decrypting and unpacking...",
                    maximum=100,
                    parent=self,
                    style=wx.PD_APP_MODAL | wx.PD_AUTO_HIDE,
                )
                callback = lambda progress: wx.CallAfter(
                    progress_dialog.Update, progress
                )
                bin_extract_thread = threading.Thread(
                    target=extract_bin_task,
                    args=(bin_file, output_dir, self.panel.flash_info, callback, self.panel.flash_utils),
                )
                bin_extract_thread.start()
                progress_dialog.Pulse()
                progress_dialog.Show()

if __name__ == "__main__":
    app = wx.App(False)
    frame = VWFlashFrame()
    app.MainLoop()
