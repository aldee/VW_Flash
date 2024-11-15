import logging
import sys
import winreg

import serial.tools.list_ports

logging.basicConfig(level=logging.INFO)

import wx


def get_dlls_from_registry():
    interfaces = []

    try:
        base_key = winreg.OpenKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\\PassThruSupport.04.04\\"
        )
    except:
        logging.error("No J2534 DLLs found, returning empty list of interfaces")
        return interfaces

    for i in range(winreg.QueryInfoKey(base_key)[0]):
        try:
            device_key = winreg.OpenKeyEx(base_key, winreg.EnumKey(base_key, i))
            name = winreg.QueryValueEx(device_key, "Name")[0]
            function_library = winreg.QueryValueEx(device_key, "FunctionLibrary")[0]
            interfaces.append((name, f"J2534_{name}_{function_library}"))
        except:
            logging.error("Found a J2534 interface, but could not enumerate the registry entry. Continuing.")

    return interfaces


def get_socketcan_ports():
    # TODO: implement fetching of SocketCAN ports in linux
    return [("SocketCAN can0", "SocketCAN_can0")]


def poll_interfaces():
    interfaces = []

    if sys.platform == "win32":
        interfaces += get_dlls_from_registry()
    elif sys.platform == "linux":
        interfaces += get_socketcan_ports()

    serial_ports = serial.tools.list_ports.comports()
    for port in serial_ports:
        interfaces.append((port.name + " : " + port.description, "USBISOTP_" + port.device))

    return interfaces


class Window(wx.Frame):
    def __init__(self, title):
        super().__init__(parent=None, title=title, size=(480, 640))
        self.panel = wx.Panel(self)

        self.selected_interface = None

        action_button_sizer = wx.BoxSizer(wx.HORIZONTAL)

        select_interface_button = wx.Button(self.panel, label="Select Interface", size=(100, 50))
        select_interface_button.Bind(wx.EVT_BUTTON, self.on_select_interface)
        action_button_sizer.Add(
            select_interface_button, 0, wx.ALL, 8
        )
        
        main_sizer = wx.BoxSizer(wx.VERTICAL)
        main_sizer.Add(action_button_sizer)
        
        self.panel.SetSizer(main_sizer)

        self.statusbar = self.CreateStatusBar(2)

        self.Show()

    def on_select_interface(self, event):
        logging.info("Select Interface button clicked")

        diag_interfaces = list(filter(lambda interfaces: interfaces[0] is not None, poll_interfaces()))

        dialog_interfaces = []

        for interface in diag_interfaces:
            dialog_interfaces.append(interface[0])

        interface_dialog = wx.SingleChoiceDialog(
            self,
            "Select an interface",
            "Select an interface to connect to your car",
            dialog_interfaces
        )

        if interface_dialog.ShowModal() == wx.ID_OK:
            self.selected_interface = diag_interfaces[interface_dialog.GetSelection()]
            logging.info("User selected interface: " + self.selected_interface[0])
            self.statusbar.SetStatusText(
                self.selected_interface[0],
                1
            )
        interface_dialog.Destroy()


app = wx.App()
window = Window("VW Flash GUI")
app.MainLoop()
