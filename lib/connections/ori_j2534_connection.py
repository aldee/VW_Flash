import ctypes
import queue
import threading
from typing import Optional

from udsoncan import TimeoutException
from udsoncan.connections import BaseConnection
from udsoncan.j2534 import (
    TxStatusFlag,
    J2534,
    Protocol_ID,
    Ioctl_Flags,
    SCONFIG_LIST,
    Ioctl_ID,
    Error_ID,
)


class J2534Connection(BaseConnection):
    """
    Sends and receives data through a J2534 Interface.
    A windows DLL and a J2534 interface must be installed in order to use this connection

    :param windll: The path to the windows DLL for the J2534 interface (example: 'C:/Program Files{x86}../../openport 2.0/op20pt32.dll')
    :type interface: string
    :param rxid: The reception CAN id
    :type rxid: int
    :param txid: The transmission CAN id
    :type txid: int
    :param name: This name is included in the logger name so that its output can be redirected. The logger name will be ``Connection[<name>]``
    :type name: string
    :param debug: This will enable windows debugging mode in the dll (see tactrix doc for additional information)
    :type debug: boolean
    :param args: Optional parameters list (Unused right now).
    :type args: list
    :param kwargs: Optional parameters dictionary Unused right now).
    :type kwargs: dict

    """

    interface: "J2534"
    protocol: "Protocol_ID"
    baudrate: int
    result: "Error_ID"
    firmwareVersion: "ctypes.Array[ctypes.c_char]"
    dllVersion: "ctypes.Array[ctypes.c_char]"
    apiVersion: "ctypes.Array[ctypes.c_char]"
    rxqueue: "queue.Queue[bytes]"
    exit_requested: bool
    opened: bool

    def __init__(
        self,
        windll: str,
        rxid: int,
        txid: int,
        name: Optional[str] = None,
        debug: bool = False,
        st_min=None,
        *args,
        **kwargs
    ):

        BaseConnection.__init__(self, name)

        # Determine mode ID29 or ID11
        txFlags = (
            TxStatusFlag.ISO15765_CAN_ID_29.value
            if txid >> 11
            else TxStatusFlag.ISO15765_CAN_ID_11.value
        )

        # Set up a J2534 interface using the DLL provided
        self.interface = J2534(windll=windll, rxid=rxid, txid=txid, txFlags=txFlags)

        # Set the protocol to ISO15765, Baud rate to 500000
        self.protocol = Protocol_ID.ISO15765
        self.baudrate = 500000
        self.debug = debug

        # Open the interface (connect to the DLL)
        result, self.devID = self.interface.PassThruOpen()

        if debug:
            self.result = self.interface.PassThruIoctl(
                0,
                Ioctl_Flags.TX_IOCTL_SET_DLL_DEBUG_FLAGS,
                SCONFIG_LIST(
                    [(0, Ioctl_Flags.TX_IOCTL_DLL_DEBUG_FLAG_J2534_CALLS.value)]
                ),
            )
            self.log_last_operation("PassThruIoctl SET_DLL_DEBUG")

        # Get the firmeware and DLL version etc, mainly for debugging output
        self.result, self.firmwareVersion, self.dllVersion, self.apiVersion = (
            self.interface.PassThruReadVersion(self.devID)
        )
        self.logger.info(
            "J2534 FirmwareVersion: "
            + str(self.firmwareVersion.value)
            + ", dllVersion: "
            + str(self.dllVersion.value)
            + ", apiVersion"
            + str(self.apiVersion.value)
        )

        # get the channel ID of the interface (used for subsequent communication)
        self.result, self.channelID = self.interface.PassThruConnect(
            self.devID, self.protocol.value, self.baudrate
        )
        self.log_last_operation("PassThruConnect")

        configs = SCONFIG_LIST(
            [
                (Ioctl_ID.DATA_RATE.value, 500000),
                (Ioctl_ID.LOOPBACK.value, 0),
                (Ioctl_ID.ISO15765_BS.value, 0x20),
                (Ioctl_ID.ISO15765_STMIN.value, 0),
                (Ioctl_ID.STMIN_TX.value, st_min),
            ]
        )
        self.result = self.interface.PassThruIoctl(
            self.channelID, Ioctl_ID.SET_CONFIG, configs
        )
        self.log_last_operation("PassThruIoctl SET_CONFIG")

        self.result = self.interface.PassThruIoctl(
            self.channelID, Ioctl_ID.CLEAR_MSG_FILTERS
        )
        self.log_last_operation("PassThruIoctl CLEAR_MSG_FILTERS")

        # Set the filters and clear the read buffer (filters will be set based on tx/rxids)
        self.result = self.interface.PassThruStartMsgFilter(
            self.channelID, self.protocol.value
        )
        self.log_last_operation("PassThruStartMsgFilter")

        self.result = self.interface.PassThruIoctl(
            self.channelID, Ioctl_ID.CLEAR_RX_BUFFER
        )
        self.log_last_operation("PassThruIoctl CLEAR_RX_BUFFER")

        self.result = self.interface.PassThruIoctl(
            self.channelID, Ioctl_ID.CLEAR_TX_BUFFER
        )
        self.log_last_operation("PassThruIoctl CLEAR_TX_BUFFER")

        self.rxqueue = queue.Queue()
        self.exit_requested = False
        self.opened = False

    def open(self) -> "J2534Connection":
        self.exit_requested = False
        self.rxthread = threading.Thread(target=self.rxthread_task, daemon=True)
        self.rxthread.start()
        self.opened = True
        self.logger.info("J2534 Connection opened")
        return self

    def __enter__(self) -> "J2534Connection":
        return self

    def __exit__(self, type, value, traceback) -> None:
        self.close()

    def is_open(self) -> bool:
        return self.opened

    def rxthread_task(self) -> None:

        while not self.exit_requested:
            try:
                result, data, numMessages = self.interface.PassThruReadMsgs(
                    self.channelID, self.protocol.value, 1, 1
                )
                if data is not None:
                    self.rxqueue.put(data)
            except Exception:
                self.logger.critical("Exiting J2534 rx thread")
                self.exit_requested = True

    def log_last_operation(self, exec_method: str) -> None:
        res, pErrDescr = self.interface.PassThruGetLastError()
        if self.result != Error_ID.ERR_SUCCESS:
            self.logger.error("J2534 %s: %s %s" % (exec_method, self.result, pErrDescr))

        elif self.debug:
            self.logger.debug("J2534 %s: OK" % (exec_method))

    def close(self) -> None:
        self.exit_requested = True
        self.rxthread.join()
        self.result = self.interface.PassThruDisconnect(self.channelID)
        self.result = self.interface.PassThruClose(self.devID)
        self.opened = False
        self.log_last_operation("Connection closed")

    def specific_send(self, payload: bytes, timeout: Optional[float] = None):
        if timeout is None:
            timeout = 0
        result = self.interface.PassThruWriteMsgs(
            self.channelID, payload, self.protocol.value, Timeout=int(timeout * 1000)
        )

    def specific_wait_frame(self, timeout: Optional[float] = None) -> Optional[bytes]:
        if not self.opened:
            raise RuntimeError("J2534 Connection is not open")

        timedout = False
        frame = None
        try:
            frame = self.rxqueue.get(block=True, timeout=timeout)
        except queue.Empty:
            timedout = True

        if timedout:
            raise TimeoutException(
                "Did not received response from J2534 RxQueue (timeout=%s sec)"
                % timeout
            )

        return frame

    def empty_rxqueue(self) -> None:
        while not self.rxqueue.empty():
            self.rxqueue.get()
