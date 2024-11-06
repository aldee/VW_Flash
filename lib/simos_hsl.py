#!/usr/bin/env python3
# yaml is used to define the logged parameters, bytes is for byte stuff, and
#  threading is so we can handle multiple threads (start the reader thread)
#  time is used so I could put pauses in various places
#  argparse is used to handle the argument parser
#  os does various filesystem/path checks
#  logging is used so we can log to an activity log
#  struct is used for some of the floating point conversions from the ECU
import csv
import json
import logging
import os
import shutil
import socket
import struct
import sys
import threading
import time

# import datetime so we can put something in the CSV, and import timedelta
# which will help us calculate the time to stop WOT logging
from datetime import datetime
from math import sqrt

import yaml
from udsoncan import configs, TimeoutException
from udsoncan import exceptions

# import the udsoncan stuff
from udsoncan.client import Client

from lib import constants
from lib.connections.connection_setup import connection_setup

try:
    from dashing import *
except:
    print("dashing module not loaded")

# globals
KG_TO_N = 9.80665
TQ_CONSTANT = 16.3
PI = 3.14


class hsl_logger:
    def load_config(self, config_path):
        """Load configuration from a given path."""
        if not os.path.exists(config_path) or not os.access(config_path, os.R_OK):
            return None

        try:
            self.activityLogger.debug(f"Loading configuration file: {config_path}")
            with open(config_path, "r") as configFile:
                return yaml.safe_load(configFile)
        except Exception as e:
            self.activityLogger.info(f"No configuration file loaded: {str(e)}")
            return None

    def parse_configuration(self, configuration):
        """Parse and apply configuration settings."""
        if "Log Prefix" in configuration:
            self.activityLogger.debug(f"  Log Prefix: {self.logPrefix}")
            self.logPrefix = str(configuration["Log Prefix"])

        if "Allow Display" in configuration:
            self.activityLogger.debug(
                f"  Allow Display: {str(configuration['Allow Display'])}"
            )
            self.displayGauges = bool(configuration["Allow Display"])

        if "Log Trigger" in configuration:
            self.activityLogger.debug(
                f"  Log Trigger: {str(configuration['Log Trigger'])}"
            )
            self.logTrigger = str(configuration["Log Trigger"])

        if "Calculate HP" in configuration:
            hp_config = configuration["Calculate HP"]
            hp_type = hp_config.get("Type", "").lower()
            if hp_type == "none":
                self.activityLogger.debug("  Calculate HP: None")
                self.calcHP = 0
            elif hp_type == "reported":
                self.activityLogger.debug("  Calculate HP: Reported TQ")
                self.calcHP = 1
            elif hp_type == "accel":
                self.activityLogger.debug("  Calculate HP: Accelerometer TQ")
                self.calcHP = 2

            self.curbWeight = float(hp_config.get("Curb Weight", 0)) * KG_TO_N
            self.tireCircumference = float(hp_config.get("Tire Circumference", 0)) * PI
            self.frontalArea = float(hp_config.get("Frontal Area", 0))
            self.coefficientOfDrag = float(hp_config.get("Coefficient Of Drag", 0))

            for g in range(1, 8):
                gearString = f"Gear {g}"
                if gearString in hp_config:
                    self.gearRatios[g - 1] = float(hp_config[gearString])

        # Additional logType configuration
        logTypeConfig = configuration.get("Mode" + self.logType, {})
        if logTypeConfig:
            self.activityLogger.debug(f"  Mode {self.logType}")
            fps = logTypeConfig.get("fps")
            if fps:
                self.activityLogger.debug(f"    FPS: {fps}")
            self.param_file = logTypeConfig.get("param_file")
            if self.param_file:
                self.activityLogger.debug(f"    Parameter File: {self.param_file}")

    def load_and_apply_config(self):
        # Primary configuration path
        config_path = self.CONFIGFILE
        configuration = self.load_config(config_path)

        # If the primary config is missing, attempt to load a default config
        if not configuration:
            config_path = constants.internal_path("logs", "log_config.yaml")
            configuration = self.load_config(config_path)

        if configuration:
            self.parse_configuration(configuration)

    def load_parameters(self, param_path):
        """Load parameters from a CSV file and parse each entry."""
        if not os.path.exists(param_path) or not os.access(param_path, os.R_OK):
            return False

        try:
            self.activityLogger.debug(f"Loading parameters from: {param_path}")
            with open(param_path, "r") as parameterFile:
                csvParams = csv.DictReader(parameterFile)
                for param in csvParams:
                    self.process_parameter(param)
            return True
        except Exception as e:
            self.activityLogger.info(f"Error loading parameter file: {str(e)}")
            return False

    def process_parameter(self, param):
        """Process a single parameter entry from the CSV."""
        param_entry = {
            "Name": param["Name"],
            "Address": param["Address"],
            "Length": int(param["Length"]),
            "Equation": param["Equation"].lower(),
            "Signed": param["Signed"].lower() == "true",
            "ProgMin": float(param["ProgMin"]),
            "ProgMax": float(param["ProgMax"]),
            "Value": 0.0,
            "Raw": 0.0,
            "Virtual": param["Address"].lstrip("0x").lower() in {"ffff", "ffffffff"},
        }
        self.logParams[self.pid_counter] = param_entry

        # Assignment validation and logging
        assign_to = param.get("Assign To", "").lower()
        if self.validate_assignment(assign_to):
            self.activityLogger.debug(f"Assignment: {assign_to} to: {param['Name']}")
            self.assignments[assign_to] = self.pid_counter
            self.assignment_counter += 1

        # Update CSV header and divider
        self.csvHeader += f",{param['Name']}"
        self.csvDivider += ",0"
        self.activityLogger.debug(
            f"Logging parameter: {param['Name']}|{param['Address']}|{param['Length']}|{param_entry['Signed']}"
        )
        self.pid_counter += 1

    def validate_assignment(self, assign_to):
        """Validate if the assignment string is acceptable."""
        if assign_to and assign_to not in {"", "x", "e", "hp", "tq"}:
            if all(ch == "_" or "a" <= ch <= "z" for ch in assign_to):
                return True
            else:
                self.activityLogger.warning(f"Invalid Assignment: {assign_to}")
        return False

    def load_and_initialize_parameters(self, param_file):
        # Primary parameter file path
        param_path = self.PARAMFILE
        if not self.load_parameters(param_path):
            # Use default path if primary file is missing
            self.PARAMFILE = constants.internal_path("logs", param_file)
            self.load_parameters(self.PARAMFILE)

    def __init__(
        self,
        runServer=False,
        interactive=False,
        mode="22",
        level=None,
        path="./",
        callbackFunction=None,
        interface="J2534",
        singleCSV=False,
        interfacePath=None,
        displayGauges=False,
    ):
        # set defaults
        self.activityLogger = logging.getLogger("SimosHSL")
        self.dataStream = {}
        self.runServer = runServer
        self.interactive = interactive
        self.interface = interface
        self.interfacePath = interfacePath
        self.callbackFunction = callbackFunction
        self.mode = mode.upper()
        self.filePath = path
        self.singleCSV = singleCSV
        self.currentTime = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.kill = False
        self.logPrefix = "Logging_"
        self.displayGauges = displayGauges
        self.dataRow = None
        self.isLogging = False
        self.isPIDTriggered = False
        self.isKeyTriggered = False
        self.logTrigger = ""
        self.calcHP = 0
        self.gearRatios = [2.92, 1.79, 1.14, 0.78, 0.58, 0.46, 0.0]
        self.gearFinal = 4.77
        self.coefficientOfDrag = 0.28
        self.frontalArea = 2.4
        self.tireCircumference = 0.639 * PI
        self.curbWeight = 1500.0 * KG_TO_N

        # Set up the activity logging
        self.logfile = self.filePath + "simos_hsl.log"
        f_handler = logging.FileHandler(self.logfile)

        if level is not None:
            loglevels = {
                "DEBUG": logging.DEBUG,
                "INFO": logging.INFO,
                "WARNING": logging.WARNING,
                "ERROR": logging.ERROR,
                "CRITICAL": logging.CRITICAL,
            }

            self.activityLogger.setLevel(level)

        else:
            self.activityLogger.setLevel(logging.INFO)

        if self.callbackFunction:
            self.callbackFunction(logger_status="Setting up logger")

        f_handler.setLevel(logging.DEBUG)
        self.activityLogger.addHandler(f_handler)
        self.activityLogger.debug("Current path arg: " + path)
        self.activityLogger.debug("Current filepath: " + self.filePath)
        self.activityLogger.debug("Activity log file: " + self.logfile)
        self.activityLogger.info("Activity log level: " + str(level))

        # open config file
        if self.mode == "22":
            self.logType = "22"
        elif self.mode == "22-MED":
            self.logType = "22_med"
            self.mode = "22"
        else:
            self.logType = "3E"
        configuration = {}
        fps = 0
        self.param_file = ""
        self.CONFIGFILE = self.filePath + "log_config.yaml"
        self.activityLogger.info("Checking for configuration file: " + self.CONFIGFILE)

        self.load_and_apply_config()

        # display current settings
        self.activityLogger.info("Logging mode:  " + self.mode)
        self.activityLogger.info("Data server: " + str(self.runServer))
        self.activityLogger.info("Interactive mode: " + str(self.interactive))
        self.activityLogger.info("Display Gauges: " + str(self.displayGauges))
        self.activityLogger.info("Log Trigger: " + str(self.logTrigger))

        if fps < 1:
            self.delay = 0.0
            self.activityLogger.info("Max frame rate: unlimited")
        else:
            self.delay = 1 / fps
            self.activityLogger.info("Max frame rate: " + str(fps))

        if self.mode == "22" and self.calcHP == 2:
            self.calcHP = 1
        if self.calcHP == 0:
            self.activityLogger.info("Calculate HP: None")
        elif self.calcHP == 1:
            self.activityLogger.info("Calculate HP: Reported TQ")
        elif self.calcHP == 2:
            self.activityLogger.info("Calculate HP: Accelerometer TQ")

        # open params file
        self.PARAMFILE = self.filePath + self.param_file
        self.activityLogger.info("Checking for parameter file: " + self.PARAMFILE)
        self.logParams = {}
        self.assignments = {}
        self.assignmentValues = {}
        self.csvHeader = "Time"
        self.csvDivider = "0"
        self.pid_counter = 0
        self.assignment_counter = 0

        self.load_and_initialize_parameters(self.param_file)

        self.activityLogger.info("PID count: " + str(self.pid_counter))
        self.activityLogger.info("Assignment count: " + str(self.assignment_counter))

        self.activityLogger.info("CSV Header for log files will be: " + self.csvHeader)

        # If we're only going to be writing to a single CSV file, create that file and put the header in it
        if self.singleCSV:
            self.filename = self.filePath + self.logPrefix + self.currentTime + ".csv"
            self.activityLogger.debug("Opening logfile at: " + self.filename)
            self.logFile = open(self.filename, "a")
            self.logFile.write(self.csvHeader + "\n")
            self.logFile.write(self.csvDivider + "\n")
            self.logFile.close()

        # start connection to ecu
        self.conn = connection_setup(
            self.interface, txid=0x7E0, rxid=0x7E8, interface_path=self.interfacePath
        )

    def startLogger(self):
        with Client(
            self.conn, request_timeout=2, config=configs.default_client_config
        ) as client:
            try:
                self.main(client=client)

            except exceptions.NegativeResponseException as e:
                self.activityLogger.critical(
                    'Server refused our request for service %s with code "%s" (0x%02x)'
                    % (
                        e.response.service.get_name(),
                        e.response.code_name,
                        e.response.code,
                    )
                )

            except exceptions.InvalidResponseException as e:
                self.activityLogger.critical(
                    "Server sent an invalid payload : %s" % e.response.original_payload
                )

            except exceptions.UnexpectedResponseException as e:
                self.activityLogger.critical(
                    "Server sent an invalid payload : %s" % e.response.original_payload
                )

            except exceptions.TimeoutException as e:
                self.activityLogger.critical(
                    "Timeout waiting for response on can: " + str(e)
                )

            except Exception as e:
                self.activityLogger.critical("Unhandled exception: " + str(e))
                raise

    def stop(self):
        self.activityLogger.critical("Received kill signal")
        if self.callbackFunction:
            self.callbackFunction(logger_status="Killing logger process")
        self.kill = True

    def main(self, client=None, callback=None):
        if client is not None:
            # setup parameter lists
            if self.mode != "22":
                hslPrefix = "3E32"
                if self.mode.upper() == "HSL":
                    hslPrefix = "3E02"
                self.memoryOffset = 0xB001E700
                paramList = ""
                for parameter in self.logParams:
                    if self.logParams[parameter]["Virtual"] == False:
                        paramList += "0"
                        paramList += str(self.logParams[parameter]["Length"])[0:1]
                        paramList += self.logParams[parameter]["Address"].lstrip("0x")
                paramList += "00"

                fullRequest = (
                    hslPrefix
                    + str(hex(self.memoryOffset)).lstrip("0x")
                    + str(hex(int(len(paramList) / 2))).lstrip("0x").zfill(4)
                    + paramList
                )
                self.activityLogger.debug("Sending 3E request to set up logging: ")
                self.activityLogger.debug(fullRequest)
                results = self.sendRaw(bytes.fromhex(fullRequest))
                if str(results.hex())[0:2].lower() == "7e":
                    self.activityLogger.debug("Created 3E list: " + str(results.hex()))
                else:
                    self.activityLogger.critical(
                        "Failed to create 3E list: " + str(results.hex())
                    )
                    exit()

        # start main polling thread
        try:
            self.activityLogger.debug("Starting the data polling thread")
            readData = threading.Thread(target=self.pollValues)
            readData.daemon = True
            readData.start()
        except (KeyboardInterrupt, SystemExit):
            sys.exit()
        except:
            self.activityLogger.critical("Error starting the data polling thread")

        # server mode: make datastream for GUI
        if self.runServer is True:
            try:
                self.activityLogger.debug("Starting data streaming thread")
                streamData = threading.Thread(target=self.streamData)
                streamData.daemon = True
                streamData.start()
            except (KeyboardInterrupt, SystemExit):
                sys.exit()
            except:
                self.activityLogger.critical("Error starting data streamer")

        # interactive mode: listen for enter key
        if self.interactive is True:
            try:
                self.activityLogger.debug("Starting the interactive thread")
                interactiveThread = threading.Thread(target=self.checkKeyboard)
                interactiveThread.daemon = True
                interactiveThread.start()
            except (KeyboardInterrupt, SystemExit):
                sys.exit()
            except:
                self.activityLogger.critical("Error starting the interactive thread")

        # main loop waiting for kill
        while self.kill == False:
            if self.displayGauges:
                self.drawGauges()

            if self.callbackFunction:
                self.callbackFunction(
                    logger_status="Logger Running", dataStream=self.dataStream
                )

            time.sleep(0.2)

        del logging.Logger.manager.loggerDict["SimosHSL"]

    def checkKeyboard(self):
        self.activityLogger.info(
            "Starting interactive thread [Enter: toggle logging, 'stop': will stop logger]"
        )

        while self.kill == False:
            log = input().lower()
            if log == "exit" or log == "stop":
                self.stop()
            else:
                self.activityLogger.debug("Input from user: " + log)
                self.isKeyTriggered = not self.isKeyTriggered

    def checkLogging(self):
        try:
            conditionsMet = False
            equationList = self.logTrigger.split("|")
            for currentEquation in equationList:
                if conditionsMet == False:
                    subConditionsMet = True
                    subEquationList = currentEquation.split("&")
                    for subEquation in subEquationList:
                        if subConditionsMet and len(subEquation) >= 3:
                            comparePos = subEquation.find(">")
                            if comparePos == -1:
                                comparePos = subEquation.find("=")
                            if comparePos == -1:
                                comparePos = subEquation.find("<")
                            assignment = subEquation[:comparePos].strip()
                            assignmentPID = self.assignments[assignment]
                            if assignmentPID is not None:
                                value = self.logParams[assignmentPID]["Value"]
                                compare = subEquation[comparePos]
                                compareValue = float(
                                    subEquation[comparePos + 1 :].strip()
                                )

                                if compare == ">":
                                    if value <= compareValue:
                                        subConditionsMet = False
                                elif compare == "<":
                                    if value >= compareValue:
                                        subConditionsMet = False
                                elif compare == "=":
                                    if abs(value - compareValue) > 0.15:
                                        subConditionsMet = False
                                else:
                                    subConditionsMet = True

                    if subConditionsMet:
                        conditionsMet = True

            self.isPIDTriggered = conditionsMet
        except:
            self.isPIDTriggered = False

        if self.isLogging:
            if self.isKeyTriggered == False and self.isPIDTriggered == False:
                self.isLogging = False
                self.logFile = None
                if self.displayGauges == False:
                    print("\033[F-Logging stopped-\033[0K")
        else:
            if self.isKeyTriggered or self.isPIDTriggered:
                self.isLogging = True
                if self.displayGauges == False:
                    print("\033[F-Logging started-\033[0K")

    def pollValues(self):
        self.activityLogger.info("Starting ECU poller")
        self.logFile = None

        nextFrameTime = time.time()
        while self.kill == False:
            try:
                currentTime = time.time()
                if currentTime > nextFrameTime:
                    nextFrameTime += self.delay
                    if nextFrameTime < currentTime:
                        nextFrameTime = currentTime

                    if self.mode == "22":
                        self.getParams22()
                    else:
                        self.getParamsHSL()

                    self.setAssignmentValues()
                    self.calcTQ()

                    if self.logFile:
                        self.logFile.flush()

                    self.checkLogging()
            except TimeoutException as e:
                self.activityLogger.error(
                    "Timeout waiting for response on can: " + str(e)
                )
                self.stop()

    def drawGauges(self):
        if self.dataRow is None:
            return

        header = self.csvHeader.split(",")
        values = self.dataRow.split(",")
        columnCount = int(shutil.get_terminal_size().columns / 15) - 1
        outString = "Status: "
        if self.isLogging:
            outString += "\033[1;31mLogging\033[1;37m"
        else:
            outString += "\033[1;32mPolling\033[1;37m"
        outString += "\033[0K\n"
        headerString = ""
        valuesString = ""
        seperationString = ""
        pos = 0
        row = 5
        for c in header:
            headerString += "{0:14s}".format(header[pos])[0:14] + "|"
            valuesString += "{0:14s}".format(values[pos])[0:14] + "|"
            seperationString += "---------------"
            pos += 1
            if pos % columnCount == 0:
                if pos == columnCount:
                    outString += seperationString + "\n"
                outString += (
                    headerString
                    + "\033[0K\n"
                    + valuesString
                    + "\033[0K\n"
                    + seperationString
                    + "\033[0K\n"
                )
                headerString = ""
                valuesString = ""
                seperationString = ""
                row += 3
                if row > shutil.get_terminal_size().lines - 3:
                    break
        if headerString != "":
            outString += (
                headerString
                + "\033[0K\n"
                + valuesString
                + "\033[0K\n"
                + seperationString
                + "\033[0K\n"
            )

        outString = "\033[H" + outString + "\033[0J"
        print(outString)

    def writeCSV(self, row):
        self.dataStream = self.dataStreamBuffer
        self.dataRow = row

        if self.isLogging:
            if self.logFile is None:
                if self.singleCSV:
                    self.filename = (
                        self.filePath + self.logPrefix + self.currentTime + ".csv"
                    )
                else:
                    self.filename = (
                        self.filePath
                        + self.logPrefix
                        + datetime.now().strftime("%Y%m%d-%H%M%S")
                        + ".csv"
                    )
                self.activityLogger.debug("Opening logfile at: " + self.filename)
                self.logFile = open(self.filename, "a")
                if not self.singleCSV:
                    self.logFile.write(self.csvHeader + "\n")
            self.logFile.write(row + "\n")
            self.activityLogger.debug(row)

    def getParamsHSL(self):
        loggerPrefix = "3e33"
        loggerSufix = ""
        if self.mode.upper() == "HSL":
            loggerPrefix = "3e04"
            loggerSufix = "FFFF"

        requestString = (
            loggerPrefix + str(hex(self.memoryOffset)).lstrip("0x") + loggerSufix
        )
        self.activityLogger.debug("Sending request for: " + requestString)
        results = self.sendRaw(bytes.fromhex(requestString))

        if results is not None:
            results = results.hex()
            self.activityLogger.debug(str(results))
        else:
            self.activityLogger.warning(str("No Response from ECU"))
            return

        # The data comes back as raw data, so we need the size of each variable and its
        #  factor so that we can actually parse it.  In here, we'll pull X bytes off the
        #  front of the result, process it, add it to the CSV row, and remove it from
        #  the result
        results = results[2:]
        row = self.clearDataStream()
        for parameter in self.logParams:
            if results == "":
                break

            if self.logParams[parameter]["Virtual"]:
                self.setPIDValue(parameter, self.logParams[parameter]["Value"])
            else:
                # get current data and remove it from the results
                val = results[: self.logParams[parameter]["Length"] * 2]
                results = results[self.logParams[parameter]["Length"] * 2 :]
                self.activityLogger.debug(str(parameter) + " raw from ecu: " + str(val))

                # get raw value
                rawval = int.from_bytes(
                    bytearray.fromhex(val),
                    "little",
                    signed=self.logParams[parameter]["Signed"],
                )
                if self.logParams[parameter]["Length"] == 4:
                    rawval = struct.unpack("f", int(rawval).to_bytes(4, "little"))[0]

                # set pid value
                self.activityLogger.debug(
                    str(parameter) + " pre-function: " + str(rawval)
                )
                self.setPIDValue(parameter, rawval)
                self.activityLogger.debug(
                    str(parameter) + " scaling applied: " + str(val)
                )

            # fill stream and log with current value
            self.dataStreamBuffer[parameter] = {
                "Name": self.logParams[parameter]["Name"],
                "Value": str(self.logParams[parameter]["Value"]),
            }
            row += "," + str(self.logParams[parameter]["Value"])
        self.writeCSV(row)

    def getParamAddress(self, address):
        for parameter in self.logParams:
            if address == self.logParams[parameter]["Address"].lstrip("0x"):
                return parameter

    def reqParams22(self, parameterString):
        self.activityLogger.debug("Sending: " + parameterString)
        results = (self.sendRaw(bytes.fromhex(parameterString))).hex()
        self.activityLogger.debug("Received: " + results)
        if results.startswith("62"):
            results = results[2:]
            while results != "":
                address = results[0:4]
                results = results[4:]
                pid = self.getParamAddress(address)
                if pid is not None:
                    if address == self.logParams[pid]["Address"].lstrip("0x"):
                        pidLength = self.logParams[pid]["Length"] * 2
                        val = results[0:pidLength]
                        results = results[pidLength:]
                        self.activityLogger.debug(
                            self.logParams[pid]["Name"] + " raw from ecu: " + str(val)
                        )
                        rawval = int.from_bytes(
                            bytearray.fromhex(val),
                            "big",
                            signed=self.logParams[pid]["Signed"],
                        )
                        self.activityLogger.debug(
                            self.logParams[pid]["Name"]
                            + " pre-function: "
                            + str(rawval)
                        )
                        self.setPIDValue(pid, rawval)
                        self.activityLogger.debug(
                            self.logParams[pid]["Name"]
                            + " scaling applied: "
                            + str(self.logParams[pid]["Value"])
                        )
                else:
                    results = ""

    # clear datastream and csv row
    def clearDataStream(self):
        self.dataStreamBuffer = {}
        self.dataStreamBuffer["Time"] = {
            "Name": "Time",
            "Value": str(datetime.now().time()),
        }
        self.dataStreamBuffer["isLogging"] = {
            "Name": "isLogging",
            "Value": str(self.isLogging),
        }
        return str(datetime.now().time())

    def getParams22(self):
        self.activityLogger.debug("Getting values via 0x22")

        parameterPosition = 0
        parameterString = "22"
        for parameter in self.logParams:
            if self.logParams[parameter]["Virtual"]:
                self.setPIDValue(parameter, self.logParams[parameter]["Value"])
            else:
                if parameterPosition < 8:
                    parameterString += self.logParams[parameter]["Address"].lstrip("0x")
                    parameterPosition += 1
                else:
                    self.reqParams22(parameterString)
                    parameterPosition = 1
                    parameterString = "22" + self.logParams[parameter][
                        "Address"
                    ].lstrip("0x")

        if parameterPosition > 0:
            self.reqParams22(parameterString)

        # fill stream and log with current values
        row = self.clearDataStream()
        for parameter in self.logParams:
            self.dataStreamBuffer[parameter] = {
                "Name": self.logParams[parameter]["Name"],
                "Value": str(self.logParams[parameter]["Value"]),
            }
            row += "," + str(self.logParams[parameter]["Value"])

        self.writeCSV(row)

    def calcTQ(self):
        if self.calcHP == 2:
            try:
                gearValue = int(self.logParams[self.assignments["gear"]]["Raw"])
                if gearValue in range(1, 8):
                    ms2Value = sqrt(
                        (self.logParams[self.assignments["accel_long"]]["Raw"] - 512.0)
                        / 32.0
                    )
                    ratioValue = sqrt(self.gearRatios[gearValue - 1] * self.gearFinal)
                    velValue = self.logParams[self.assignments["speed"]]["Raw"] / 100.0
                    rpmValue = self.logParams[self.assignments["rpm"]]["Raw"]
                    dragAirValue = (
                        velValue**3
                        * 0.00001564
                        * self.coefficientOfDrag
                        * self.frontalArea
                    )
                    dragRollValue = velValue * self.curbWeight * 0.00000464
                    dragValue = (dragAirValue + dragRollValue) / rpmValue * 7127.0
                    self.assignmentValues["tq"] = (
                        self.curbWeight
                        * ms2Value
                        / ratioValue
                        / self.tireCircumference
                        / TQ_CONSTANT
                    ) + dragValue
                    self.assignmentValues["hp"] = (
                        self.assignmentValues["tq"] * rpmValue / 7127.0
                    )
            except:
                self.assignmentValues["tq"] = 0.0
                self.assignmentValues["hp"] = 0.0
        elif self.calcHP == 1:
            try:
                if self.mode == "22":
                    self.assignmentValues["tq"] = (
                        self.logParams[self.assignments["tq_rep"]]["Raw"] / 10.0
                    )
                else:
                    self.assignmentValues["tq"] = (
                        self.logParams[self.assignments["tq_rep"]]["Raw"] / 32.0
                    )

                rpmValue = self.logParams[self.assignments["rpm"]]["Raw"]

                self.assignmentValues["hp"] = (
                    self.assignmentValues["tq"] * rpmValue / 7127.0
                )
            except:
                self.assignmentValues["tq"] = 0.0
                self.assignmentValues["hp"] = 0.0

    def setAssignmentValues(self):
        for assign in self.assignments:
            self.assignmentValues[assign] = self.logParams[self.assignments[assign]][
                "Value"
            ]

    def setPIDValue(self, parameter, raw):
        try:
            self.assignmentValues["x"] = raw
            self.logParams[parameter]["Raw"] = raw
            self.logParams[parameter]["Value"] = round(
                eval(self.logParams[parameter]["Equation"], self.assignmentValues), 2
            )
        except:
            self.logParams[parameter]["Value"] = 0.0

    # A function used to send raw data (so we can create the dynamic identifier etc), since udsoncan can't do it all
    def sendRaw(self, data):
        results = None

        while results is None:
            self.conn.send(data)
            results = self.conn.wait_frame(timeout=4, exception=True)
            if results is None:
                self.activityLogger.critical("No response from ECU")

        return results

    # Stream data over a socket connection.
    # Open the socket, and if it happens to disconnect or fail, open it again
    # This is used for the android app
    def streamData(self, callback=None):
        self.activityLogger.info("Starting data server thread")
        HOST = "0.0.0.0"  # Standard loopback interface address (localhost)
        PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

        while self.kill == False:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((HOST, PORT))
                    s.listen()
                    conn, addr = s.accept()
                    self.activityLogger.info(
                        "Server listening on " + str(HOST) + ":" + str(PORT)
                    )
                    with conn:
                        print("Connected by", addr)
                        conn.sendall(
                            b"HTTP/1.1 200 OK\n"
                            + b"Content-Type: stream\n"
                            + b"Access-Control-Allow-Origin: *\n"
                            + b"\n"
                        )
                        while self.kill == False:
                            json_data = json.dumps(self.dataStream) + "\n"
                            self.activityLogger.debug(
                                "Sending json to app: " + json_data
                            )
                            conn.sendall(json_data.encode())
                            time.sleep(0.1)
            except:
                self.activityLogger.info(
                    "Socket closed due to error or client disconnect"
                )
