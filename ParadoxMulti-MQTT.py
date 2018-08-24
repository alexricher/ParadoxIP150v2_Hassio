#encoding=utf-8

import hashlib
import socket
import time
import lib.client as mqtt
import sys
import array
import random
import configparser
import struct
import importlib
import serial
import logging
import re
import json
import socket
import select

Label_Regex = re.compile('[^a-zA-Z0-9\ \-]')

FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger()

# Alarm controls can be given in payload, e.g. Paradox/C/P1, payl = Disarm

# Do not edit these variables here, use the config.ini file instead.
Zone_Amount = 32
passw = "0000"
user = "1000"

SERIAL_PORT = "/dev/ttyS1"

MQTT_IP = "127.0.0.1"
MQTT_Port = 1883
MQTT_KeepAlive = 60  # Seconds
MQTT_Username = None
MQTT_Password = None

# Options are Arm, Disarm, Stay, Sleep (case sensitive!)
Topic_Debug = "Paradox/Debug"
Topic_Publish_Battery = "Paradox/Voltage"
Topic_Publish_Events = "Paradox/Events"
Topic_Publish_Status = "Paradox/Status"
Events_Payload_Numeric = False
Topic_Subscribe_Control = "Paradox/Control/" # e.g. To arm partition 1: Paradox/C/P1/Arm
Startup_Publish_All_Info = "True"
Startup_Update_All_Labels = "True"
Topic_Publish_Labels = "Paradox/Labels"
Topic_Publish_AppState = "Paradox/State"
Alarm_Model = "ParadoxMG5050"
Alarm_Registry_Map = "ParadoxMG5050"
Alarm_Event_Map = "ParadoxMG5050"
Socket_Address = "0.0.0.0"
Socket_Port = 2000

# Global variables
Alarm_Control_Action = 0
Alarm_Control_Partition = 0
Alarm_Control_NewState = ""
Output_FControl_Action = 0
Output_FControl_Number = 0
Output_FControl_NewState = ""
Output_PControl_Action = 0
Output_PControl_Number = 0
Output_PControl_NewState = ""
Zone_Control_Action = 0
Zone_Control_Number = 0
Zone_Control_NewState = ""

State_Machine = 0
Debug_Mode = 2
Poll_Speed = 1
Debug_Packets = False
Keep_Alive_Interval = 5
State_Machine_Exception_Exit = True

Alarm_Data = {'zone': [], 'partition': []}
myAlarm = None

def ConfigSectionMap(section):
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                logger.debug ("skip: %s" % option)
        except:
            logger.exception("exception on %s!" % option)
            dict1[option] = None
    return dict1


def on_connect(client, userdata, flags, rc):
    logger.info("Connected to MQTT broker with result code " + str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    # client.subscribe("$SYS/#")


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    global Alarm_Control_Partition
    global Alarm_Control_NewState
    global Alarm_Control_Action
    global Output_FControl_Number
    global Output_FControl_NewState
    global Output_FControl_Action
    global Output_PControl_Number
    global Output_PControl_NewState
    global Output_PControl_Action
    global Zone_Control_Number
    global Zone_Control_NewState
    global Zone_Control_Action
    global State_Machine
    global Debug_Packets

    valid_states = ['Arm', 'Disarm', 'Sleep', 'Stay']

    logger.debug("MQTT Message: " + msg.topic + " " + str(msg.payload))

    topic = msg.topic


    if Topic_Subscribe_Control in msg.topic:
        if "/Output/" in msg.topic:
            try:
                Output_FControl_Number = msg.topic.split("/")[-1]

                logger.debug("Output force control number: ", Output_FControl_Number)
                Output_FControl_NewState = msg.payload.strip()
                if len(Output_FControl_NewState) == 0:
                    logger.warning("No payload for output: e.g. On")
                    return

                logger.debug( "Output force control state: ", Output_FControl_NewState)
                client.publish(Topic_Publish_AppState,
                               "Output: Forcing PGM " + str(Output_FControl_Number) + " to state: " + Output_FControl_NewState, 0, True)
                Output_FControl_Action = 1
            except:
                logger.exception("MQTT message received with incorrect structure")

        elif "/Pulse/" in msg.topic:
            try:
                Output_PControl_Number = msg.topic.split("/")[-1]

                logger.debug("Output pulse control number: ", Output_PControl_Number)
                Output_PControl_NewState = msg.payload.strip()
                if len(Output_PControl_NewState) == 0:
                    logger.warning("No payload for output: e.g. On")
                    return
                
                logger.debug( "Output pulse control state: ", Output_PControl_NewState)
                client.publish(Topic_Publish_AppState,
                               "Output: Pulsing PGM " + str(Output_PControl_Number) + " to state: " + Output_PControl_NewState,
                               0, True)
                Output_PControl_Action = 1
            except:
                logger.exception("MQTT message received with incorrect structure")
        elif "/Partition/" in msg.topic:
            try:
                Alarm_Control_Partition = topic.split("/")[-1]
                logger.debug( "Alarm control partition: %s ", Alarm_Control_Partition)
                Alarm_Control_NewState = msg.payload.strip()
                if len(Alarm_Control_NewState) < 1:
                    logger.warning('No payload given for alarm control: e.g. Disarm')
                    return

                logger.debug( "Alarm control state: %s", Alarm_Control_NewState)
                client.publish(Topic_Publish_AppState,
                               "Alarm: Control partition " + str(Alarm_Control_Partition) + " to state: " + Alarm_Control_NewState,
                               0, True)
                Alarm_Control_Action = 1
            except:
                logger.exception("MQTT message received with incorrect structure")
        elif "/Zone/" in msg.topic:
            try:
                Zone_Control_Number = topic.split("/")[-1]
                logger.debug( "Alarm control zone: %s ", Zone_Control_Number)
                Zone_Control_NewState = msg.payload.strip()
                if len(Zone_Control_NewState) < 1:
                    logger.warning('No payload given for alarm control: e.g. Disarm')
                    return

                logger.debug( "Alarm control state: %s", Zone_Control_NewState)
                client.publish(Topic_Publish_AppState,
                               "Alarm: Control zone " + str(Zone_Control_Number) + " to state: " + Zone_Control_NewState,
                               0, True)
                Zone_Control_Action = 1
            except:
                logger.exception("MQTT message received with incorrect structure")

        elif msg.topic.split("/")[-1] == "State":
            if msg.payload.upper() == "DEBUGPACKETS":
                Debug_Packets = True
            elif msg.payload.upper() == "NODEBUGPACKETS":
                Debug_Packets = False
            elif msg.payload.upper() == "NORMAL" and State_Machine == 20:
                if myAlarm is not None:
                    myAlarm.stopSerialPassthrough()
                State_Machine = 0
                logger.info("Switching to Standard mode")
            elif msg.payload.upper() == "PASSTHROUGH":
                State_Machine = 20
                logger.info("Switching to Passthrough mode")
            elif msg.payload.upper() == "RESET":
                State_Machine = 0
                logger.info("Reseting Paradox Multi MQTT")
            else:
                logger.warning("Unknown new state: %s", msg.payload)

class CommSerial:
    comm = None
    
    def __init__(self, serialport, mqttc):
        self.serialport = serialport
        self.comm = None
        self.client = mqttc
        self.callbacks = dict()

    def connect(self, baud=9600, timeout=1):
        try:
            logger.info( "Opening Serial port: " + self.serialport)
            self.comm = serial.Serial()
            self.comm.baudrate = baud
            self.comm.port =  self.serialport
            self.comm.timeout = timeout
            self.comm.open()
            logger.info( "Serial port open!")
        except:
            return False

        return True

    def write(self, data):
        if Debug_Packets and logger.isEnabledFor(logging.DEBUG):
            if data is not None and len(data) > 0:
                self.dumpBuffer(data, direction="out")
        self.comm.write(data)
        
    def read(self, sz=37, timeout=5):        
        self.comm.timeout = timeout / 5.0

        data = ""
        tstart = time.time()
        read_sz = sz
        while time.time() < (tstart + timeout): 
            recv_data = self.comm.read(read_sz)
            
            if recv_data is None:
                continue

            data += recv_data
            
            if len(data) < sz:
                continue

            # We may have multiple packets, some corrupted
            # Must find the correct packets
            while not self.checksum(data) and len(data) >= 37:
                data = data[1:]
            
            # Message is invalid! Lets try to get the missing data
            if not self.checksum(data):
                # If data is waiting, get it, otherwise read 1 byte at a time
                if self.comm.in_waiting > 0:
                    read_sz = self.comm.in_waiting
                else:
                    read_sz = 1
                
                continue

            if Debug_Packets and logger.isEnabledFor(logging.DEBUG):
                self.dumpBuffer(data, direction="in")
            
            # If message is async, deliver through the callback
            for k in list(self.callbacks.keys()):
                if data.startswith(k):
                    self.callbacks[k](data)
                    data = data[37:] 
                    break
            else:
                return data
            
        return None


    def disconnect(self):
        self.comm.close()
        
    def flush(self):
        self.comm.flush()

    def getfd(self):
        return self.comm.fileno()

    def registerMessageCallback(self, mid, callback):
        s = ""
        for c in mid:
            s += " %02x" % ord(c)

        logger.debug("Register callback for message: %s" % s)
        self.callbacks[mid] = callback

    def checksum(self, data):
        c = 0
        
        if data is None:
            return False
        
        if len(data) < 37:
            return False

        for i in data[:36]:
            c += ord(i)

        r = (c % 256) == ord(data[36])
        return r

    def dumpBuffer(self, data, direction="in"):
        if data is not None and len(data) > 0:
            topic = "Packet"
            m = str(len(data))
            if direction == "in":
                m += " <- "
                topic = "IN_Packet"
            elif direction == "out":
                m += " -> "
                topic = "OUT_Packet"
            else:
                m += " "

            for c in data:
                m += " %02x" % ord(c)

            logger.debug(m)

            self.client.publish(Topic_Debug + "/" + topic, m, qos=2)

# To be implemented. Do dot have the hardware to proceed. 
class CommIP150:
    def connect():
        pass

    def write():
        pass

    def read():
        pass

    def disconnect():
        pass


class Paradox:
    loggedin = 0
    alarmName = None
    zoneTotal = 0
    zoneStatus = ['']
    zoneNames = ['']
    zonePartition = None
    partitionStatus = None
    partitionName = None
    Skip_Update_Labels = 0
    mode = 0

    def __init__(self, _transport, _encrypted=0, _retries=3, _alarmeventmap="ParadoxMG5050",
                 _alarmregmap="ParadoxMG5050"):
        self.comms = _transport  # instance variable unique to each instance
        self.retries = _retries
        self.encrypted = _encrypted
        self.alarmeventmap = _alarmeventmap
        self.alarmregmap = _alarmregmap
        self.mode = 0

        try:
            mod = __import__("ParadoxMap", fromlist=[self.alarmeventmap + "EventMap"])
            self.eventmap = getattr(mod, self.alarmeventmap + "EventMap")
        except Exception as e:
            logger.exception("Failed to load Event Map: ", repr(e))
            logger.info("Defaulting to MG5050 Event Map...")
            try:
                mod = __import__("ParadoxMap", fromlist=["ParadoxMG5050EventMap"])
                self.eventmap = getattr(mod, "ParadoxMG5050EventMap")
            except Exception as e:
                logger.exception( "Failed to load Event Map (exiting): ", repr(e))
                sys.exit()

        try:
            mod = __import__("ParadoxMap", fromlist=[self.alarmregmap + "Registers"])
            self.registermap = getattr(mod, self.alarmregmap + "Registers")
        except Exception as e:
            logger.exception( "Failed to load Register Map (defaulting to not update labels from alarm): ", repr(e))
            self.Skip_Update_Labels = 1
        
        self.comms.registerMessageCallback('\xe0', self.handleEvent)
        self.comms.registerMessageCallback('\xe2\x14', self.handleEvent)
        

    def skipLabelUpdate(self):
        return self.Skip_Update_Labels

    def saveState(self):
        self.eventmap.save()

    def loadState(self):
        logger.debug("Loading previous event states and labels from file")
        self.eventmap.load()

    def login(self, password, Debug_Mode=0): 
        logger.info("Connecting to Alarm System")
        message = '\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        message = self.format37ByteMessage(message)
        reply = self.readDataRaw(message, Debug_Mode)

        message = '\x50\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        message = self.format37ByteMessage(message)
        reply = self.readDataRaw(message, Debug_Mode)

        message = '\x5f\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        message = self.format37ByteMessage(message)
        reply = self.readDataRaw(message, Debug_Mode)

        message = reply
        message = self.format37ByteMessage(message)
        reply = self.readDataRaw( message, Debug_Mode)

        message = '\x50\x00\x1f\xe0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4f'
        message = self.format37ByteMessage(message)
        reply = self.readDataRaw(message, Debug_Mode)


        message = '\x50\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        message = self.format37ByteMessage(message)
        reply = self.readDataRaw(message, Debug_Mode)

        message = '\x50\x00\x0e\x52\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        message = self.format37ByteMessage(message)
        reply = self.readDataRaw(message, Debug_Mode)

        return True

    def format37ByteMessage(self, message):
        checksum = 0

        if len(message) % 37 != 0:
            for val in message:
                checksum += ord(val)

            while checksum > 255:
                checksum = checksum - (checksum / 256) * 256

            message += bytes(bytearray([checksum]))  # Add check to end of message

        return message

    def updateAllLabels(self, Startup_Publish_All_Info="True", Topic_Publish_Labels="True", Debug_Mode=0):
        Alarm_Data['labels'] = dict()

        for func in self.registermap.getsupportedItems():

            logger.debug("Reading from alarm: " + func)

            try:

                register_dict = getattr(self.registermap, "get" + func + "Register")()
                mapping_dict = getattr(self.eventmap, "set" + func)

                total = sum(1 for x in register_dict if isinstance(x, int))

                logger.debug("Amount of numeric items in dictionary to read: " + str(total))

                skip_next = 0
                last_index = False
                for x in range(1, total + 1):

                    message = register_dict[x]["Send"]
                    try:
                        next_message = register_dict[x + 1]["Send"]
                    except KeyError:
                        skip_next = True
                    
                    assert isinstance(message, str), "Message to be sent is not a string: %r" % message
                    message = message.ljust(36, '\x00')
                    
                    reply = self.readDataRaw(self.format37ByteMessage(message), Debug_Mode)
                    if skip_next:
                        skip_next = False
                        continue

                    start = reply.find('R')

                    if start == -1 or len(reply) < start + 19:
                        #logger.warning("Invalid message!")
                        continue
                    start += 4

                    finish = start + 16
                    label = reply[start:finish].strip()
                    mapping_dict(x, label)
                    
                    x += 1
                    start = finish 
                    finish = start + 16
                    label = reply[start :finish ].strip()
                    mapping_dict(x, label)

                    skip_next = True

                try:
                    completed_dict = getattr(self.eventmap, "getAll" + func)()
                    if Debug_Mode >= 1:
                        logger.info("Labels detected for " + func + ": " + str(completed_dict))
                    
                except Exception as e:
                    logger.exception( "Failed to load supported function's completed mappings after updating: " + repr(e))
                

                Alarm_Data['labels'][func] = completed_dict
                Alarm_Data[func.replace('Label', '')] = [None] * len(Alarm_Data['labels'][func])

                if Startup_Publish_All_Info == "True":
                    topic = func.split("Label")[0]
                    client.publish(Topic_Publish_Labels + "/" + topic[0].upper() + topic[1:] + "s",
                                   ';'.join('{}{}'.format(key, ":" + val) for key, val in list(completed_dict.items())))

            except Exception as e:
                logger.exception( "Failed to load supported function's mapping: " + repr(e))
        
        
        #Initialize Zone structure (if label is present)
        if 'zone' in Alarm_Data:
            for i in range(0, len(Alarm_Data['zone'])):
                Alarm_Data['zone'][i] = {'state': None, 'bypass': False}

        return

    def handleEvent(self, message, Events_Payload_Numeric=0, Debug_Mode=0,):
        reply = '.'

        if len(message) > 0:
            if message[0] == '\xe2' or message[0] == '\xe0':
                try:
                    event, subevent = self.eventmap.getEventDescription(ord(message[7]), ord(message[8]))
                    event = event.strip()
                    subevent = subevent.strip()

                    reply = json.dumps({"Event": event, "SubEvent":subevent})
                    logger.info(reply)
                    
                    client.publish(Topic_Publish_Events, reply, qos=0, retain=True)
                    if event.find("Zone ") == 0:
                        client.publish(Topic_Publish_Status + "/Zones/"+subevent.replace(' ','_').title(), event, qos=1, retain=True)

                    elif ord(message[7]) == 0x02:
                        se = ord(message[8])
                        if se in [2, 3, 4, 5, 6, 7, 13, 99]:
                            client.publish(Topic_Publish_Status + "/Partitions/All", subevent, qos=1, retain=True)
                            
                    elif ord(message[7]) != 0x03:
                        client.publish(Topic_Publish_Status + "/System", event + " -> " + subevent, qos=1, retain=True)

                except ValueError:
                    reply = "No register entry for Event: " + str(ord(message[7])) + ", Sub-Event: " + str(
                        ord(message[8]))

            else:
                reply = "Unknown event: " + " ".join(hex(ord(i)) for i in message)

        return reply

    def testForEvents(self, Events_Payload_Numeric=0, Debug_Mode=0, timeout=1):
    
        # Wait for events during a timeout
        message = self.comms.read(timeout=timeout)
        
        if message is None or len(message) < 9:
            return None

        return self.handleEvent(message, Events_Payload_Numeric, Debug_Mode)
         

    def readDataRaw(self, request='', Debug_Mode=2):

        tries = self.retries

        while tries > 0:
            try:
                if len(request) > 0:
                    self.comms.write(request)
                
                inc_data = self.comms.read()
                
                if inc_data is None:
                    if tries > 0:
                        logger.warning("Error reading data from panel, retrying again... (" + str(tries) + ")")
                        tries -= 1
                        time.sleep(0.5)
                        continue
                    elif tries == 0:
                        return ''
                    else:
                        break
                else:
                    return inc_data

            except Exception as e:
                logger.exception("Error reading from panel")
                sys.exit(-1)

    def readDataStruct37(self, inputData='', Debug_Mode=0):  # Sends data, read input data and return the Header and Message

        rawdata = self.readDataRaw(inputData, Debug_Mode)
        return rawdata

    def controlGenericOutput(self, mapping_dict, outputs, state, Debug_Mode=0):

      
        logger.info("Sending generic Output Control: Output: " + str(outputs) + ", State: " + state)

        for output in outputs:

            message = mapping_dict[output][state]

            if not isinstance(message, str):
                logger.warning("Generic Output: Message to be sent is not a string: %r" % message)
                continue

            message = message.ljust(36, '\x00')

            reply = self.readDataRaw(self.format37ByteMessage(message), Debug_Mode)

        return

    def controlPGM(self, pgm, state="OFF", Debug_Mode=0):

        if pgm.isdigit():
            pgm = [int(pgm)]
        if pgm == "ALL":
            pgm = list(range(1, 1 + len(Alarm_Data['labels']['outputLabel'])))
        else:
            try:
                pgm = json.loads(pgm)
                if not isinstance(pgm, list):
                    logger.warning("PGM must be str, int or list")
                    return
            except:
                logger.warning("Could not decode partition list")
                return

        if not state in ["ON", "1", "TRUE", "ENABLE", "OFF", "FALSE", "0", "DISABLE"]:
            logger.warning("PGM State is not given correctly: %r" % str(state))
            return

        for p in pgm:
            if not isinstance(p, int) or not (p >= 0 and p <= len(Alarm_Data['labels']['outputLabel'])):
                logger.warning("Problem with PGM number: %r" % str(p))
                return

        self.controlGenericOutput(self.registermap.getcontrolOutputRegister(), pgm, state, Debug_Mode)

        return

    def controlGenericAlarm(self, mapping_dict, partition, state, Debug_Mode):
        registers = mapping_dict

        logger.info("Sending generic Alarm Control: Partition: " + str(partition) + ", State: " + state)

        for p in partition:
            if p not in list(registers.keys()):
                logger.warning("Invalid partition: %d", p)
                continue
    
            message = registers[p][state]
            message = message.ljust(36, '\x00')
            reply = self.readDataRaw(self.format37ByteMessage(message), Debug_Mode)
            
        return

    def controlAlarm(self, partition="1", state="Disarm", Debug_Mode=0):
        
        partition = partition.upper()
        state = state.split(' ')[0].upper()

        if partition.isdigit():
            partition = [int(partition)]
        elif partition == "ALL":
            partition = list(range(1, 1 + len(Alarm_Data['labels']['partitionLabel'])))
        else:
            try:
                partition = json.loads(partition)
                if not isinstance(partition, list):
                    logger.warning("Partition must be str, int or list")
                    return
            except:
                logger.warning("Could not decode partition list")
                return
        
        for p in partition:
            if not p in list(self.registermap.getcontrolAlarmRegister().keys()):
                logger.warning("Unkown partition")
                return

            if not state in list(self.registermap.getcontrolAlarmRegister()[p].keys()):
                logger.warning("State is not given correctly: %r for partition %d" % (str(state), p))
                return

        self.controlGenericAlarm(self.registermap.getcontrolAlarmRegister(), partition, state, Debug_Mode)

        return


    def controlGenericZone(self, mapping_dict, zone, state, Debug_Mode):
        registers = mapping_dict

        logger.info("Sending generic Alarm Control: Zone: " + str(zone) + ", State: " + state)

        for z in zone:
            if z not in list(registers.keys()):
                logger.warning("Invalid Zone: %d", p)
                continue
    
            message = registers[z][state]
            message = message.ljust(36, '\x00')
            reply = self.readDataRaw(self.format37ByteMessage(message), Debug_Mode)
            
        return

    def controlZone(self, zone="1", state="CLEAR_BYPASS", Debug_Mode=0):
        
        zone = zone.upper()
        state = state.split(' ')[0].upper()

        if zone.isdigit():
            zone = [int(zone)]
        elif zone == "ALL":
            zone = list(range(1, len(Alarm_Data['labels']['zoneLabel'])))
        else:
            try:
                zone = json.loads(zone)
                if not isinstance(zone, list):
                    logger.warning("Zone must be str, int or list")
                    return
            except:
                logger.warning("Could not decode zone list")
                return
        
        for z in zone:
            if not z in list(self.registermap.getcontrolZoneRegister().keys()):
                logger.warning("Unkown Zone: %s" % z)
                return
            
            if not state in list(self.registermap.getcontrolZoneRegister()[z].keys()):
                logger.warning("State is not given correctly: %r for zone %d" % (str(state), z))
                return

        self.controlGenericZone(self.registermap.getcontrolZoneRegister(), zone, state, Debug_Mode)
        
        return

    def disconnect(self, Debug_Mode=0):
        message = "\x70\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x76"
        self.readDataRaw(self.format37ByteMessage(message))

        self.comms.disconnect()


    def keepAlive(self, Debug_Mode=0):
    
        global Alarm_Data

        aliveSeq = 0
    
        while aliveSeq < 3:
            message = "\x50\x00\x80"
            message += bytes(bytearray([aliveSeq]))
            message += "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


            data = self.readDataRaw(self.format37ByteMessage(message))
    
            if len(data) != 37 or ord(data[0]) != 0x52 or ord(data[3]) != aliveSeq:
                logger.warn("Invalid message")
                if data is not None and len(data) > 0:
                    m = str(len(data)) + " <- "                

                    for c in data:
                        m += " %02x" % ord(c)
                    logger.debug(m)
                return

            if aliveSeq == 0:
                Alarm_Data['date_time'] = {"year": ord(data[9])*100 + ord(data[10]),
                        "month": ord(data[11]),
                        "day": ord(data[12]),
                        "hours": ord(data[13]),
                        "minutes": ord(data[14])}
            
                voltage =   {'vdc': round(ord(data[15])*(20.3-1.4)/255.0+1.4,1) , 
                            'dc': round(ord(data[16])*22.8/255.0,1),
                            'battery': round(ord(data[17])*22.8/255.0,1)}

                if not 'voltage' in list(Alarm_Data.keys()) or \
                    abs(voltage['vdc'] - Alarm_Data['voltage']['vdc']) > 0.3 or abs(voltage['dc'] - Alarm_Data['voltage']['dc']) > 0.3 or abs(voltage['battery'] - Alarm_Data['voltage']['battery']) > 0.3:
                
                    client.publish(Topic_Publish_Battery, json.dumps(voltage), retain=True)
                    Alarm_Data['voltage'] = voltage
                
                b = 0
                bt = 0

                ## Ignore the last zone (99 = Any Zone)
                for i in range(0, len(Alarm_Data['zone']) - 1 ):

                    bt = i % 8
                    if i != 0 and bt == 0:
                        b += 1
                    
                    if Alarm_Data['labels']['zoneLabel'][i+1].startswith("Zone "):
                        continue
                    
                    state = (ord(data[19 + b]) >> bt) & 0x01
                    if state == 0:
                        state  = "Zone OK"
                    else:
                        state = "Zone open"
                    
                    oldState = Alarm_Data['zone'][i]['state']
                    if oldState is None or oldState != state and ('open' in oldState or 'OK' in oldState):
                        
                        Alarm_Data['zone'][i]['state'] = state
                        
                        client.publish(Topic_Publish_Status+"/Zones/"+Alarm_Data['labels']['zoneLabel'][i + 1].replace(' ','_').title(), state, retain=True)
                       
            elif aliveSeq == 1:
                changed = False

                for i in [0, 1]:
                    state = 0

                    # Arming
                    if ord(data[18 + i * 4]) == 0x01:
                        state = "Arm"
                    elif ord(data[17 + i * 4]) == 0x01:
                        state = "Arm"
                    else:
                        state  = "Disarm"

                    if Alarm_Data['partition'][i] != state:
                        client.publish(Topic_Publish_Status + "/Partitions/%d" % (i + 1), str(state), retain=True )
                        Alarm_Data['partition'][i] = state
                        changed = True
                
                if changed:
                    # See if all partitions are in the same state
                    states = dict()
                    for p in Alarm_Data['partition']:
                        states[p] = 1

                    if len(list(states.keys())) == 1:
                        client.publish(Topic_Publish_Status + "/Partitions/All", str(list(states.keys())[0]), retain=True )
                    else:
                        client.publish(Topic_Publish_Status + "/Partitions/All", "Mixed", retain=True )
            
            elif aliveSeq == 2:
                for i in range(0, len(Alarm_Data['zone']) - 1 ):
                    state = ord(data[4 + i])
                    changed = False

                    if state & 0x08 != 0:
                        if not Alarm_Data['zone'][i]['bypass']:
                            changed = True
                        Alarm_Data['zone'][i]['bypass'] = True
                    else:
                        if Alarm_Data['zone'][i]['bypass']:
                            changed = True
                        Alarm_Data['zone'][i]['bypass'] = False
                
                    if changed:
                        m = Alarm_Data['zone'][i]['state']
                        if Alarm_Data['zone'][i]['bypass']:
                            m += " (Bypass)"

                        client.publish(Topic_Publish_Status+"/Zones/"+Alarm_Data['labels']['zoneLabel'][i + 1].replace(' ','_').title(), m, retain=True)

            aliveSeq += 1
        
    def walker(self, ):
        self.zoneTotal = Zone_Amount

        logger.debug("Reading (" + str(Zone_Amount) + ") zone names...")

        for x in range(16, 65535, 32):
            message = "\xe2\x00"
            zone = x
            zone = list(struct.pack("H", zone))
            swop = zone[0]
            zone[0] = zone[1]
            zone[1] = swop

            temp = "".join(zone)
            message += temp

            message += "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            reply = self.readDataRaw(self.format37ByteMessage(message))
        return

    def startSerialPassthrough(self):

        self.comms.connect()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(0)
        self.comms.timeout = 1

        try:
            s.bind((Socket_Address, Socket_Port))
            s.listen(10)
            s.settimeout(5)
        except socket.error as msg:
            s.close()
            s = None
            logger.warning("Could not bind to socket %s:%s", Socket_Address, Socket_Port)
            return
        self.mode = 1

        while self.mode == 1:
            inputs = [self.comms.getfd()]

            logger.debug("Passthrough: Waiting for client")
            client = None

            while self.mode == 1:
                try:
                    client, addr = s.accept()
                    logger.debug("Passthrough: Client connected: %s", str(addr))
                    break
                except socket.timeout:
                    pass


            inputs.append(client)

            while self.mode == 1:
                readable, writable, exceptional = select.select(inputs, [] , inputs, 5)

                if inputs[0] in readable:
                    data = self.comms.read(37)
                    if data is None or len(data) == 0:
                        continue
                    direction = "<- "
                    client.send(data)
                else:
                    try:
                        data = client.recv(37)
                        if data is None or len(data) == 0:
                            break
                    except:
                        break
                    self.comms.write(data)
                    direction = "-> "
                    
                sys.stdout.write(direction)
                for c in data:
                    sys.stdout.write("%02x" % ord(c))

                sys.stdout.write("\n")

                for fex in exceptional:
                    if fex == inputs[0]:
                        logger.warning("Could not read from panel!")
                        return
                    else:
                        logger.warning("Client closed connection")
                        break;
            #if client is not None:
            #    client.close()
        self.comms.disconnect()

    def stopSerialPassthrough(self):
        self.mode = 0


if __name__ == '__main__':

    attempts = 3
    lastKeepAlive = 0

    while True:

        # -------------- Read Config file ----------------
        if State_Machine <= 0:

            logger.info("Reading config.ini file...")

            try:

                Config = configparser.ConfigParser()
                Config.read("config.ini")
                Alarm_Model = Config.get("Alarm", "Alarm_Model")
                Alarm_Registry_Map = Config.get("Alarm", "Alarm_Registry_Map")
                Alarm_Event_Map = Config.get("Alarm", "Alarm_Event_Map")
                Zone_Amount = int(Config.get("Alarm", "Zone_Amount"))
                if Zone_Amount % 2 != 0:
                    Zone_Amount += 1

                passw = Config.get ("SERIAL", "Password")
                SERIAL_PORT = Config.get("SERIAL", "SERIAL_PORT")

                MQTT_IP = Config.get("MQTT Broker", "IP")
                MQTT_Port = int(Config.get("MQTT Broker", "Port"))
                MQTT_KeepAlive = int(Config.get("MQTT Broker", "KeepAlive"))
                MQTT_Username = Config.get("MQTT Broker", "Username")
                MQTT_Password = Config.get("MQTT Broker", "Password")

                Topic_Publish_Events = Config.get("MQTT Topics", "Topic_Publish_Events")
                Events_Payload_Numeric = Config.get("MQTT Topics", "Events_Payload_Numeric")
                Topic_Subscribe_Control = Config.get("MQTT Topics", "Topic_Subscribe_Control")
                Startup_Publish_All_Info = Config.get("MQTT Topics", "Startup_Publish_All_Info")
                Topic_Publish_Labels = Config.get("MQTT Topics", "Topic_Publish_Labels")
                Topic_Publish_AppState = Config.get("MQTT Topics", "Topic_Publish_AppState")
                Startup_Update_All_Labels = Config.get("Application", "Startup_Update_All_Labels")
                Debug_Mode = int(Config.get("Application", "Debug_Mode"))

                if Debug_Mode == 1:
                    logger.setLevel(logging.INFO)
                elif Debug_Mode == 2:
                    logger.setLevel(logging.DEBUG)
                else: 
                    logger.setLevel(logging.WARN)
                logger.info("config.ini file read successfully")
                State_Machine += 1

            except Exception as e:
                logger.exception( "******************* Error reading config.ini file (will use defaults): " + repr(e))
                State_Machine = 1
                attempts = 3
        # -------------- MQTT ----------------
        elif State_Machine == 1:

            try:

                logger.info("Attempting connection to MQTT Broker: " + MQTT_IP + ":" + str(MQTT_Port))
                client = mqtt.Client()
                client.on_connect = on_connect
                client.on_message = on_message
                if MQTT_Username is not None:
                    client.username_pw_set(username=MQTT_Username, password=MQTT_Password)

                client.connect(MQTT_IP, MQTT_Port, MQTT_KeepAlive)

                client.loop_start()

                client.subscribe(Topic_Subscribe_Control + "#")

                logger.info("MQTT client subscribed to control messages on topic: " + Topic_Subscribe_Control + "#")

                client.publish(Topic_Publish_AppState,"State Machine 1, Connected to MQTT Broker",0,True)

                State_Machine += 1

            except Exception as e:

                logger.exception( "MQTT connection error (" + str(attempts) + ": " + repr(e))
                time.sleep(attempts * 2)
                attempts -= 1

                if attempts < 1:
                    logger.error("Error within State_Machine: " + str(State_Machine) + ": " + repr(e))
                    State_Machine -= 1
                    logger.debug("Going to State_Machine: " + str(State_Machine))
                    attempts = 3

        # -------------- Login to Module ----------------
        elif State_Machine == 2:

            try:
                client.publish(Topic_Publish_AppState, "State Machine 2, Connecting to Alarm...", 0, True)

                comms = CommSerial(SERIAL_PORT, client)
                if not comms.connect():
                    logger.critical("Error connecting to Alarm")
                    sys.exit(0)

                client.publish(Topic_Publish_AppState,
                               "State Machine 2, Connected to Alarm, unlocking...",
                               0, True)

                myAlarm = Paradox(comms, 0, 3, Alarm_Event_Map, Alarm_Registry_Map)

                if not myAlarm.login(passw, Debug_Mode):
                    logger.warning("Failed to login & unlock panel, check if another app is using the port. Retrying... ")
                    client.publish(Topic_Publish_AppState,
                                   "State Machine 2, Failed to login & unlock panel, check if another app is using the port. Retrying... ",
                                   0, True)
                    comms.close()
                    time.sleep(Poll_Speed * 20)
                else:
                    client.publish(Topic_Publish_AppState, "State Machine 2, Logged into panel successfully", 0, True)
                    State_Machine += 1

            except Exception as e:
                logger.exception("Error attempting connection to panel (" + str(attempts) + ": " + repr(e))
                client.publish(Topic_Publish_AppState,
                               "State Machine 2, Exception, retrying... (" + str(attempts) + ": " + repr(e),
                               0, True)
                time.sleep(Poll_Speed * 5)
                attempts -= 1

                if attempts < 1:
                    logger.error("Error within State_Machine: " + str(State_Machine) + ": " + repr(e))
                    client.publish(Topic_Publish_AppState, "State Machine 2, Error, moving to previous state", 0, True)
                    State_Machine -= 1
                    logger.error("Going to State_Machine: " + str(State_Machine))
                    attempts = 3
        # -------------- Reading Labels ----------------
        elif State_Machine == 3:

            try:

                if Startup_Update_All_Labels == "True" and myAlarm.skipLabelUpdate() == 0:

                    client.publish(Topic_Publish_AppState, "State Machine 3, Reading labels from alarm", 0, True)

                    logger.info("Updating all labels from alarm")
                    myAlarm.updateAllLabels(Startup_Publish_All_Info, Topic_Publish_Labels, Debug_Mode)

                    State_Machine += 1
                    logger.info("Listening for events...")
                    client.publish(Topic_Publish_AppState, "State Machine 4, Listening for events...", 0, True)
                else:
                    State_Machine += 1
                    logger.info("Listening for events...")
                    client.publish(Topic_Publish_AppState, "State Machine 4, Listening for events...", 0, True)

            except Exception as e:

                logger.exception( "Error reading labels: " + repr(e))
                client.publish(Topic_Publish_AppState, "State Machine 3, Exception: " + repr(e), 0, True)
                time.sleep(Poll_Speed * 5)
                attempts -= 1

                if attempts < 1:
                    logger.error("Error within State_Machine: " + str(State_Machine) + ": " + repr(e))
                    client.publish(Topic_Publish_AppState, "State Machine 3, Error, moving to previous state", 0, True)
                    State_Machine -= 1
                    logger.debug("Going to State_Machine: " + str(State_Machine))

            Alarm_Control_Action = 0
            attempts = 3

            # -------------- Checking Events & Actioning Controls ----------------
        elif State_Machine == 4:

            try:
                # Test for new events & publish to broker
                timeRemaining = time.time() - lastKeepAlive + Keep_Alive_Interval
                if lastKeepAlive > 0 and timeRemaining > 0:
                    myAlarm.testForEvents(Events_Payload_Numeric, Debug_Mode, timeout=timeRemaining)
                
                # Test for pending Zone Control
                if Zone_Control_Action == 1:
                    myAlarm.controlZone(Zone_Control_Number, Zone_Control_NewState, Debug_Mode)
                    Zone_Control_Action = 0
                    logger.info( "Listening for events...")
                    client.publish(Topic_Publish_AppState, "State Machine 4, Listening for events...", 0, True)

                # Test for pending Alarm Control
                if Alarm_Control_Action == 1:
                    myAlarm.controlAlarm(Alarm_Control_Partition, Alarm_Control_NewState, Debug_Mode)
                    Alarm_Control_Action = 0
                    logger.info( "Listening for events...")
                    client.publish(Topic_Publish_AppState, "State Machine 4, Listening for events...", 0, True)

                # Test for pending Force Output Control
                if Output_FControl_Action == 1:
                    myAlarm.controlPGM(Output_FControl_Number, Output_FControl_NewState.upper(), Debug_Mode)
                    Output_FControl_Action = 0
                    logger.info("Listening for events...")
                    client.publish(Topic_Publish_AppState, "State Machine 4, Listening for events...", 0, True)

                # Test for pending Pulse Output Control
                if Output_PControl_Action == 1:
                    myAlarm.controlPGM(Output_PControl_Number, Output_PControl_NewState.upper(), Debug_Mode)
                    time.sleep(0.5)
                    if Output_PControl_NewState.upper() in ["ON", "1", "TRUE", "ENABLE"]:
                        myAlarm.controlPGM(Output_PControl_Number, "OFF", Debug_Mode)
                    else:
                        myAlarm.controlPGM(Output_PControl_Number, "ON", Debug_Mode)

                    Output_PControl_Action = 0
                    logger.info("Listening for events...")
                    client.publish(Topic_Publish_AppState, "State Machine 4, Listening for events...", 0, True)
                
                if time.time() >= lastKeepAlive + Keep_Alive_Interval:
                    myAlarm.keepAlive(Debug_Mode)
                    lastKeepAlive = time.time()

            except Exception as e:

                logger.exception( "Error during normal poll: " + repr(e) + ", Attempt: " + str(attempts))
                client.publish(Topic_Publish_AppState, "State Machine 4, Exception: " + repr(e), 0, True)
                if State_Machine_Exception_Exit:
                    sys.exit(-1)

                time.sleep(Poll_Speed * 5)
                attempts -= 1

                if attempts < 1:
                    logger.error("Error within State_Machine: " + str(State_Machine) + ": " + repr(e))
                    State_Machine -= 1
                    client.publish(Topic_Publish_AppState, "State Machine 4, Error, moving to previous state", 0, True)
                    attempts = 3

        elif State_Machine == 20:
            myAlarm.disconnect()
            myAlarm.startSerialPassthrough()
            State_Machine = 1

        elif State_Machine == 10:
            time.sleep(3)

        else:
            State_Machine = 2


