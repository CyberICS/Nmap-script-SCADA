local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
This NSE script is used to send a FINS packet to a remote device. The script
will send a Controller Data Read Command and once a response is received, it
validates that it was a proper response to the command that was sent, and then
will parse out the data.
]]
---
-- @usage
-- nmap --script omron-info-details.nse -sU -p 9600 <host>
--
-- @output
-- 9600/tcp open  OMRON FINS
-- | omron-info:
-- |   Controller Model: CJ2M-CPU32          02.01
-- |   Controller Version: 02.01
-- |   For System Use:
-- |   Program Area Size: 20
-- |   IOM size: 23
-- |   No. DM Words: 32768
-- |   Timer/Counter: 8
-- |   Expansion DM Size: 1
-- |   No. of steps/transitions: 0
-- |   Kind of Memory Card: 0
-- |_  Memory Card Size: 0

-- @xmloutput
-- <elem key="Controller Model">CS1G_CPU44H         03.00</elem>
-- <elem key="Controller Version">03.00</elem>
-- <elem key="For System Use"></elem>
-- <elem key="Program Area Size">20</elem>
-- <elem key="IOM size">23</elem>
-- <elem key="No. DM Words">32768</elem>
-- <elem key="Timer/Counter">8</elem>
-- <elem key="Expansion DM Size">1</elem>
-- <elem key="No. of steps/transitions">0</elem>
-- <elem key="Kind of Memory Card">0</elem>
-- <elem key="Memory Card Size">0</elem>


author = "Stephen Hilt (Digital Bond) / Edit by CyberICS"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

--
-- Function to define the portrule as per nmap standards
--
--
portrule = shortport.version_port_or_service(9600, "fins", {"tcp", "udp"})

---
--  Function to set the nmap output for the host, if a valid OMRON FINS packet
--  is received then the output will show that the port is open instead of
--  <code>open|filtered</code>
--
-- @param host Host that was passed in via nmap
-- @param port port that FINS is running on (Default UDP/9600)
function set_nmap(host, port)

  --set port Open
  port.state = "open"
  -- set version name to OMRON FINS
  port.version.name = "fins"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")

end

local memcard = {
  [0] = "No Memory Card",
  [1] = "SPRAM",
  [2] = "EPROM",
  [3] = "EEPROM"
}

function memory_card(value)
  local mem_card = memcard[value] or "Unknown Memory Card Type"
  return mem_card
end
---
--  send_udp is a function that is used to run send the appropriate traffic to
--  the omron devices via UDP
--
-- @param socket Socket that is passed in from Action
function send_udp(socket)
  local controller_data_read = stdnse.fromhex( "800002000000006300ef050100")
  -- send Request Information Packet
  socket:send(controller_data_read)
  local rcvstatus, response = socket:receive()
  return response
end
---
--  send_tcp is a function that is used to run send the appropriate traffic to
--  the omron devices via TCP
--
-- @param socket Socket that is passed in from Action
function send_tcp(socket)
  -- this is the request address command
  local req_addr = stdnse.fromhex( "46494e530000000c000000000000000000000000")
  -- TCP requires a network address that is revived from the first request,
  -- The read controller data these two strings will be joined with the address
  local controller_data_read = stdnse.fromhex("46494e5300000015000000020000000080000200")
  local controller_data_read2 = stdnse.fromhex("000000ef050501")

  -- send Request Information Packet
  socket:send(req_addr)
  local rcvstatus, response = socket:receive()
  local header = string.byte(response, 1)
  if(header == 0x46) then
    local address = string.byte(response, 24)
    local controller_data = ("%s%c%s%c"):format(controller_data_read, address, controller_data_read2, 0x00)
    -- send the read controller data request
    socket:send(controller_data)
    local rcvstatus, response = socket:receive()
    return response
  end
  return "ERROR"
end

---
--  Action Function that is used to run the NSE. This function will send the initial query to the
--  host and port that were passed in via nmap. The initial response is parsed to determine if host
--  is a FINS supported device.
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host,port)

  -- create table for output
  local output = stdnse.output_table()
  -- create new socket
  local socket = nmap.new_socket()
  local catch = function()
    socket:close()
  end
  -- create new try
  local try = nmap.new_try(catch)
  -- connect to port on host
  try(socket:connect(host, port))
  -- init response var
  local response = ""
  -- set offset to 0, this will mean its UDP
  local offset = 0
  -- check to see if the protocol is TCP, if it is set offset to 16
  -- and perform the tcp_send function
  if (port.protocol == "tcp")then
    offset = 16
    response = send_tcp(socket)
    -- else its udp and call the send_udp function
  else
    response = send_udp(socket)
  end
  -- unpack the first byte for checking that it was a valid response
  local header = string.unpack("B", response, 1)
  if(header == 0xc0 or header == 0xc1 or header == 0x46) then
    set_nmap(host, port)
    local response_code = string.unpack("<I2", response, 13 + offset)
    -- test for a few of the error codes I saw when testing the script
    if(response_code == 2081) then
      output["Response Code"] = "Data cannot be changed (0x2108)"
    elseif(response_code == 290) then
      output["Response Code"] = "The mode is wrong (executing) (0x2201)"
      -- if a successful response code then
      -- elseif(response_code == 0) then
      -- parse information from response
    else
      if(response_code == 0) then
        output["Response Code"] = "Normal completion" 
      elseif(response_code == 1) then
        output["Response Code"] = "Service was interrupted"
      elseif(response_code == 101) then
        output["Response Code"] = "Local node not part of Network"
      elseif(response_code == 102) then
        output["Response Code"] = "Token time-out, node number to large"
      elseif(response_code == 103) then
        output["Response Code"] = "Number of transmit retries exceeded"
      elseif(response_code == 104) then
        output["Response Code"] = "Maximum number of frames exceeded" 
      elseif(response_code == 105) then
        output["Response Code"] = "Node number setting error (range)"
      elseif(response_code == 106) then
        output["Response Code"] = "Node number duplication error"
      elseif(response_code == 201) then
        output["Response Code"] = "Destination node not part of Network"
      elseif(response_code == 202) then
        output["Response Code"] = "No node with the specified node number"
      elseif(response_code == 203) then
        output["Response Code"] = "Third node not part of Network : Broadcasting was specified"
      elseif(response_code == 204) then
        output["Response Code"] = "Busy error, destination node busy"
      elseif(response_code == 205) then
        output["Response Code"] = "Response time-out"
      elseif(response_code == 301) then
        output["Response Code"] = "Error occurred : ERC indicator is lit"
      elseif(response_code == 302) then
        output["Response Code"] = "CPU error occurred in the PC at the destination node"
      elseif(response_code == 303) then
        output["Response Code"] = "A controller error has prevented a normal response"
      elseif(response_code == 304) then
        output["Response Code"] = "Node number setting error"
      elseif(response_code == 401) then
        output["Response Code"] = "An undefined command has been used"
      elseif(response_code == 402) then
        output["Response Code"] = "Cannot process command because the specified unit model or version is wrong"
      elseif(response_code == 501) then
        output["Response Code"] = "Destination node number is not set in the routing table"
      elseif(response_code == 501) then
        output["Response Code"] = "Destination node number is not set in the routing table"
      elseif(response_code == 501) then
        output["Response Code"] = "Destination node number is not set in the routing table"
      elseif(response_code == 501) then
        output["Response Code"] = "Destination node number is not set in the routing table"
      elseif(response_code == 501) then
        output["Response Code"] = "Destination node number is not set in the routing table"
      elseif(response_code == 501) then
        output["Response Code"] = "Destination node number is not set in the routing table"
      elseif(response_code == 0502) then
        output["Response Code"] = "Routing table isn't registered"
      elseif(response_code == 0503) then
        output["Response Code"] = "Routing table error"
      elseif(response_code == 0504) then
        output["Response Code"] = "Max relay nodes (2) was exceeded"
      elseif(response_code == 1001) then
        output["Response Code"] = "The command is longer than the max permissible length"
      elseif(response_code == 1002) then
        output["Response Code"] = "The command is shorter than the min permissible length"
      elseif(response_code == 1003) then
        output["Response Code"] = "The designated number of data items differs from the actual number"
      elseif(response_code == 1004) then
        output["Response Code"] = "An incorrect command format has been used"
      elseif(response_code == 1005) then
        output["Response Code"] = "An incorrect header has been used"
      elseif(response_code == 1101) then
        output["Response Code"] = "Memory area code invalid or DM is not available"
      elseif(response_code == 1102) then
        output["Response Code"] = "Access size is wrong in command"
      elseif(response_code == 1103) then
        output["Response Code"] = "First address in inaccessible area"
      elseif(response_code == 1104) then
        output["Response Code"] = "The end of specified word range exceeds acceptable range"
      elseif(response_code == 1106) then
        output["Response Code"] = "A non-existent program number"
      elseif(response_code == 1109) then
        output["Response Code"] = "The size of data items in command block are wrong"
      --elseif(response_code == 110A) then
      --  output["Response Code"] = "The IOM break function cannot be executed"
      --elseif(response_code == 110B) then
      --  output["Response Code"] = "The response block is longer than the max length"
      --elseif(response_code == 110C) then
      --  output["Response Code"] = "An incorrect parameter code has been specified"
      elseif(response_code == 2002) then
        output["Response Code"] = "The data is protected"
      elseif(response_code == 2003) then
        output["Response Code"] = "Registered table does not exist"
      elseif(response_code == 2004) then
        output["Response Code"] = "Search data does not exist"
      elseif(response_code == 2005) then
        output["Response Code"] = "Non-existent program number"
      elseif(response_code == 2006) then
        output["Response Code"] = "Non-existent file"
      elseif(response_code == 2007) then
        output["Response Code"] = "Verification error"
      elseif(response_code == 2101) then
        output["Response Code"] = "Specified area is read-only"
      elseif(response_code == 2102) then
        output["Response Code"] = "The data is protected"
      elseif(response_code == 2103) then
        output["Response Code"] = "Too many files open"
      elseif(response_code == 2105) then
        output["Response Code"] = "Non-existent program number"
      elseif(response_code == 2106) then
        output["Response Code"] = "Non-existent file"
      elseif(response_code == 2107) then
        output["Response Code"] = "File already exists"
      elseif(response_code == 2108) then
        output["Response Code"] = "Data cannot be changed"
      elseif(response_code == 2201) then
        output["Response Code"] = "The mode is wrong (executing)"
      elseif(response_code == 2202) then
        output["Response Code"] = "The mode is wrong (stopped)"
      elseif(response_code == 2203) then
        output["Response Code"] = "The PC is in the PROGRAM mode"
      elseif(response_code == 2204) then
        output["Response Code"] = "The PC is in the DEBUG mode"
      elseif(response_code == 2205) then
        output["Response Code"] = "The PC is in the MONITOR mode"
      elseif(response_code == 2206) then
        output["Response Code"] = "The PC is in the RUN mode"
      elseif(response_code == 2207) then
        output["Response Code"] = "The specified node is not the control node"
      elseif(response_code == 2208) then
        output["Response Code"] = "The mode is wrong and the step cannot be executed"
      elseif(response_code == 2301) then
        output["Response Code"] = "The file device does not exist where specified"
      elseif(response_code == 2302) then
        output["Response Code"] = "The specified memory does not exist"
      elseif(response_code == 2303) then
        output["Response Code"] = "No clock exists"
      elseif(response_code == 2401) then
        output["Response Code"] = "Data link table is incorrect"
      elseif(response_code == 2502) then
        output["Response Code"] = "Parity / checksum error occurred"
      elseif(response_code == 2503) then
        output["Response Code"] = "I/O setting error"
      elseif(response_code == 2504) then
        output["Response Code"] = "Too many I/O points"
      elseif(response_code == 2505) then
        output["Response Code"] = "CPU bus error"
      elseif(response_code == 2506) then
        output["Response Code"] = "I/O duplication error"
      elseif(response_code == 2507) then
        output["Response Code"] = "I/O bus error"
      elseif(response_code == 2509) then
        output["Response Code"] = "SYSMAC BUS/2 error"
      --elseif(response_code == 250A) then
      --  output["Response Code"] = "Special I/O Unit error"
      --elseif(response_code == 250D) then
      --  output["Response Code"] = "Duplication in SYSMAC BUS word allocation"
      --elseif(response_code == 250F) then
      --  output["Response Code"] = "A memory error has occurred"
      elseif(response_code == 2510) then
        output["Response Code"] = "Terminator not connected in SYSMAC BUS system"
      elseif(response_code == 2601) then
        output["Response Code"] = "The specified area is not protected"
      elseif(response_code == 2602) then
        output["Response Code"] = "An incorrect password has been specified"
      elseif(response_code == 2604) then
        output["Response Code"] = "The specified area is protected"
      elseif(response_code == 2605) then
        output["Response Code"] = "The service is being executed"
      elseif(response_code == 2606) then
        output["Response Code"] = "The service is not being executed"
      elseif(response_code == 2607) then
        output["Response Code"] = "Service cannot be execute from local node"
      elseif(response_code == 2608) then
        output["Response Code"] = "Service cannot be executed settings are incorrect"
      elseif(response_code == 2609) then
        output["Response Code"] = "Service cannot be executed incorrect settings in command data"
      --elseif(response_code == 260A) then
      --  output["Response Code"] = "The specified action has already been registered"
      --elseif(response_code == 260B) then
      --  output["Response Code"] = "Cannot clear error, error still exists"
      elseif(response_code == 3001) then
        output["Response Code"] = "The access right is held by another device"
      elseif(response_code == 4001) then
        output["Response Code"] = "Command aborted with ABORT command"
      end
      output["Controller Model"] = string.unpack("z", response,15 + offset)
      output["Controller Version"] = string.unpack("z", response, 35 + offset)
      output["For System Use"] = string.unpack("z", response, 55 + offset)
      local pos
      output["Program Area Size"], pos = string.unpack(">I2", response, 95 + offset)
      output["IOM size"], pos = string.unpack("B", response, pos)
      output["No. DM Words"], pos = string.unpack(">I2", response, pos)
      output["Timer/Counter"], pos = string.unpack("B", response, pos)
      output["Expansion DM Size"], pos = string.unpack("B", response, pos)
      output["No. of steps/transitions"], pos = string.unpack(">I2", response, pos)
      local mem_card_type
      mem_card_type, pos = string.unpack("B", response, pos)
      output["Kind of Memory Card"] = memory_card(mem_card_type)
      output["Memory Card Size"], pos = string.unpack(">I2", response, pos)
    end
    socket:close()
    return output

  else
    socket:close()
    return nil
  end

end
