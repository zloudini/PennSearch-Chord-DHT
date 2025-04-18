/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 University of Pennsylvania
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include "penn-search.h"
#include "ns3/grader-logs.h"
#include <sstream>
#include <fstream>

#include "ns3/random-variable-stream.h"
#include "ns3/inet-socket-address.h"

using namespace ns3;

TypeId
PennSearch::GetTypeId ()
{
  static TypeId tid = TypeId ("PennSearch")
    .SetParent<PennApplication> ()
    .AddConstructor<PennSearch> ()
    .AddAttribute ("AppPort",
                   "Listening port for Application",
                   UintegerValue (10000),
                   MakeUintegerAccessor (&PennSearch::m_appPort),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("ChordPort",
                   "Listening port for Application",
                   UintegerValue (10001),
                   MakeUintegerAccessor (&PennSearch::m_chordPort),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("PingTimeout",
                   "Timeout value for PING_REQ in milliseconds",
                   TimeValue (MilliSeconds (2000)),
                   MakeTimeAccessor (&PennSearch::m_pingTimeout),
                   MakeTimeChecker ())
    ;
  return tid;
}

PennSearch::PennSearch ()
  : m_auditPingsTimer (Timer::CANCEL_ON_DESTROY)
{
  m_chord = NULL;

  Ptr<UniformRandomVariable> m_uniformRandomVariable = CreateObject<UniformRandomVariable> ();
  m_currentTransactionId = m_uniformRandomVariable->GetValue (0x00000000, 0xFFFFFFFF);


}

PennSearch::~PennSearch ()
{

}

void
PennSearch::DoDispose ()
{
  StopApplication ();
  PennApplication::DoDispose ();
  
  // FOR TESTING
  // GraderLogs::HelloGrader(ReverseLookup(GetLocalAddress()), GetLocalAddress());
}

void
PennSearch::StartApplication (void)
{
  std::cout << "PennSearch::StartApplication()!!!!!" << std::endl;
  // Create and Configure PennChord
  ObjectFactory factory;

  factory.SetTypeId (PennChord::GetTypeId ());
  factory.Set ("AppPort", UintegerValue (m_chordPort));
  m_chord = factory.Create<PennChord> ();
  m_chord->SetNode (GetNode ());
  m_chord->SetNodeAddressMap (m_nodeAddressMap);
  m_chord->SetAddressNodeMap (m_addressNodeMap);
  m_chord->SetModuleName ("CHORD");
  std::string nodeId = GetNodeId ();
  m_chord->SetNodeId (nodeId);
  m_chord->SetLocalAddress (m_local);

  // Configure Callbacks with Chord
  m_chord->SetPingSuccessCallback (MakeCallback (&PennSearch::HandleChordPingSuccess, this)); 
  m_chord->SetPingFailureCallback (MakeCallback (&PennSearch::HandleChordPingFailure, this));
  m_chord->SetPingRecvCallback (MakeCallback (&PennSearch::HandleChordPingRecv, this)); 
  // Start Chord
  m_chord->SetStartTime (Simulator::Now());
  m_chord->Initialize();

  if (m_socket == 0)
    { 
      TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
      m_socket = Socket::CreateSocket (GetNode (), tid);
      InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny(), m_appPort);
      m_socket->Bind (local);
      m_socket->SetRecvCallback (MakeCallback (&PennSearch::RecvMessage, this));
    }  
  
  // Configure timers
  m_auditPingsTimer.SetFunction (&PennSearch::AuditPings, this);
  // Start timers
  m_auditPingsTimer.Schedule (m_pingTimeout);

  // set lookup success callback
  m_chord->SetLookupSuccessCallback(MakeCallback(&PennSearch::HandleChordLookupSuccess, this));
  m_chord->SetLookupFailureCallback(MakeCallback(&PennSearch::HandleChordLookupFailure, this));
}

void
PennSearch::StopApplication (void)
{
  //Stop chord
  m_chord->StopChord ();
  // Close socket
  if (m_socket)
    {
      m_socket->Close ();
      m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
      m_socket = 0;
    }

  // Cancel timers
  m_auditPingsTimer.Cancel ();
  m_pingTracker.clear ();
}

void
PennSearch::ProcessCommand (std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;
  if (command == "CHORD")
    { 
      // Send to Chord Sub-Layer
      tokens.erase (iterator);
      m_chord->ProcessCommand (tokens);
    } 
  if (command == "PING")
    {
      if (tokens.size() < 3)
        {
          ERROR_LOG ("Insufficient PING params..."); 
          return;
        }
      iterator++;
      if (*iterator != "*")
        {
          std::string nodeId = *iterator;
          iterator++;
          std::string pingMessage = *iterator;
          SendPing (nodeId, pingMessage);
        }
      else
        {
          iterator++;
          std::string pingMessage = *iterator;
          std::map<uint32_t, Ipv4Address>::iterator iter;
          for (iter = m_nodeAddressMap.begin () ; iter != m_nodeAddressMap.end (); iter++)  
            {
              std::ostringstream sin;
              uint32_t nodeNumber = iter->first;
              sin << nodeNumber;
              std::string nodeId = sin.str();    
              SendPing (nodeId, pingMessage);
            }
        }
    }
    else if (command == "PUBLISH") {
      std::string filename = tokens[1];
      PublishMetadataFile(filename); // publish metadata file to map: <transaction id, <keyword, docID>>
    }
}

void
PennSearch::SendPing (std::string nodeId, std::string pingMessage)
{
  // Send Ping Via-Chord layer 
  SEARCH_LOG ("Sending Ping via Chord Layer to node: " << nodeId << " Message: " << pingMessage);
  Ipv4Address destAddress = ResolveNodeIpAddress(nodeId);
  m_chord->SendPing (destAddress, pingMessage);
}

void
PennSearch::SendPennSearchPing (Ipv4Address destAddress, std::string pingMessage)
{
  if (destAddress != Ipv4Address::GetAny ())
    {
      uint32_t transactionId = GetNextTransactionId ();
      SEARCH_LOG ("Sending PING_REQ to Node: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << pingMessage << " transactionId: " << transactionId);
      Ptr<PingRequest> pingRequest = Create<PingRequest> (transactionId, Simulator::Now(), destAddress, pingMessage);
      // Add to ping-tracker
      m_pingTracker.insert (std::make_pair (transactionId, pingRequest));
      Ptr<Packet> packet = Create<Packet> ();
      PennSearchMessage message = PennSearchMessage (PennSearchMessage::PING_REQ, transactionId);
      message.SetPingReq (pingMessage);
      packet->AddHeader (message);
      m_socket->SendTo (packet, 0 , InetSocketAddress (destAddress, m_appPort));
    }


}

void
PennSearch::RecvMessage (Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom (sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4 ();
  uint16_t sourcePort = inetSocketAddr.GetPort ();
  PennSearchMessage message;
  packet->RemoveHeader (message);

  switch (message.GetMessageType ())
    {
      case PennSearchMessage::PING_REQ:
        ProcessPingReq (message, sourceAddress, sourcePort);
        break;
      case PennSearchMessage::PING_RSP:
        ProcessPingRsp (message, sourceAddress, sourcePort);
        break;
      case PennSearchMessage::PUBLISH_REQ:
        ProcessPublishReq (message, sourceAddress, sourcePort);
        break;
      case PennSearchMessage::PUBLISH_RSP:
        ProcessPublishRsp (message, sourceAddress, sourcePort);
        break;
      default:
        ERROR_LOG ("Unknown Message Type!");
        break;
    }
}

void
PennSearch::ProcessPingReq (PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{

    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup (sourceAddress);
    SEARCH_LOG ("Received PING_REQ, From Node: " << fromNode << ", Message: " << message.GetPingReq().pingMessage);
    // Send Ping Response
    PennSearchMessage resp = PennSearchMessage (PennSearchMessage::PING_RSP, message.GetTransactionId());
    resp.SetPingRsp (message.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet> ();
    packet->AddHeader (resp);
    m_socket->SendTo (packet, 0 , InetSocketAddress (sourceAddress, sourcePort));
}

void
PennSearch::ProcessPingRsp (PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // Remove from pingTracker
  std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
  iter = m_pingTracker.find (message.GetTransactionId ());
  if (iter != m_pingTracker.end ())
    {
      std::string fromNode = ReverseLookup (sourceAddress);
      SEARCH_LOG ("Received PING_RSP, From Node: " << fromNode << ", Message: " << message.GetPingRsp().pingMessage);
      m_pingTracker.erase (iter);
    }
  else
    {
      DEBUG_LOG ("Received invalid PING_RSP!");
    }
}

void
PennSearch::AuditPings ()
{
  std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
  for (iter = m_pingTracker.begin () ; iter != m_pingTracker.end();)
    {
      Ptr<PingRequest> pingRequest = iter->second;
      if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
        {
          DEBUG_LOG ("Ping expired. Message: " << pingRequest->GetPingMessage () << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds () << " CurrentTime: " << Simulator::Now().GetMilliSeconds ());
          // Remove stale entries
          m_pingTracker.erase (iter++);
        }
      else
        {
          ++iter;
        }
    }
  // Rechedule timer
  m_auditPingsTimer.Schedule (m_pingTimeout); 
}

uint32_t
PennSearch::GetNextTransactionId ()
{
  return m_currentTransactionId++;
}

// Handle Chord Callbacks

void
PennSearch::HandleChordPingFailure (Ipv4Address destAddress, std::string message)
{
  SEARCH_LOG ("Chord Ping Expired! Destination nodeId: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << message);
}

void
PennSearch::HandleChordPingSuccess (Ipv4Address destAddress, std::string message)
{
  SEARCH_LOG ("Chord Ping Success! Destination nodeId: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << message);
  // Send ping via search layer 
  SendPennSearchPing (destAddress, message);
}

void
PennSearch::HandleChordPingRecv (Ipv4Address destAddress, std::string message)
{
  SEARCH_LOG ("Chord Layer Received Ping! Source nodeId: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << message);
}

// Override PennLog

void
PennSearch::SetTrafficVerbose (bool on)
{ 
  m_chord->SetTrafficVerbose (on);
  g_trafficVerbose = on;
}

void
PennSearch::SetErrorVerbose (bool on)
{ 
  m_chord->SetErrorVerbose (on);
  g_errorVerbose = on;
}

void
PennSearch::SetDebugVerbose (bool on)
{
  m_chord->SetDebugVerbose (on);
  g_debugVerbose = on;
}

void
PennSearch::SetStatusVerbose (bool on)
{
  m_chord->SetStatusVerbose (on);
  g_statusVerbose = on;
}

void
PennSearch::SetChordVerbose (bool on)
{
  m_chord->SetChordVerbose (on);
  g_chordVerbose = on;
}

void
PennSearch::SetSearchVerbose (bool on)
{
  m_chord->SetSearchVerbose (on);
  g_searchVerbose = on;
}

/** PUBLISH AND LOOKUP **/

/**
 * Publish metadata file to map: <transaction id, <keyword, docID>>
 * \param filename The metadata file to publish
 */
void
PennSearch::PublishMetadataFile(std::string filename)
{
  // open file reading lines
  // example: Doc23 keywordA keywordB …

  // grab the line
  std::ifstream in(filename);

  if (!in.is_open()) {
    ERROR_LOG("Failed to open metadata file: " << filename);
    return;
  }

  // clear pending publishes to avoid duplicates for a new publish
  m_pendingPublishes.clear();

  std::string line;
  while (std::getline(in, line)) {
    // prepare for reading in file data
    istringstream iss(line);
    std::string docID;
    std::vector<std::string> keywords;

    // grab the docid
    iss >> docID;
    std::string kw;

    // grab all the keywords and lookup for each keyword and create a publish request
    while (iss >> kw) {
      uint32_t key = PennKeyHelper::CreateShaKey(kw);
      uint32_t tid = m_chord->Lookup(key);
      m_pendingPublishes[tid] = std::make_pair(kw, docID);
    }
  }
  in.close();
}

/**
 * Handle chord lookup success
 * \param tid The transaction id of the lookup
 * \param sourceAddress The source address of the lookup
 */
void
PennSearch::HandleChordLookupSuccess(uint32_t tid, Ipv4Address sourceAddress)
{
  // lookup success
  auto it = m_pendingPublishes.find(tid);
  if (it == m_pendingPublishes.end()) {
    DEBUG_LOG("Lookup success for unknown transaction ID");
    return;
  }
  // unpack publish request
  std::string keyword = it->second.first;
  std::string docID = it->second.second;
  SEARCH_LOG(GraderLogs::GetPublishLogStr(keyword, docID));

  // create publish request
  PennSearchMessage req = PennSearchMessage(PennSearchMessage::PUBLISH_REQ, tid);
  req.SetPublishReq(keyword, docID);

  // send publish response
  Ptr<Packet> packet = Create<Packet>();
  packet->AddHeader(req);
  m_socket->SendTo(packet, 0, InetSocketAddress(sourceAddress, m_appPort));

  // wait for publish response from node to erase from pending publishes
}

/**
 * Handle chord lookup failure
 * \param tid The transaction id of the lookup
 */
void
PennSearch::HandleChordLookupFailure(uint32_t tid)
{
  // lookup failure for unknown transaction ID
  auto it = m_pendingPublishes.find(tid);
  if (it == m_pendingPublishes.end()) {
    DEBUG_LOG("Lookup failure for unknown transaction ID");
  }
  else {
    m_pendingPublishes.erase(it); // remove from pending publishes after lookup failure
  }
}

/**
 * Process publish request
 * \param message The publish request message
 * \param sourceAddress The source address of the publish request
 * \param sourcePort The source port of the publish request
 */
void
PennSearch::ProcessPublishReq (PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // unpack publish request
  auto publish_req = message.GetPublishReq();
  std::string keyword = publish_req.keyword;
  std::string docID = publish_req.docID;
  uint32_t tid = message.GetTransactionId();

  // store in local inverted index
  m_invertedIndex[keyword].push_back(docID);

  // log store for grader
  SEARCH_LOG(GraderLogs::GetStoreLogStr(keyword, docID));

  // send back publish response
  PennSearchMessage resp = PennSearchMessage(PennSearchMessage::PUBLISH_RSP, tid);
  resp.SetPublishRsp(); // payload is empty because grader does not expect any data

  Ptr<Packet> packet = Create<Packet>();
  packet->AddHeader(resp);
  m_socket->SendTo(packet, 0, InetSocketAddress(sourceAddress, sourcePort));
}

/**
 * Process publish response
 * \param message The publish response message
 * \param sourceAddress The source address of the publish response
 */
void
PennSearch::ProcessPublishRsp (PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // unpack publish response
  uint32_t tid = message.GetTransactionId();
  auto it = m_pendingPublishes.find(tid);
  if (it != m_pendingPublishes.end()) {
    m_pendingPublishes.erase(it); // remove from pending publishes after receiving response
  }
}
