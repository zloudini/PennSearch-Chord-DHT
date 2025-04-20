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
#include <algorithm>

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

  m_chord->SetLookUpCallback (MakeCallback (&PennSearch::HandleLookupResult, this));
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

  // set lookup success and failure callbacks
  m_chord->SetLookupSuccessCallback(MakeCallback(&PennSearch::HandleChordLookupSuccess, this));
  m_chord->SetLookupFailureCallback(MakeCallback(&PennSearch::HandleChordLookupFailure, this));

  // leave callback
  m_chord->SetLeaveCallback(MakeCallback(&PennSearch::HandleLeave, this));
  m_chord->SetRejoinCallback(MakeCallback(&PennSearch::HandleRejoin, this));
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
    else if (command == "SEARCH") {
      if (tokens.size() < 3) {
        ERROR_LOG ("Insufficient SEARCH params...");
        return;
      }

      uint32_t targetNode = std::stoi(tokens[1]);
      Ipv4Address targetIp = ResolveNodeIpAddress(std::to_string(targetNode));
      std::vector<std::string> keywords(tokens.begin() + 2, tokens.end());

      if (keywords.size() == 0) {
        ERROR_LOG ("No keywords provided for search");
        return;
      }

      uint32_t transactionId = GetNextTransactionId ();
      PennSearchMessage message = PennSearchMessage (PennSearchMessage::SEARCH_REQ, transactionId);
      std::vector<std::string> returnDocs;
      message.SetSearchReq (m_local, keywords, returnDocs, 0);
      Ptr<Packet> packet = Create<Packet> ();
      packet->AddHeader (message);
      m_socket->SendTo (packet, 0 , InetSocketAddress (targetIp, m_appPort));
      
      SEARCH_LOG ("Sent SEARCH_REQ to Node: " << ReverseLookup(targetIp) << " IP: " << targetIp << " Keywords: ");
      for (const auto& keyword : keywords) {
        SEARCH_LOG (keyword << " ");
      }
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
      case PennSearchMessage::REJOIN_REQ:
        ProcessRejoin(message, sourceAddress, sourcePort);
        break;
      case PennSearchMessage::SEARCH_REQ:
        ProcessSearchReq(message, sourceAddress, sourcePort);
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

// lookup logic
void
PennSearch::Lookup(uint32_t hashToFind) 
{
  uint32_t transactionId = GetNextTransactionId();

  m_lookupTracker[transactionId] = hashToFind;

  m_chord->ChordLookup(transactionId, hashToFind);
}

void
PennSearch::HandleLookupResult(Ipv4Address owner, uint32_t transactionId)
{
  auto it = m_lookupTracker.find(transactionId);

  if (it != m_lookupTracker.end()) {
    uint32_t hashToFind = m_lookupTracker[transactionId];

    m_lookupTracker.erase(transactionId);

    ProcessLookupResult(owner, hashToFind);
  }
}

void 
PennSearch::ProcessLookupResult(Ipv4Address owner, uint32_t hashToFind)
{
  SEARCH_LOG("FOUND OWNER FOR HASH: " << PennKeyHelper::KeyToHexString(hashToFind) << " AT NODE: " << m_chord->ReverseLookup(owner) << " WITH HASH: " << PennKeyHelper::KeyToHexString(PennKeyHelper::CreateShaKey(owner)));
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
 * 1) Read file, build invertedLists: keyword → all docIDs
 * 2) For each unique keyword, fire exactly one Chord lookup and map tid → (keyword, all its docIDs)
 * \param filename The metadata file to publish
 */
void
PennSearch::PublishMetadataFile(std::string filepath)
{
  // we provide the filepath in the command line
  std::ifstream in(filepath);
  if (!in.is_open()) {
    ERROR_LOG("Failed to open metadata file: " << filepath);
    return;
  }

  // 1) Read file, build invertedLists: keyword → all docIDs
  std::map<std::string, std::vector<std::string>> invertedLists;
  std::string line;
  while (std::getline(in, line)) {
    std::istringstream iss(line);
    std::string docID;
    iss >> docID;
    std::string kw;
    while (iss >> kw) {
      // check if docID is already in vector for this keyword
      if (std::find(invertedLists[kw].begin(), invertedLists[kw].end(), docID) == invertedLists[kw].end()) {
        invertedLists[kw].push_back(docID);
      }
    }
  }
  in.close();

  // 2) For each unique keyword, fire exactly one Chord lookup and map tid → (keyword, all its docIDs)
  for (auto const& entry : invertedLists) {
    // get keyword and docIDs
    const std::string& keyword = entry.first;
    const auto& docIDs = entry.second;

    // lookup keyword
    uint32_t key = PennKeyHelper::CreateShaKey(keyword);

    
    // fire Chord lookup
    // map tid → (keyword, all its docIDs)
    uint32_t transactionId = GetNextTransactionId();
    // stash the whole vector of docIDs under this tid
    m_pendingPublishes[transactionId] = std::make_pair(keyword, docIDs);
    m_chord->ChordLookup(transactionId, key);

    // SEARCH_LOG("Sent with transactionId: " << transactionId << " looking for key: " << PennKeyHelper::KeyToHexString(key));

  }

  // DEBUG_LOG("Pending publishes: " << m_pendingPublishes.size());
}

/* SEARCH */
void
PennSearch::ProcessSearchReq (PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // unpack search request
  PennSearchMessage::SearchReq req = message.GetSearchReq();
  std::vector<std::string> keywords = req.keywords;
}

/**
 * Handle chord lookup success callback
 * Pull back out the (keyword,docID), log the "PUBLISH" event, then ship a PUBLISH_REQ to the node that owns that key.
 * \param tid The transaction id of the lookup
 * \param owner The owner of the publish keyword
 */
void
PennSearch::HandleChordLookupSuccess(uint32_t tid, Ipv4Address owner)
{
  // lookup success
  auto publishIt = m_pendingPublishes.find(tid);
  //SEARCH_LOG("SEARCHED FOR TRANSACTION ID: " << tid);
  if (publishIt != m_pendingPublishes.end()) {
    // unpack publish request
    std::string keyword = publishIt->second.first;
    std::vector<std::string> docIDs = publishIt->second.second;

    for (const auto& docID : docIDs) {
      // log publish for grader
      SEARCH_LOG(GraderLogs::GetPublishLogStr(keyword, docID));

      // create publish request and send PUBLISH_REQ to owner
      PennSearchMessage req = PennSearchMessage(PennSearchMessage::PUBLISH_REQ, tid);
      req.SetPublishReq(keyword, docID);
      Ptr<Packet> packet = Create<Packet>();
      packet->AddHeader(req);
      m_socket->SendTo(packet, 0, InetSocketAddress(owner, m_appPort));
      // SEARCH_LOG("Publishing on Node: " << m_chord->ReverseLookup(owner))
    }

    // clean up pending publishes
    m_pendingPublishes.erase(publishIt);
  }

  auto rejoinIt = m_pendingRejoin.find(tid);

  if (rejoinIt != m_pendingRejoin.end()) {

    // SEARCH_LOG ("OWNER = " << ReverseLookup(owner));
    if (owner != GetLocalAddress())
    {
      // unpack publish request
      std::string keyword = rejoinIt->second.first;
      std::vector<std::string> docIDs = rejoinIt->second.second;

      for (const auto& docID : docIDs) {
        // log publish for grader
        SEARCH_LOG(GraderLogs::GetPublishLogStr(keyword, docID));

        // create publish request and send PUBLISH_REQ to owner
        PennSearchMessage req = PennSearchMessage(PennSearchMessage::PUBLISH_REQ, tid);
        req.SetPublishReq(keyword, docID);
        Ptr<Packet> packet = Create<Packet>();
        packet->AddHeader(req);
        m_socket->SendTo(packet, 0, InetSocketAddress(owner, m_appPort));
        // SEARCH_LOG("Publishing on Node: " << m_chord->ReverseLookup(owner))
      }
    }
  }

  auto searchIt = m_pendingSearches.find(tid);
  if (searchIt != m_pendingSearches.end()) {
    // unpack search request
    Ipv4Address requester = searchIt->second.first;
    std::string keyword = searchIt->second.second;

    auto it = m_invertedIndex.find(keyword);
    if (it != m_invertedIndex.end()) {
      
    }
  }

  // SEARCH_LOG("unknown type of request");
}

/**
 * Handle chord lookup failure callback
 * \param tid The transaction id of the lookup
 */
void
PennSearch::HandleChordLookupFailure(uint32_t tid)
{
  // lookup failure for unknown transaction ID
  auto it = m_pendingPublishes.find(tid);
  if (it == m_pendingPublishes.end()) {
    // DEBUG_LOG("Lookup failure for unknown transaction ID");
    return;
  }
  else {
    m_pendingPublishes.erase(it); // remove from pending publishes after lookup failure
    // DEBUG_LOG("Lookup failure for transaction ID: " << tid);
  }
}

/**
 * Process publish request
 * Append docID into node's in-memory inverted index, log the "STORE" event, and ack the sender with a PUBLISH_RSP.
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
  // if the keyword is not in the inverted index, create a new vector
  if (m_invertedIndex.find(keyword) == m_invertedIndex.end()) {
    m_invertedIndex[keyword] = std::vector<std::string>();
  }
  // append the docID to the vector
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
 * When the original publisher sees the ack, it clears that tid from m_pendingPublishes
 * \param message The publish response message
 * \param sourceAddress The source address of the publish response
 */
void
PennSearch::ProcessPublishRsp (PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // we're handling the clean up in the process publish request for now
}

/* LEAVE LOGIC */
void
PennSearch::HandleLeave(Ipv4Address successorIp)
{
  // SEARCH_LOG("ENTERED HANDLE LEAVE IN PENNSEARCH");

  // SEARCH_LOG("LEAVE: Inverted index size = " << m_invertedIndex.size());

  // SEARCH_LOG("LEAVE: Successor IP is " << successorIp);

  
  for (const auto& entry : m_invertedIndex)
  {
    const std::string& keyword = entry.first;
    const std::vector<std::string>& docs = entry.second;

    for (const auto& doc : docs)
    {
      PennSearchMessage msg = PennSearchMessage(PennSearchMessage::PUBLISH_REQ, GetNextTransactionId());
      msg.SetPublishReq(keyword, doc);
      Ptr<Packet> pkt = Create<Packet>();
      pkt->AddHeader(msg);
      m_socket->SendTo(pkt, 0, InetSocketAddress(successorIp, m_appPort));

      SEARCH_LOG(GraderLogs::GetPublishLogStr(keyword, doc));

      // SEARCH_LOG("LEAVE: Sent tag (" << keyword << ", " << doc << ") to successor " << m_chord->ReverseLookup(successorIp));
      
    }
  }

  m_invertedIndex.clear();

}

void
PennSearch::HandleRejoin(Ipv4Address successorIp)
{
  // SEARCH_LOG("REJOIN: Requesting data from successor " << m_chord->ReverseLookup(successorIp));

  PennSearchMessage msg = PennSearchMessage(PennSearchMessage::REJOIN_REQ, GetNextTransactionId());
  msg.SetRejoinReq(GetLocalAddress());

  Ptr<Packet> pkt = Create<Packet>();
  pkt->AddHeader(msg);
  m_socket->SendTo(pkt, 0, InetSocketAddress(successorIp, m_appPort));
}

void 
PennSearch::ProcessRejoin(PennSearchMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  //Ipv4Address requester = sourceAddress;
  
  // SEARCH_LOG("REJOIN: Processing request from " << m_chord->ReverseLookup(requester));

  for (const auto& entry : m_invertedIndex)
  {
    const std::string& keyword = entry.first;
    const auto& docs = entry.second;

    // lookup keyword
    uint32_t key = PennKeyHelper::CreateShaKey(keyword);
    
    // fire Chord lookup
    // map tid → (keyword, all its docIDs)
    uint32_t transactionId = GetNextTransactionId();
    // stash the whole vector of docIDs under this tid
    m_pendingRejoin[transactionId] = std::make_pair(keyword, docs);
    m_chord->ChordLookup(transactionId, key);

    // SEARCH_LOG("REJOIN: Sent (" << keyword << ", " << ") to " << m_chord->ReverseLookup(requester));
  }
}