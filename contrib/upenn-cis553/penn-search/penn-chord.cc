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


#include "penn-chord.h"

#include "ns3/inet-socket-address.h"
#include "ns3/random-variable-stream.h"
#include "ns3/penn-key-helper.h"
#include "ns3/grader-logs.h"
#include <openssl/sha.h>

using namespace ns3;

TypeId
PennChord::GetTypeId ()
{
  static TypeId tid
      = TypeId ("PennChord")
            .SetParent<PennApplication> ()
            .AddConstructor<PennChord> ()
            .AddAttribute ("AppPort", "Listening port for Application", UintegerValue (10001),
                           MakeUintegerAccessor (&PennChord::m_appPort), MakeUintegerChecker<uint16_t> ())
            .AddAttribute ("PingTimeout", "Timeout value for PING_REQ in milliseconds", TimeValue (MilliSeconds (2000)),
                           MakeTimeAccessor (&PennChord::m_pingTimeout), MakeTimeChecker ())
  ;
  return tid;
}

PennChord::PennChord ()
    : m_auditPingsTimer (Timer::CANCEL_ON_DESTROY)
{
  Ptr<UniformRandomVariable> m_uniformRandomVariable = CreateObject<UniformRandomVariable> ();
  m_currentTransactionId = m_uniformRandomVariable->GetValue (0x00000000, 0xFFFFFFFF);

  // set finger table size and resize actual finger table
  m_fingerTableSize = 32;
  m_fingerTable.resize(m_fingerTableSize);

  // set nextFingerToFix to first entry and mark fingerTable as not initialzed yet
  m_nextFingerToFix = 0;
  m_fingerTableInitialized = false;

}

PennChord::~PennChord ()
{

}

void
PennChord::DoDispose ()
{
  StopApplication ();
  PennApplication::DoDispose ();
}


void
PennChord::StartApplication (void)
{
  std::cout << "PennChord::StartApplication()!!!!!" << std::endl;
  if (m_socket == 0)
    { 
      TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
      m_socket = Socket::CreateSocket (GetNode (), tid);
      InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny(), m_appPort);
      m_socket->Bind (local);
      m_socket->SetRecvCallback (MakeCallback (&PennChord::RecvMessage, this));
      // std::cout << "reset m_socekt to not null, now is " << m_socket << std::endl;
    }  
  
  m_nodeHash = PennKeyHelper::CreateShaKey(GetLocalAddress());
  m_predecessor = Ipv4Address::GetAny();
  m_successor = GetLocalAddress(); // self is its own successor

  // Configure timers
  m_auditPingsTimer.SetFunction (&PennChord::AuditPings, this);
  // Start timers
  m_auditPingsTimer.Schedule (m_pingTimeout);

  m_stabilizeTimer.SetFunction(&PennChord::Stabilize, this);
  m_stabilizeTimer.Schedule(Seconds(2));

  // configure and start finger table timer
  m_fixFingerTimer.SetFunction(&PennChord::FixFingerTable, this);
  m_fixFingerTimer.Schedule(Seconds(1));
}

void
PennChord::StopApplication (void)
{
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

  m_stabilizeTimer.Cancel ();

  m_fixFingerTimer.Cancel ();
}

void
PennChord::ProcessCommand (std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  // tokens for 0 PENNSEARCH CHORD JOIN 0 = [JOIN, 0]
  std::string command = *iterator;

  if (command == "JOIN"){
    iterator++;
    std::string landmarkNode = *iterator;

    //CHORD_LOG("Joining on node " << landmarkNode);

    std::string currentNode = GetNodeId();

    //CHORD_LOG("currentNode " << currentNode);

    if (currentNode == landmarkNode){
      //CHORD_LOG("Entering ChordCreate")
      ChordCreate();
    }
    else
    {
      //CHORD_LOG("Entering Join");
      Ipv4Address landmarkIp = ResolveNodeIpAddress(landmarkNode);
      Join(landmarkIp);
    }
  } else if (command == "RINGSTATE"){
    RingState();
  } else if (command == "LEAVE"){
    Leave();
  } 
}

void
PennChord::SendPing (Ipv4Address destAddress, std::string pingMessage)
{
  if (destAddress != Ipv4Address::GetAny ())
    {
      uint32_t transactionId = GetNextTransactionId ();
      CHORD_LOG ("Sending PING_REQ to Node: " << ReverseLookup(destAddress) << " IP: " << destAddress << " Message: " << pingMessage << " transactionId: " << transactionId);
      Ptr<PingRequest> pingRequest = Create<PingRequest> (transactionId, Simulator::Now(), destAddress, pingMessage);
      // Add to ping-tracker
      m_pingTracker.insert (std::make_pair (transactionId, pingRequest));
      Ptr<Packet> packet = Create<Packet> ();
      PennChordMessage message = PennChordMessage (PennChordMessage::PING_REQ, transactionId);
      message.SetPingReq (pingMessage);
      packet->AddHeader (message);
      m_socket->SendTo (packet, 0 , InetSocketAddress (destAddress, m_appPort));
      
    }
  else
    {
      // Report failure   
      m_pingFailureFn (destAddress, pingMessage);
    }
}

void
PennChord::RecvMessage (Ptr<Socket> socket)
{
  Address sourceAddr;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddr);
  InetSocketAddress inetSocketAddr = InetSocketAddress::ConvertFrom (sourceAddr);
  Ipv4Address sourceAddress = inetSocketAddr.GetIpv4 ();
  uint16_t sourcePort = inetSocketAddr.GetPort ();
  PennChordMessage message;
  packet->RemoveHeader (message);

  switch (message.GetMessageType ())
    {
      case PennChordMessage::PING_REQ:
        ProcessPingReq (message, sourceAddress, sourcePort);
        break;
      case PennChordMessage::PING_RSP:
        ProcessPingRsp (message, sourceAddress, sourcePort);
        break;
      case PennChordMessage::FIND_SUCCESSOR_REQ:
        ProcessFindSuccessorReq(message);
        break;
      case PennChordMessage::FIND_SUCCESSOR_RSP:
        ProcessFindSuccessorRsp(message);
        break;
      case PennChordMessage::STABILIZE_REQ:
        ProcessStabilizeReq(message);
        break;
      case PennChordMessage::STABILIZE_RSP:
        ProcessStabilizeRsp(message);
        break;
      case PennChordMessage::NOTIFY_PKT:
        ProcessNotifcationPkt(message);
        break;
      case PennChordMessage::RINGSTATE_PKT:
        ProcessRingStatePtk(message);
        break;
      case PennChordMessage::LEAVE_SUCCESSOR:
        ProcessLeaveSuccessor(message);
        break;
      case PennChordMessage::LEAVE_PREDECESSOR:
        ProcessLeavePredecessor(message);
        break;
      default:
        ERROR_LOG ("Unknown Message Type!");
        break;
    }
}

void
PennChord::ProcessPingReq (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{

    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup (sourceAddress);
    CHORD_LOG ("Received PING_REQ, From Node: " << fromNode << ", Message: " << message.GetPingReq().pingMessage);
    // Send Ping Response
    PennChordMessage resp = PennChordMessage (PennChordMessage::PING_RSP, message.GetTransactionId());
    resp.SetPingRsp (message.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet> ();
    packet->AddHeader (resp);
    m_socket->SendTo (packet, 0 , InetSocketAddress (sourceAddress, sourcePort));
    // Send indication to application layer
    m_pingRecvFn (sourceAddress, message.GetPingReq().pingMessage);
}

void
PennChord::ProcessPingRsp (PennChordMessage message, Ipv4Address sourceAddress, uint16_t sourcePort)
{
  // Remove from pingTracker
  std::map<uint32_t, Ptr<PingRequest> >::iterator iter;
  iter = m_pingTracker.find (message.GetTransactionId ());
  if (iter != m_pingTracker.end ())
    {
      std::string fromNode = ReverseLookup (sourceAddress);
      CHORD_LOG ("Received PING_RSP, From Node: " << fromNode << ", Message: " << message.GetPingRsp().pingMessage);
      m_pingTracker.erase (iter);
      // Send indication to application layer
      m_pingSuccessFn (sourceAddress, message.GetPingRsp().pingMessage);
    }
  else
    {
      DEBUG_LOG ("Received invalid PING_RSP!");
    }
}

void
PennChord::AuditPings ()
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
          // Send indication to application layer
          m_pingFailureFn (pingRequest->GetDestinationAddress(), pingRequest->GetPingMessage ());
        }
      else
        {
          ++iter;
        }
    }
  // Rechedule timer
  m_auditPingsTimer.Schedule (m_pingTimeout); 
}

void
PennChord::ChordCreate()
{
  Ipv4Address selfIp = GetLocalAddress();
  m_predecessor = Ipv4Address::GetAny();
  m_successor = selfIp;
  // might be unneccessary
  m_nodeHash = PennKeyHelper::CreateShaKey(selfIp);
  
  // initialize finger table on ChordCreate
  InitFingerTable();

  //("CREATE: Created Chord ring at node " << ReverseLookup(selfIp) << " With Successor: " << ReverseLookup(m_successor) << " | Hash: " << m_nodeHash);
}

void
PennChord::Join(Ipv4Address landmark)
{
  Ipv4Address selfIp = GetLocalAddress();
  uint32_t myId = PennKeyHelper::CreateShaKey(selfIp);

  // packet overhead
  uint32_t transactionId = GetNextTransactionId();
  PennChordMessage msg = PennChordMessage(PennChordMessage::FIND_SUCCESSOR_REQ, transactionId);
  msg.SetFindSuccessorReq(myId, selfIp);

  // send packet
  Ptr<Packet> pkt = Create<Packet>();
  pkt->AddHeader(msg);

  if (landmark == Ipv4Address::GetAny())
  {
    CHORD_LOG("Error: landmark is empty");
    return;
  }

  m_socket->SendTo(pkt, 0, InetSocketAddress(landmark, m_appPort));

  // TO-DO Might need to change parameters of call
  CHORD_LOG(GraderLogs::GetLookupIssueLogStr(myId, myId));

  //CHORD_LOG("JOIN: Sent FIND_SUCCESSOR_REQ to " << ReverseLookup(landmark) << " (IP: " << landmark << ") for id " << myId);
}

void
PennChord::ProcessFindSuccessorReq(PennChordMessage message)
{
  PennChordMessage::FindSuccessorReq req = message.GetFindSuccessorReq();
  uint32_t idToFind = req.idToFind;
  Ipv4Address requestorIp = req.requestorIp;

  // initialized in StartApplication
  uint32_t selfId = m_nodeHash;
  uint32_t successorId = PennKeyHelper::CreateShaKey(m_successor);

  bool replyTriggered = false;

  //REMOVE LAST OR STATEMENT WHEN FINGER TABLE COMPLETE
  if (IsInBetween(selfId, idToFind, successorId) || selfId == successorId || selfId == idToFind){
    replyTriggered = true;
  }

  if (replyTriggered) {
    //respond to requestor
    uint32_t transactionId = message.GetTransactionId();
    PennChordMessage resp = PennChordMessage(PennChordMessage::FIND_SUCCESSOR_RSP, transactionId);
    
    if (selfId == idToFind) {
      resp.SetFindSuccessorRsp(GetLocalAddress());
    } else {
      resp.SetFindSuccessorRsp(m_successor);
    }

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(resp);

    if (requestorIp == Ipv4Address::GetAny())
    {
      CHORD_LOG("Error: requestorIp is empty");
      return;
    }

    m_socket->SendTo(packet, 0, InetSocketAddress(requestorIp, m_appPort));

    // CHORD_LOG(GraderLogs::GetLookupResultLogStr(m_nodeHash, idToFind, ReverseLookup(requestorIp), idToFind));

    Ipv4Address succ = (selfId==idToFind ? GetLocalAddress() : m_successor);
    CHORD_LOG(GraderLogs::GetLookupResultLogStr(m_nodeHash, idToFind, ReverseLookup(succ), idToFind));

    //CHORD_LOG("FIND_SUCCESSOR_REQ for node " << ReverseLookup(requestorIp) << "... replying with successor " << ReverseLookup(m_successor));
  } 
  else
  {
    int idx = ClosestPrecedingFinger(idToFind);
    Ipv4Address nextHopIp = (idx >= 0) ? m_fingerTable[idx].finger_ip : m_successor;
    uint16_t nextHopPort = (idx >= 0 ? m_fingerTable[idx].finger_port : m_appPort);

    // scan finger table to find its ip+port
    // for (auto &e : m_fingerTable)
    // {
    //   if (e.finger_id == nextHopIp)
    //   {
    //     nextHopIp = e.finger_ip;
    //     nextHopPort = e.finger_port;
    //     break;
    //   }
    // }
    // fallback to successor if nothing matched
    if (nextHopIp == Ipv4Address::GetAny())
    {
      nextHopIp = m_successor;
      nextHopPort = m_appPort;
    }
    
    // forward to successor
    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(message);

    if (nextHopIp == Ipv4Address::GetAny())
    {
      CHORD_LOG("Error: nextHopIp is empty");
      return;
    }

    m_socket->SendTo(packet, 0, InetSocketAddress(nextHopIp, nextHopPort));

    // CHORD_LOG(GraderLogs::GetLookupForwardingLogStr(m_nodeHash, ReverseLookup(m_successor),  PennKeyHelper::CreateShaKey(m_successor), idToFind));
    auto hopHash = PennKeyHelper::CreateShaKey(nextHopIp);
    
    CHORD_LOG(GraderLogs::GetLookupForwardingLogStr(m_nodeHash, ReverseLookup(nextHopIp), hopHash, idToFind));

    //CHORD_LOG("FIND_SUCCESSOR_REQ for node " << ReverseLookup(requestorIp) << "... forwarding to " << ReverseLookup(m_successor));
  }

}

void
PennChord::ProcessFindSuccessorRsp(PennChordMessage message)
{
  PennChordMessage::FindSuccessorRsp rsp = message.GetFindSuccessorRsp();
  Ipv4Address successorIp = rsp.successorIp;

  m_successor = successorIp;
  if (!m_fingerTableInitialized) {
    InitFingerTable();
    m_fingerTableInitialized = true;
  }

  // get transaction id
  uint32_t tx = message.GetTransactionId();

  // check if transaction id is in pendingFingers
  auto txId = m_pendingFingers.find(tx);
  
  // transaction id found in pendingFingers
  if (txId != m_pendingFingers.end())
  {
    // get index of finger table entry in pendingFingers
    uint32_t idx = txId->second;

    // ensure index is within bounds
    if (idx >= m_fingerTableSize)
    {
      CHORD_LOG("Error: Index out of bounds");
      return;
    }
    

    // update finger table then erase transactionId from pendingFingers
    m_fingerTable[idx].finger_ip = m_successor;
    m_fingerTable[idx].finger_port = m_appPort;
    m_fingerTable[idx].finger_id = PennKeyHelper::CreateShaKey(successorIp);
    m_pendingFingers.erase(txId);
  }

  if (!m_lookupCallback.IsNull())
  {
    m_lookupCallback(successorIp, tx);
  }

  //CHORD_LOG("FIND_SUCCESSOR_RSP: Set successor for node: " << ReverseLookup(GetLocalAddress()) << " to node: " << ReverseLookup(m_successor));
}

void
PennChord::Stabilize()
{
  Ipv4Address sender = GetLocalAddress();
  Ipv4Address receiver = m_successor;

  // packet overhead
  uint32_t transactionId = GetNextTransactionId();
  PennChordMessage msg = PennChordMessage(PennChordMessage::STABILIZE_REQ, transactionId);
  msg.SetStabilizeReq(sender, receiver);

  // send packet
  Ptr<Packet> pkt = Create<Packet>();
  pkt->AddHeader(msg);

  if (receiver == Ipv4Address::GetAny())
  {
    CHORD_LOG("Error: receiver is empty");
    return;
  }
  m_socket->SendTo(pkt, 0, InetSocketAddress(receiver, m_appPort));

  // CHORD_LOG("Stabilize: Sent StabilizeReq to " << ReverseLookup(receiver) << " for node " << ReverseLookup(sender));

  m_stabilizeTimer.Schedule(Seconds(1));
}

bool PennChord::IsInBetween(uint32_t start, uint32_t target, uint32_t end) const
{
  if (start < end) {
    return (start < target && target < end);
  } else if (start > end) {
    return (target > start || target < end);
  } else if (start == end) {
    return true;
  } else {
    return false;
  }
}

void
PennChord::ProcessStabilizeReq(PennChordMessage message)
{
  PennChordMessage::StabilizeReq req = message.GetStabilizeReq();
  Ipv4Address senderIp = req.sender;
  Ipv4Address nodeToNotify = req.receiver;

  uint32_t n = PennKeyHelper::CreateShaKey(senderIp);
  // uint32_t successor = m_nodeHash;
  uint32_t successor = PennKeyHelper::CreateShaKey(m_successor);


  uint32_t x = PennKeyHelper::CreateShaKey(m_predecessor);

  // if (x in (n, successor))
  if(IsInBetween(n, x, successor) && x != PennKeyHelper::CreateShaKey(Ipv4Address::GetAny())){
    // if we enter here then the new node that is going to be notified in
    // successor.notify(n) since we set successor = x if we enter here, and
    // successor.predecessor is the node processing the Stabilization Request's
    // predecessor

    if (senderIp != GetLocalAddress() && m_predecessor != Ipv4Address::GetAny()){
      //create stabilizeRsp packet
      nodeToNotify = m_predecessor;
      Ipv4Address updated_successor = m_predecessor;
      // CHORD_LOG("Setting updated_successor = " << updated_successor);

      //packet overhead
      uint32_t transactionId = GetNextTransactionId();
      PennChordMessage msg = PennChordMessage(PennChordMessage::STABILIZE_RSP, transactionId);
      msg.SetStabilizeRsp(updated_successor);
      
      // send packet back to node that sent the request
      Ptr<Packet> pkt = Create<Packet>();
      pkt->AddHeader(msg);

      if (senderIp == Ipv4Address::GetAny())
      {
        CHORD_LOG("Error: senderIp is empty");
        return;
      }
      m_socket->SendTo(pkt, 0, InetSocketAddress(senderIp, m_appPort));

      //CHORD_LOG("Stabilize: Sent StabilizeRsp to " << ReverseLookup(senderIp) << " updating successor to: " << ReverseLookup(updated_successor));

    } else {
      m_successor = m_predecessor;
    }
  }

  //successor.notify(sender)
  // create notifyPkt
  Ipv4Address newPredecessor = senderIp;

  //packet overhead
  uint32_t transactionId = GetNextTransactionId();
  PennChordMessage msg = PennChordMessage(PennChordMessage::NOTIFY_PKT, transactionId);
  msg.SetNotifyPkt(newPredecessor);

  // send packet to node that needs to be notified
  Ptr<Packet> pkt = Create<Packet>();
  pkt->AddHeader(msg);

  if (nodeToNotify == Ipv4Address::GetAny())
  {
    CHORD_LOG("Error: nodeToNotify is empty");
    return;
  }
  m_socket->SendTo(pkt, 0, InetSocketAddress(nodeToNotify, m_appPort));

  // CHORD_LOG("Notify: Sent NotifyPacket to " << ReverseLookup(nodeToNotify) << " for node " << ReverseLookup(newPredecessor))
}

void
PennChord::ProcessStabilizeRsp(PennChordMessage message)
{
  PennChordMessage::StabilizeRsp msg = message.GetStabilizeRsp();

  Ipv4Address newSuccessor = msg.sender;

  // CHORD_LOG("StabilizeRsp: " << ReverseLookup(GetLocalAddress()) << " got STABILIZE_RSP to update successor to: " << newSuccessor);

  if (newSuccessor != Ipv4Address::GetAny() && (m_successor != newSuccessor || m_successor == Ipv4Address::GetAny())){

    // CHORD_LOG("StabilizeRsp: Updating successor from " << ReverseLookup(m_successor) << " to " << ReverseLookup(newSuccessor));
    
    m_successor = newSuccessor;
  }
}


void
PennChord::ProcessNotifcationPkt(PennChordMessage message)
{
  PennChordMessage::NotifyPkt notification = message.GetNotifyPkt();
  Ipv4Address updatePredecessor = notification.newPredecessor;
  uint32_t nPrime = PennKeyHelper::CreateShaKey(updatePredecessor);

  // CHORD_LOG("Notify Packet recieved from " << ReverseLookup(updatePredecessor));
  // CHORD_LOG("Current Pred = " << ReverseLookup(m_predecessor));

  if (m_predecessor == Ipv4Address::GetAny())
  {
    m_predecessor = updatePredecessor;
    // CHORD_LOG("Updated Predecessor for Node: " << ReverseLookup(GetLocalAddress()) << " set to: " << ReverseLookup(m_predecessor));
  }
  else
  {
    uint32_t currentPredHash = PennKeyHelper::CreateShaKey(m_predecessor);

    // CHORD_LOG("Self = " << ReverseLookup(GetLocalAddress())
    //        << " | Current Pred = " << ReverseLookup(m_predecessor)
    //        << " | Update Pred = " << ReverseLookup(updatePredecessor));

    // CHORD_LOG("Self = " << ReverseLookup(GetLocalAddress())
    //        << " | Current Successor = " << ReverseLookup(m_successor));

    if (IsInBetween(currentPredHash, nPrime, m_nodeHash) && currentPredHash != PennKeyHelper::CreateShaKey(updatePredecessor))
    {
      m_predecessor = updatePredecessor;
      // CHORD_LOG("Updated Predecessor for Node: " << ReverseLookup(GetLocalAddress()) << " set to: " << ReverseLookup(m_predecessor));
    }
  }
}

void
PennChord::RingState()
{
  Ipv4Address localIp = GetLocalAddress();
  std::string localId = ReverseLookup(localIp);
  uint32_t localHash = m_nodeHash;

  Ipv4Address predIp = m_predecessor;
  std::string predId = ReverseLookup(predIp);
  uint32_t predHash = PennKeyHelper::CreateShaKey(predIp);

  Ipv4Address succIp = m_successor;
  std::string succId = ReverseLookup(succIp);
  uint32_t succHash = PennKeyHelper::CreateShaKey(succIp);

  GraderLogs::RingState(localIp, localId, localHash, predIp, predId, predHash, succIp, succId, succHash);

  //packet overhead
  uint32_t transactionId = GetNextTransactionId();
  PennChordMessage msg = PennChordMessage(PennChordMessage::RINGSTATE_PKT, transactionId);
  // CHORD_LOG("Created msg with type = " << msg.GetMessageType());
  msg.SetRingstatePkt(localIp);

  // send packet to node that needs to be notified
  Ptr<Packet> pkt = Create<Packet>();
  pkt->AddHeader(msg);

  if (succIp == Ipv4Address::GetAny())
  {
    CHORD_LOG("Error: succIp is empty");
    return;
  }
  m_socket->SendTo(pkt, 0, InetSocketAddress(succIp, m_appPort));
  // CHORD_LOG("SENDING RINGSTATE TO: " << ReverseLookup(succIp));
}

void
PennChord::ProcessRingStatePtk(PennChordMessage message)
{

  PennChordMessage::RingstatePkt mssg = message.GetRingstatePkt();
  Ipv4Address ringStateEnd = mssg.endRingState;

  // CHORD_LOG("Received RingState packet at node " << ReverseLookup(GetLocalAddress()));

  

  if (ringStateEnd == GetLocalAddress())
  {
    GraderLogs::EndOfRingState();
  } else 
  {

    Ipv4Address localIp = GetLocalAddress();
    std::string localId = ReverseLookup(localIp);
    uint32_t localHash = m_nodeHash;

    Ipv4Address predIp = m_predecessor;
    std::string predId = ReverseLookup(predIp);
    uint32_t predHash = PennKeyHelper::CreateShaKey(predIp);

    Ipv4Address succIp = m_successor;
    std::string succId = ReverseLookup(succIp);
    uint32_t succHash = PennKeyHelper::CreateShaKey(succIp);

    GraderLogs::RingState(localIp, localId, localHash, predIp, predId, predHash, succIp, succId, succHash);
    //packet overhead
    uint32_t transactionId = GetNextTransactionId();
    PennChordMessage msg = PennChordMessage(PennChordMessage::RINGSTATE_PKT, transactionId);
    msg.SetRingstatePkt(ringStateEnd);

    Ptr<Packet> pkt = Create<Packet>();
    pkt->AddHeader(msg);

    if (succIp == Ipv4Address::GetAny())
    {
      CHORD_LOG("Error: succIp is empty");
      return;
    }
    m_socket->SendTo(pkt, 0, InetSocketAddress(succIp, m_appPort));
  }
}

void
PennChord::Leave()
{
  //CHORD_LOG(ReverseLookup(GetLocalAddress()) << " leaving the chord");

  //CHORD_LOG("Sending my current predecessor: " << m_predecessor << " to " << m_successor);
  // send packet to current successor, update the successor with this node's predecessor
  //packet overhead
  uint32_t transactionId = GetNextTransactionId();
  PennChordMessage msg = PennChordMessage(PennChordMessage::LEAVE_SUCCESSOR, transactionId);
  msg.SetLeaveSuccessor(GetLocalAddress(), m_predecessor);

  Ptr<Packet> pkt = Create<Packet>();
  pkt->AddHeader(msg);

  if (m_successor == Ipv4Address::GetAny())
  {
    CHORD_LOG("Error: m_successor is empty");
    return;
  }
  m_socket->SendTo(pkt, 0, InetSocketAddress(m_successor, m_appPort));

  //CHORD_LOG("Sending my current successor: " << m_successor << " to " << m_predecessor);
  // send pack to current predecessor, update the predecessor with this node's successor
  //packet overhead
  uint32_t transactionId2 = GetNextTransactionId();
  PennChordMessage msg2 = PennChordMessage(PennChordMessage::LEAVE_PREDECESSOR, transactionId2);
  msg2.SetLeavePredecessor(GetLocalAddress(), m_successor);

  Ptr<Packet> pkt2 = Create<Packet>();
  pkt2->AddHeader(msg2);
  m_socket->SendTo(pkt2, 0, InetSocketAddress(m_predecessor, m_appPort));

  m_predecessor = Ipv4Address::GetAny();
  m_successor = Ipv4Address::GetAny();
  
  // StopApplication();
}

void
PennChord::ProcessLeaveSuccessor(PennChordMessage message)
{
  PennChordMessage::LeaveSuccessor msg = message.GetLeaveSuccessor();
  Ipv4Address newPredecessor = msg.newPred;
  Ipv4Address sender = msg.sender;

  //CHORD_LOG("Received leave request from my predecessor " << ReverseLookup(sender) << " updating my predecessor to " << ReverseLookup(newPredecessor));

  if (sender == m_predecessor) {
    m_predecessor = newPredecessor;
  }

}

void
PennChord::ProcessLeavePredecessor(PennChordMessage message)
{
  PennChordMessage::LeavePredecessor msg = message.GetLeavePredecessor();
  Ipv4Address newSuccessor = msg.newSucc;
  Ipv4Address sender = msg.sender;

  //CHORD_LOG("Received leave request from my successor " << ReverseLookup(sender) << " updating my sucessor to " << ReverseLookup(newSuccessor));

  if (sender == m_successor) {
    m_successor = newSuccessor;
  }

}

/*Finger Table Methods*/

void
PennChord::InitFingerTable()
{
  // loop over all finger table entries
  for (uint32_t i = 0; i < m_fingerTableSize; i++) {
    // calculate start = id + 2^i mod 2^32
    uint32_t start = m_nodeHash + (1u << i);

    // store start of current index in finger table, initialize other fields
    m_fingerTable[i].start = start;
    m_fingerTable[i].finger_ip = Ipv4Address::GetAny();
    m_fingerTable[i].finger_id = 0;
    m_fingerTable[i].finger_port = 0;

    // find successor of start
    uint32_t tx = GetNextTransactionId();
    m_pendingFingers[tx] = i;
    PennChordMessage msg(PennChordMessage::FIND_SUCCESSOR_REQ, tx);
    msg.SetFindSuccessorReq(start, GetLocalAddress());
    Ptr<Packet> pkt = Create<Packet>();
    pkt->AddHeader(msg);

    if (m_successor == Ipv4Address::GetAny())
    {
      CHORD_LOG("Error: m_successor is empty");
      return;
    }
    m_socket->SendTo(pkt, 0, InetSocketAddress(m_successor, m_appPort));
    CHORD_LOG(GraderLogs::GetLookupIssueLogStr(m_nodeHash, start));
  }

  // reset nextFingerToFix and set finger table as initialized
  m_nextFingerToFix = 0;
  m_fingerTableInitialized = true;
}

void
PennChord::FixFingerTable()
{
  // if finger table is not initialized, reschedule and exit
  if (!m_fingerTableInitialized)
    {
      m_fixFingerTimer.Schedule(Seconds(1));
      return;
    }

  // get index of next finger to be fixed
  uint32_t nextFinger = m_nextFingerToFix;
  
  // look up successor of "start" of finger being fixed
  uint32_t target = m_fingerTable[nextFinger].start;
  uint32_t tx = GetNextTransactionId();

  // associate transaction id with finger table entry (to be picked up in ProcessFindSuccessorRsp)
  m_pendingFingers[tx] = nextFinger;

  // send req to find successor of start
  PennChordMessage msg(PennChordMessage::FIND_SUCCESSOR_REQ, tx);
  msg.SetFindSuccessorReq(target, GetLocalAddress());
  Ptr<Packet> pkt = Create<Packet>();
  pkt->AddHeader(msg);

  if (m_successor == Ipv4Address::GetAny())
  {
    CHORD_LOG("Error: m_successor is empty");
    return;
  }
  m_socket->SendTo(pkt, 0, InetSocketAddress(m_successor, m_appPort));

  // autograder log
  CHORD_LOG(GraderLogs::GetLookupIssueLogStr(m_nodeHash, target));

  // advance m_nextFingerToFix and schedule next finger fix
  m_nextFingerToFix = (nextFinger + 1) % m_fingerTableSize;
  m_fixFingerTimer.Schedule(Seconds(1));
}

int
PennChord::ClosestPrecedingFinger(uint32_t idToFind) const
{
  // loop over all finger table entries
  for (int i = int(m_fingerTableSize) - 1; i >= 0; i--)
    {
      // skip uninitialized entries
      if (m_fingerTable[i].finger_ip == Ipv4Address::GetAny())
        {
          continue;
        }

      // get finger id of ith finger
      uint32_t fid = m_fingerTable[i].finger_id;

      // check if finger is in between idToFind and the target
      if (IsInBetween(m_nodeHash, fid, idToFind))
        {
          return i;
        }
    }
  return -1;
}

void
PennChord::ChordLookup(uint32_t transactionId, uint32_t idToFind)
{
  PennChordMessage msg = PennChordMessage(PennChordMessage::FIND_SUCCESSOR_REQ, transactionId);

  msg.SetFindSuccessorReq(idToFind, GetLocalAddress());

  Ptr<Packet> pkt = Create<Packet>();
  pkt->AddHeader(msg);

  if (m_successor == Ipv4Address::GetAny())
  {
    CHORD_LOG("Error: m_successor is empty");
    return;
  }

  m_socket->SendTo(pkt, 0, InetSocketAddress(m_successor, m_appPort));

  CHORD_LOG(GraderLogs::GetLookupIssueLogStr(m_nodeHash, idToFind));
}

void 
PennChord::SetLookUpCallback(Callback<void, Ipv4Address, uint32_t> lookupCb)
{
  m_lookupCallback = lookupCb;
}

uint32_t
PennChord::GetNextTransactionId ()
{
  return m_currentTransactionId++;
}

void
PennChord::StopChord ()
{
  StopApplication ();
}

void
PennChord::SetPingSuccessCallback (Callback <void, Ipv4Address, std::string> pingSuccessFn)
{
  m_pingSuccessFn = pingSuccessFn;
}


void
PennChord::SetPingFailureCallback (Callback <void, Ipv4Address, std::string> pingFailureFn)
{
  m_pingFailureFn = pingFailureFn;
}

void
PennChord::SetPingRecvCallback (Callback <void, Ipv4Address, std::string> pingRecvFn)
{
  m_pingRecvFn = pingRecvFn;
}


