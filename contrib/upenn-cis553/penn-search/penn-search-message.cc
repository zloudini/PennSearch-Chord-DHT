/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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

#include "ns3/penn-search-message.h"
#include "ns3/log.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("PennSearchMessage");
NS_OBJECT_ENSURE_REGISTERED (PennSearchMessage);

PennSearchMessage::PennSearchMessage ()
{
}

PennSearchMessage::~PennSearchMessage ()
{
}

PennSearchMessage::PennSearchMessage (PennSearchMessage::MessageType messageType, uint32_t transactionId)
{
  m_messageType = messageType;
  m_transactionId = transactionId;
}

TypeId 
PennSearchMessage::GetTypeId (void)
{
  static TypeId tid = TypeId ("PennSearchMessage")
    .SetParent<Header> ()
    .AddConstructor<PennSearchMessage> ()
  ;
  return tid;
}

TypeId
PennSearchMessage::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}


uint32_t
PennSearchMessage::GetSerializedSize (void) const
{
  // size of messageType, transaction id
  uint32_t size = sizeof (uint8_t) + sizeof (uint32_t);
  switch (m_messageType)
    {
      case PING_REQ:
        size += m_message.pingReq.GetSerializedSize ();
        break;
      case PING_RSP:
        size += m_message.pingRsp.GetSerializedSize ();
        break;
      case PUBLISH_REQ:
        size += m_message.publishReq.GetSerializedSize ();
        break;
      case PUBLISH_RSP:
        size += m_message.publishRsp.GetSerializedSize ();
        break;
      case REJOIN_REQ:
        size += m_message.rejoinReq.GetSerializedSize ();
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

void
PennSearchMessage::Print (std::ostream &os) const
{
  os << "\n****PennSearchMessage Dump****\n" ;
  os << "messageType: " << m_messageType << "\n";
  os << "transactionId: " << m_transactionId << "\n";
  os << "PAYLOAD:: \n";
  
  switch (m_messageType)
    {
      case PING_REQ:
        m_message.pingReq.Print (os);
        break;
      case PING_RSP:
        m_message.pingRsp.Print (os);
        break;
      case PUBLISH_REQ:
        m_message.publishReq.Print (os);
        break;
      case PUBLISH_RSP:
        m_message.publishRsp.Print (os);
        break;
      case REJOIN_REQ:
        m_message.rejoinReq.Print (os);
        break;
      default:
        break;  
    }
  os << "\n****END OF MESSAGE****\n";
}

void
PennSearchMessage::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  i.WriteU8 (m_messageType);
  i.WriteHtonU32 (m_transactionId);

  switch (m_messageType)
    {
      case PING_REQ:
        m_message.pingReq.Serialize (i);
        break;
      case PING_RSP:
        m_message.pingRsp.Serialize (i);
        break;
      case PUBLISH_REQ:
        m_message.publishReq.Serialize (i);
        break;
      case PUBLISH_RSP:
        m_message.publishRsp.Serialize (i);
        break;
      case REJOIN_REQ:
        m_message.rejoinReq.Serialize (i);
        break;
      default:
        NS_ASSERT (false);   
    }
}

uint32_t 
PennSearchMessage::Deserialize (Buffer::Iterator start)
{
  uint32_t size;
  Buffer::Iterator i = start;
  m_messageType = (MessageType) i.ReadU8 ();
  m_transactionId = i.ReadNtohU32 ();

  size = sizeof (uint8_t) + sizeof (uint32_t);

  switch (m_messageType)
    {
      case PING_REQ:
        size += m_message.pingReq.Deserialize (i);
        break;
      case PING_RSP:
        size += m_message.pingRsp.Deserialize (i);
        break;
      case PUBLISH_REQ:
        size += m_message.publishReq.Deserialize (i);
        break;
      case PUBLISH_RSP:
        size += m_message.publishRsp.Deserialize (i);
        break;
      case REJOIN_REQ:
        size += m_message.rejoinReq.Deserialize (i);
        break;
      default:
        NS_ASSERT (false);
    }
  return size;
}

/* PING_REQ */

uint32_t 
PennSearchMessage::PingReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
PennSearchMessage::PingReq::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
PennSearchMessage::PingReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
PennSearchMessage::PingReq::Deserialize (Buffer::Iterator &start)
{  
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingReq::GetSerializedSize ();
}

void
PennSearchMessage::SetPingReq (std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_REQ);
    }
  m_message.pingReq.pingMessage = pingMessage;
}

PennSearchMessage::PingReq
PennSearchMessage::GetPingReq ()
{
  return m_message.pingReq;
}

/* PING_RSP */

uint32_t 
PennSearchMessage::PingRsp::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t) + pingMessage.length();
  return size;
}

void
PennSearchMessage::PingRsp::Print (std::ostream &os) const
{
  os << "PingReq:: Message: " << pingMessage << "\n";
}

void
PennSearchMessage::PingRsp::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16 (pingMessage.length ());
  start.Write ((uint8_t *) (const_cast<char*> (pingMessage.c_str())), pingMessage.length());
}

uint32_t
PennSearchMessage::PingRsp::Deserialize (Buffer::Iterator &start)
{  
  uint16_t length = start.ReadU16 ();
  char* str = (char*) malloc (length);
  start.Read ((uint8_t*)str, length);
  pingMessage = std::string (str, length);
  free (str);
  return PingRsp::GetSerializedSize ();
}

void
PennSearchMessage::SetPingRsp (std::string pingMessage)
{
  if (m_messageType == 0)
    {
      m_messageType = PING_RSP;
    }
  else
    {
      NS_ASSERT (m_messageType == PING_RSP);
    }
  m_message.pingRsp.pingMessage = pingMessage;
}

PennSearchMessage::PingRsp
PennSearchMessage::GetPingRsp ()
{
  return m_message.pingRsp;
}


//
//
//

void
PennSearchMessage::SetMessageType (MessageType messageType)
{
  m_messageType = messageType;
}

PennSearchMessage::MessageType
PennSearchMessage::GetMessageType () const
{
  return m_messageType;
}

void
PennSearchMessage::SetTransactionId (uint32_t transactionId)
{
  m_transactionId = transactionId;
}

uint32_t 
PennSearchMessage::GetTransactionId (void) const
{
  return m_transactionId;
}

/** PUBLISH REQ **/

/**
 * Print publish request
 * \param os The output stream
 */
void
PennSearchMessage::PublishReq::Print (std::ostream &os) const
{
  os << "PublishReq:: Keyword: " << keyword << " DocID: " << docID << "\n";
}

/**
 * Get serialized size of publish request
 * \return The serialized size
 */
uint32_t
PennSearchMessage::PublishReq::GetSerializedSize (void) const
{
  uint32_t size;
  size = sizeof(uint16_t)  // length of keyword
    + keyword.size()  // keyword
    + sizeof(uint16_t)  // length of docID
    + docID.size();  // docID
  return size;
}

/**
 * Serialize publish request
 * \param start The buffer iterator
 */
void
PennSearchMessage::PublishReq::Serialize (Buffer::Iterator &start) const
{
  start.WriteU16(keyword.size()); // length of keyword
  start.Write((uint8_t*) keyword.data(), keyword.size()); // keyword
  start.WriteU16(docID.size()); // length of docID
  start.Write((uint8_t*) docID.data(), docID.size()); // docID
}

/**
 * Deserialize publish request
 * \param start The buffer iterator
 * \return The serialized size
 */
uint32_t
PennSearchMessage::PublishReq::Deserialize (Buffer::Iterator &start)
{
  uint16_t klen = start.ReadU16(); // length of keyword 
  keyword.resize(klen); // resize keyword
  start.Read ((uint8_t*)keyword.data(), klen); // keyword
  uint16_t dlen = start.ReadU16(); // length of docID
  docID.resize(dlen); // resize docID
  start.Read ((uint8_t*)docID.data(), dlen); // docID
  return GetSerializedSize();
}

/**
 * Set publish request
 * \param keyword The keyword
 * \param docID The docID
 */
void
PennSearchMessage::SetPublishReq (std::string keyword, std::string docID)
{
  if (m_messageType == 0)
    {
      m_messageType = PUBLISH_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == PUBLISH_REQ);
    }
  m_message.publishReq.keyword = keyword;
  m_message.publishReq.docID = docID;
}

PennSearchMessage::PublishReq
PennSearchMessage::GetPublishReq ()
{
  return m_message.publishReq;
}


/** PUBLISH RSP **/

/**
 * Print publish response
 * \param os The output stream
 */
void
PennSearchMessage::PublishRsp::Print (std::ostream &os) const
{
  os << "PublishRsp:: \n";
}

/**
 * Get serialized size of publish response
 * \return The serialized size
 */
uint32_t
PennSearchMessage::PublishRsp::GetSerializedSize (void) const
{
  return 0;
} 

/**
 * Serialize publish response
 * \param start The buffer iterator
 */
void
PennSearchMessage::PublishRsp::Serialize (Buffer::Iterator &start) const
{
}

/**
 * Deserialize publish response
 * \param start The buffer iterator
 * \return The serialized size
 */
uint32_t
PennSearchMessage::PublishRsp::Deserialize (Buffer::Iterator &start)
{
  return GetSerializedSize();
}

/**
 * Set publish response
 */
void
PennSearchMessage::SetPublishRsp ()
{
  if (m_messageType == 0)
  {
    m_messageType = PUBLISH_RSP;
  } 
  else {
    NS_ASSERT (m_messageType == PUBLISH_RSP);
  }
}

/**
 * Get publish response
 * \return The publish response
 */
PennSearchMessage::PublishRsp
PennSearchMessage::GetPublishRsp ()
{
  return m_message.publishRsp;
}

/*RejoinReq*/
uint32_t PennSearchMessage::RejoinReq::GetSerializedSize() const {
  return IPV4_ADDRESS_SIZE;
}

void PennSearchMessage::RejoinReq::Print(std::ostream &os) const {
  os << "Rejoin - requester = " << requester;
}

void PennSearchMessage::RejoinReq::Serialize(Buffer::Iterator &start) const {
  uint32_t ip = requester.Get();
  start.WriteHtonU32(ip);
}

uint32_t PennSearchMessage::RejoinReq::Deserialize(Buffer::Iterator &start) {
  requester = Ipv4Address(start.ReadNtohU32());
  return GetSerializedSize();
}

void
PennSearchMessage::SetRejoinReq (Ipv4Address requesterIp)
{
  if (m_messageType == 0)
    {
      m_messageType = REJOIN_REQ;
    }
  else
    {
      NS_ASSERT (m_messageType == REJOIN_REQ);
    }
  m_message.rejoinReq.requester = requesterIp;
}

PennSearchMessage::RejoinReq
PennSearchMessage::GetRejoinReq ()
{
  return m_message.rejoinReq;
}