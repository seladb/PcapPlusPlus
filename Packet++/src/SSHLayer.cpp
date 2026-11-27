#define LOG_MODULE PacketLogModuleSSHLayer

#include "SSHLayer.h"
#include "GeneralUtils.h"
#include "Logger.h"
#include "EndianPortable.h"
#include <cstring>

namespace pcpp
{

	constexpr char SshLayerBaseString[] = "SSH Layer";

	const FieldDescriptor SSHLayer::SerializedFields::SSHMessageType{ Layer::SerializedFields::MaxID + 1,
		                                                              "sshMessageType" };

	const FieldDescriptor SSHIdentificationMessage::SerializedFields::IdentificationMessage{
		SSHLayer::SerializedFields::MaxID + 1, "identificationMessage"
	};

	const FieldDescriptor SSHHandshakeMessage::SerializedFields::SSHHandshakeMessageType{
		SSHLayer::SerializedFields::MaxID + 1, "sshHandshakeMessageType"
	};
	const FieldDescriptor SSHHandshakeMessage::SerializedFields::SSHHandshakeMessageTypeName{
		SSHLayer::SerializedFields::MaxID + 2, "sshHandshakeMessageTypeName"
	};
	const FieldDescriptor SSHHandshakeMessage::SerializedFields::PaddingLength{ SSHLayer::SerializedFields::MaxID + 3,
		                                                                        "paddingLength" };
	const FieldDescriptor SSHHandshakeMessage::SerializedFields::MessageLength{ SSHLayer::SerializedFields::MaxID + 4,
		                                                                        "messageLength" };

	const FieldDescriptor SSHKeyExchangeInitMessage::SerializedFields::Cookie{
		SSHHandshakeMessage::SerializedFields::MaxID + 1, "cookie"
	};
	const FieldDescriptor SSHKeyExchangeInitMessage::SerializedFields::KeyExchangeAlgorithms{
		SSHHandshakeMessage::SerializedFields::MaxID + 2, "keyExchangeAlgorithms"
	};
	const FieldDescriptor SSHKeyExchangeInitMessage::SerializedFields::ServerHostKeyAlgorithms{
		SSHHandshakeMessage::SerializedFields::MaxID + 3, "serverHostKeyAlgorithms"
	};
	const FieldDescriptor SSHKeyExchangeInitMessage::SerializedFields::EncryptionAlgorithmsClientToServer{
		SSHHandshakeMessage::SerializedFields::MaxID + 4, "encryptionAlgorithmsClientToServer"
	};
	const FieldDescriptor SSHKeyExchangeInitMessage::SerializedFields::EncryptionAlgorithmsServerToClient{
		SSHHandshakeMessage::SerializedFields::MaxID + 5, "encryptionAlgorithmsServerToClient"
	};

	const FieldDescriptor SSHKeyExchangeInitMessage::SerializedFields::MacAlgorithmsClientToServer{
		SSHHandshakeMessage::SerializedFields::MaxID + 6, "macAlgorithmsClientToServer"
	};
	const FieldDescriptor SSHKeyExchangeInitMessage::SerializedFields::MacAlgorithmsServerToClient{
		SSHHandshakeMessage::SerializedFields::MaxID + 7, "macAlgorithmsServerToClient"
	};
	const FieldDescriptor SSHKeyExchangeInitMessage::SerializedFields::CompressionAlgorithmsClientToServer{
		SSHHandshakeMessage::SerializedFields::MaxID + 8, "compressionAlgorithmsClientToServer"
	};
	const FieldDescriptor SSHKeyExchangeInitMessage::SerializedFields::CompressionAlgorithmsServerToClient{
		SSHHandshakeMessage::SerializedFields::MaxID + 9, "compressionAlgorithmsServerToClient"
	};
	const FieldDescriptor SSHKeyExchangeInitMessage::SerializedFields::LanguagesClientToServer{
		SSHHandshakeMessage::SerializedFields::MaxID + 10, "languagesClientToServer"
	};
	const FieldDescriptor SSHKeyExchangeInitMessage::SerializedFields::LanguagesServerToClient{
		SSHHandshakeMessage::SerializedFields::MaxID + 11, "languagesServerToClient"
	};
	const FieldDescriptor SSHKeyExchangeInitMessage::SerializedFields::FirstKexPacketFollows{
		SSHHandshakeMessage::SerializedFields::MaxID + 12, "firstKexPacketFollows"
	};

	// ----------------
	// SSHLayer methods
	// ----------------

	SSHLayer* SSHLayer::createSSHMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		SSHIdentificationMessage* sshIdnetMsg = SSHIdentificationMessage::tryParse(data, dataLen, prevLayer, packet);
		if (sshIdnetMsg != nullptr)
			return sshIdnetMsg;

		SSHHandshakeMessage* sshHandshakeMessage = SSHHandshakeMessage::tryParse(data, dataLen, prevLayer, packet);
		if (sshHandshakeMessage != nullptr)
			return sshHandshakeMessage;

		return new SSHEncryptedMessage(data, dataLen, prevLayer, packet);
	}

	void SSHLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		constructNextLayerFromFactory(SSHLayer::createSSHMessage, m_Data + headerLen, m_DataLen - headerLen);
	}

	// --------------------------------
	// SSHIdentificationMessage methods
	// --------------------------------

	SSHIdentificationMessage* SSHIdentificationMessage::tryParse(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                             Packet* packet)
	{
		// Payload must be at least as long as the string "SSH-"
		if (dataLen < 5)
			return nullptr;

		// Payload must begin with "SSH-" and end with "\n"
		if (data[0] == 0x53 && data[1] == 0x53 && data[2] == 0x48 && data[3] == 0x2d && data[dataLen - 1] == 0x0a)
			return new SSHIdentificationMessage(data, dataLen, prevLayer, packet);

		return nullptr;
	}

	std::string SSHIdentificationMessage::getIdentificationMessage() const
	{
		// check if message ends with "\r\n" or just with "\n"
		size_t identMsgEOL = (m_Data[m_DataLen - 2] == 0x0d ? 2 : 1);
		return std::string(reinterpret_cast<const char*>(m_Data), m_DataLen - identMsgEOL);
	}

	void SSHIdentificationMessage::serializeLayer(ObjectScope& serializer) const
	{
		serializer.writeField(SSHLayer::SerializedFields::SSHMessageType, "Identification");
		serializer.writeField(SerializedFields::IdentificationMessage, getIdentificationMessage());
	}

	std::string SSHIdentificationMessage::toString() const
	{
		return std::string(SshLayerBaseString) + ", " + "Identification message";
	}

	// ---------------------------
	// SSHHandshakeMessage methods
	// ---------------------------

	SSHHandshakeMessage::SSHHandshakeMessageType SSHHandshakeMessage::getMessageType() const
	{
		uint8_t messageCode = getMsgBaseHeader()->messageCode;
		if (messageCode == 20 || messageCode == 21 || (messageCode >= 30 && messageCode <= 34))
			return static_cast<SSHHandshakeMessage::SSHHandshakeMessageType>(messageCode);
		return SSHHandshakeMessage::SSH_MSG_UNKNOWN;
	}

	std::string SSHHandshakeMessage::getMessageTypeStr() const
	{
		switch (getMessageType())
		{
		case SSHHandshakeMessage::SSH_MSG_KEX_INIT:
			return "Key Exchange Init";
		case SSHHandshakeMessage::SSH_MSG_NEW_KEYS:
			return "New Keys";
		case SSHHandshakeMessage::SSH_MSG_KEX_DH_INIT:
			return "Diffie-Hellman Key Exchange Init";
		case SSHHandshakeMessage::SSH_MSG_KEX_DH_REPLY:
			return "Diffie-Hellman Key Exchange Reply";
		case SSHHandshakeMessage::SSH_MSG_KEX_DH_GEX_INIT:
			return "Diffie-Hellman Group Exchange Init";
		case SSHHandshakeMessage::SSH_MSG_KEX_DH_GEX_REPLY:
			return "Diffie-Hellman Group Exchange Reply";
		case SSHHandshakeMessage::SSH_MSG_KEX_DH_GEX_REQUEST:
			return "Diffie-Hellman Group Exchange Request";
		default:
			return "Unknown";
		}
	}

	uint8_t* SSHHandshakeMessage::getSSHHandshakeMessage() const
	{
		return m_Data + sizeof(SSHHandshakeMessage::ssh_message_base);
	}

	size_t SSHHandshakeMessage::getSSHHandshakeMessageLength() const
	{
		size_t length = static_cast<size_t>(be32toh(getMsgBaseHeader()->packetLength));
		// the padding length and the message type come from the packet, so the subtraction
		// underflows and reports a huge message when they do not fit inside the packet length
		size_t overhead = getMsgBaseHeader()->paddingLength + sizeof(uint8_t) * 2;
		if (overhead > length)
		{
			return 0;
		}

		return length - overhead;
	}

	size_t SSHHandshakeMessage::getPaddingLength() const
	{
		return getMsgBaseHeader()->paddingLength;
	}

	size_t SSHHandshakeMessage::getHeaderLen() const
	{
		return (size_t)be32toh(getMsgBaseHeader()->packetLength) + sizeof(uint32_t);
	}

	std::string SSHHandshakeMessage::toString() const
	{
		return std::string(SshLayerBaseString) + ", " + "Handshake Message: " + getMessageTypeStr();
	}

	void SSHHandshakeMessage::serializeLayer(ObjectScope& serializer) const
	{
		serializer.writeField(SSHLayer::SerializedFields::SSHMessageType, "Handshake");
		serializer.writeField(SerializedFields::SSHHandshakeMessageType, static_cast<int>(getMessageType()));
		serializer.writeField(SerializedFields::SSHHandshakeMessageTypeName, getMessageTypeStr());
		serializer.writeField(SerializedFields::PaddingLength, getPaddingLength());
		serializer.writeField(SerializedFields::MessageLength, getSSHHandshakeMessageLength());
	}

	SSHHandshakeMessage* SSHHandshakeMessage::tryParse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		if (dataLen < sizeof(SSHHandshakeMessage::ssh_message_base))
		{
			PCPP_LOG_DEBUG(
			    "Data length is smaller than the minimum size of an SSH handshake message. It's probably not an SSH handshake message");
			return nullptr;
		}

		SSHHandshakeMessage::ssh_message_base* msgBase = (SSHHandshakeMessage::ssh_message_base*)data;

		uint32_t msgLength = be32toh(msgBase->packetLength);
		if (msgLength + sizeof(uint32_t) > dataLen)
		{
			PCPP_LOG_DEBUG("Message size is larger than layer size. It's probably not an SSH handshake message");
			return nullptr;
		}

		if (msgBase->paddingLength > msgLength)
		{
			PCPP_LOG_DEBUG("Message padding is larger than message size. It's probably not an SSH handshake message");
			return nullptr;
		}

		if (msgBase->messageCode != 20 && msgBase->messageCode != 21 &&
		    (msgBase->messageCode < 30 || msgBase->messageCode > 49))
		{
			PCPP_LOG_DEBUG("Unknown message type " << (int)msgBase->messageCode
			                                       << ". It's probably not an SSH handshake message");
			return nullptr;
		}

		switch (msgBase->messageCode)
		{
		case SSHHandshakeMessage::SSH_MSG_KEX_INIT:
			return new SSHKeyExchangeInitMessage(data, dataLen, prevLayer, packet);
		default:
			return new SSHHandshakeMessage(data, dataLen, prevLayer, packet);
		}
	}

	// ---------------------------------
	// SSHKeyExchangeInitMessage methods
	// ---------------------------------

	SSHKeyExchangeInitMessage::SSHKeyExchangeInitMessage(uint8_t* data, size_t dataLen, Layer* prevLayer,
	                                                     Packet* packet)
	    : SSHHandshakeMessage(data, dataLen, prevLayer, packet), m_OffsetsInitialized(false)
	{
		memset(m_FieldOffsets, 0, 11 * sizeof(size_t));
	}

	void SSHKeyExchangeInitMessage::parseMessageAndInitOffsets() const
	{
		m_OffsetsInitialized = true;
		if (m_DataLen <= sizeof(ssh_message_base) + 16)
			return;

		size_t offset = sizeof(ssh_message_base) + 16;
		for (int i = 0; i < 10; i++)
		{
			if (offset + sizeof(uint32_t) >= m_DataLen)
				return;

			size_t fieldLength = static_cast<size_t>(be32toh(*reinterpret_cast<uint32_t*>(m_Data + offset)));
			if (offset + sizeof(uint32_t) + fieldLength > m_DataLen)
				return;

			PCPP_LOG_DEBUG("Field offset [" << i << "] = " << offset << ", length = " << fieldLength);
			m_FieldOffsets[i] = offset;
			offset += sizeof(uint32_t) + fieldLength;
		}

		if (offset >= m_DataLen)
			return;

		m_FieldOffsets[10] = offset;
	}

	std::string SSHKeyExchangeInitMessage::getFieldValue(int fieldOffsetIndex) const
	{
		if (!m_OffsetsInitialized)
			parseMessageAndInitOffsets();

		if (m_FieldOffsets[fieldOffsetIndex] == 0)
			return "";

		size_t fieldOffset = m_FieldOffsets[fieldOffsetIndex];
		uint32_t fieldLength = be32toh(*reinterpret_cast<uint32_t*>(m_Data + fieldOffset));
		return std::string(reinterpret_cast<const char*>(m_Data + fieldOffset + sizeof(uint32_t)), (size_t)fieldLength);
	}

	uint8_t* SSHKeyExchangeInitMessage::getCookie() const
	{
		if (m_DataLen < sizeof(ssh_message_base) + 16)
			return nullptr;

		return m_Data + sizeof(ssh_message_base);
	}

	std::string SSHKeyExchangeInitMessage::getCookieAsHexStream() const
	{
		uint8_t* cookie = getCookie();
		if (cookie == nullptr)
			return "";

		return byteArrayToHexString(cookie, 16);
	}

	bool SSHKeyExchangeInitMessage::isFirstKexPacketFollows() const
	{
		if (!m_OffsetsInitialized)
			parseMessageAndInitOffsets();

		if (m_FieldOffsets[10] == 0)
			return false;

		return m_Data[m_FieldOffsets[10]] != 0;
	}

	void SSHKeyExchangeInitMessage::serializeLayer(ObjectScope& serializer) const
	{
		SSHHandshakeMessage::serializeLayer(serializer);
		serializer.writeField(SerializedFields::Cookie, getCookieAsHexStream());
		serializer.writeField(SerializedFields::KeyExchangeAlgorithms, getKeyExchangeAlgorithms());
		serializer.writeField(SerializedFields::ServerHostKeyAlgorithms, getServerHostKeyAlgorithms());
		serializer.writeField(SerializedFields::EncryptionAlgorithmsClientToServer,
		                      getEncryptionAlgorithmsClientToServer());
		serializer.writeField(SerializedFields::EncryptionAlgorithmsServerToClient,
		                      getEncryptionAlgorithmsServerToClient());
		serializer.writeField(SerializedFields::MacAlgorithmsClientToServer, getMacAlgorithmsClientToServer());
		serializer.writeField(SerializedFields::MacAlgorithmsServerToClient, getMacAlgorithmsServerToClient());
		serializer.writeField(SerializedFields::CompressionAlgorithmsClientToServer,
		                      getCompressionAlgorithmsClientToServer());
		serializer.writeField(SerializedFields::CompressionAlgorithmsServerToClient,
		                      getCompressionAlgorithmsServerToClient());
		serializer.writeField(SerializedFields::LanguagesClientToServer, getLanguagesClientToServer());
		serializer.writeField(SerializedFields::LanguagesServerToClient, getLanguagesServerToClient());
		serializer.writeField(SerializedFields::FirstKexPacketFollows, isFirstKexPacketFollows());
	}

	// ---------------------------
	// SSHEncryptedMessage methods
	// ---------------------------

	std::string SSHEncryptedMessage::toString() const
	{
		return std::string(SshLayerBaseString) + ", " + "Encrypted Message";
	}

	void SSHEncryptedMessage::serializeLayer(ObjectScope& serializer) const
	{
		serializer.writeField(SSHLayer::SerializedFields::SSHMessageType, "Encrypted");
	}

}  // namespace pcpp
