#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "SipLayer.h"
#include "SdpLayer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"


PTF_TEST_CASE(SipRequestLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/sip_req1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/sip_req2.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/sip_req3.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/sip_req4.dat");

	pcpp::Packet sipReqPacket1(&rawPacket1);
	pcpp::Packet sipReqPacket2(&rawPacket2);
	pcpp::Packet sipReqPacket3(&rawPacket3);
	pcpp::Packet sipReqPacket4(&rawPacket4);

	PTF_ASSERT_TRUE(sipReqPacket1.isPacketOfType(pcpp::SIP));
	PTF_ASSERT_TRUE(sipReqPacket1.isPacketOfType(pcpp::SIPRequest));

	PTF_ASSERT_TRUE(sipReqPacket2.isPacketOfType(pcpp::SIP));
	PTF_ASSERT_TRUE(sipReqPacket2.isPacketOfType(pcpp::SIPRequest));

	PTF_ASSERT_TRUE(sipReqPacket3.isPacketOfType(pcpp::SIP));
	PTF_ASSERT_TRUE(sipReqPacket3.isPacketOfType(pcpp::SIPRequest));

	PTF_ASSERT_TRUE(sipReqPacket4.isPacketOfType(pcpp::SIP));
	PTF_ASSERT_TRUE(sipReqPacket4.isPacketOfType(pcpp::SIPRequest));

	pcpp::SipRequestLayer* sipReqLayer = sipReqPacket1.getLayerOfType<pcpp::SipRequestLayer>();

	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getMethod(), pcpp::SipRequestLayer::SipINVITE, enum);
	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getUri(), "sip:francisco@bestel.com:55060", string);
	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getVersion(), "SIP/2.0", string);
	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getSize(), 47, int);

	PTF_ASSERT_NOT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_FROM_FIELD));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldByName(PCPP_SIP_FROM_FIELD)->getFieldValue(), "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", string);
	PTF_ASSERT_NOT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_CONTACT_FIELD));
	PTF_ASSERT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_CONTACT_FIELD, 1));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldByName(PCPP_SIP_CONTACT_FIELD)->getFieldValue(), "<sip:200.57.7.195:5060>", string);
	PTF_ASSERT_NOT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD)->getFieldValue(), "SIP/2.0/UDP 200.57.7.195;branch=z9hG4bKff9b46fb055c0521cc24024da96cd290", string);
	PTF_ASSERT_NOT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 1));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 1)->getFieldValue(), "SIP/2.0/UDP 200.57.7.195:55061;branch=z9hG4bK291d90e31a47b225bd0ddff4353e9cc0", string);
	PTF_ASSERT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 2));
	PTF_ASSERT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 100));
	PTF_ASSERT_NULL(sipReqLayer->getFieldByName("BlaBla"));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldCount(), 9, int);

	PTF_ASSERT_EQUAL(sipReqLayer->getFirstField()->getFieldName(), "Via", string);

	PTF_ASSERT_EQUAL(sipReqLayer->getHeaderLen(), 469, size);
	PTF_ASSERT_EQUAL(sipReqLayer->getLayerPayloadSize(), 229, size);
	PTF_ASSERT_EQUAL(sipReqLayer->getContentLength(), 229, int);


	sipReqLayer = sipReqPacket2.getLayerOfType<pcpp::SipRequestLayer>();

	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getMethod(), pcpp::SipRequestLayer::SipCANCEL, enum);
	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getUri(), "sip:echo@iptel.org", string);
	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getSize(), 35, int);

	PTF_ASSERT_NOT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_MAX_FORWARDS_FIELD));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldByName(PCPP_SIP_MAX_FORWARDS_FIELD)->getFieldValue(), "70", string);
	PTF_ASSERT_TRUE(sipReqLayer->getNextField(sipReqLayer->getFieldByName(PCPP_SIP_MAX_FORWARDS_FIELD))->isEndOfHeader());
	PTF_ASSERT_NOT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_CSEQ_FIELD));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldByName(PCPP_SIP_CSEQ_FIELD)->getFieldValue(), "2 CANCEL", string);
	PTF_ASSERT_NOT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_TO_FIELD));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldByName(PCPP_SIP_TO_FIELD)->getFieldValue(), "<sip:echo@iptel.org>", string);
	PTF_ASSERT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_TO_FIELD, 2));
	PTF_ASSERT_TRUE(sipReqLayer->isHeaderComplete());


	sipReqLayer = sipReqPacket3.getLayerOfType<pcpp::SipRequestLayer>();

	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getMethod(), pcpp::SipRequestLayer::SipACK, enum);
	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getUri(), "sip:admind@178.45.73.241",string);
	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getSize(), 38, int);

	PTF_ASSERT_FALSE(sipReqLayer->isHeaderComplete());
	PTF_ASSERT_NOT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 1));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 1)->getFieldValue(), "SIP/2.0/UDP 213.192.59.78:5080;rport=5080;branch=z9hG4bKjBiNGaOX", string);
	PTF_ASSERT_NOT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_CALL_ID_FIELD));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldByName(PCPP_SIP_CALL_ID_FIELD)->getFieldValue(), "2091060b-146f-e011-809a-0019cb53db77@admind-desktop", string);
	PTF_ASSERT_NOT_NULL(sipReqLayer->getFieldByName("P-hint"));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldByName("P-hint")->getFieldValue(), "rr-enforced", string);
	PTF_ASSERT_NULL(sipReqLayer->getNextField(sipReqLayer->getFieldByName("P-hint")));
	PTF_ASSERT_EQUAL(sipReqLayer->getContentLength(), 0, int);
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldCount(), 9, int);


	sipReqLayer = sipReqPacket4.getLayerOfType<pcpp::SipRequestLayer>();

	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getMethod(), pcpp::SipRequestLayer::SipBYE, enum);
	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getUri(), "sip:sipp@10.0.2.20:5060", string);
	PTF_ASSERT_EQUAL(sipReqLayer->getFirstLine()->getSize(), 37, int);

	PTF_ASSERT_FALSE(sipReqLayer->isHeaderComplete());
	PTF_ASSERT_NOT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_USER_AGENT_FIELD));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldByName(PCPP_SIP_USER_AGENT_FIELD)->getFieldValue(), "FreeSWITCH-mod_sofia/1.6.12-20-b91a0a6~64bit", string);
	PTF_ASSERT_NOT_NULL(sipReqLayer->getFieldByName(PCPP_SIP_REASON_FIELD));
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldByName(PCPP_SIP_REASON_FIELD)->getFieldValue(), "Q.850;cause=16;text=\"NORMAL_CLEARING\"", string);
	PTF_ASSERT_EQUAL(sipReqLayer->getNextField(sipReqLayer->getFieldByName(PCPP_SIP_REASON_FIELD))->getFieldName(), "Content-Lengt", string);
	PTF_ASSERT_EQUAL(sipReqLayer->getNextField(sipReqLayer->getFieldByName(PCPP_SIP_REASON_FIELD))->getFieldValue(), "", string);
	PTF_ASSERT_EQUAL(sipReqLayer->getFieldCount(), 11, int);

} // SipRequestLayerParsingTest



PTF_TEST_CASE(SipRequestLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/sip_req1.dat");

	pcpp::Packet sipReqSamplePacket(&rawPacket1);

	pcpp::Packet newSipPacket;

	pcpp::EthLayer ethLayer(*sipReqSamplePacket.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_TRUE(newSipPacket.addLayer(&ethLayer));

	pcpp::IPv4Layer ip4Layer;
	ip4Layer = *(sipReqSamplePacket.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_TRUE(newSipPacket.addLayer(&ip4Layer));

	pcpp::UdpLayer udpLayer = *(sipReqSamplePacket.getLayerOfType<pcpp::UdpLayer>());
	PTF_ASSERT_TRUE(newSipPacket.addLayer(&udpLayer));

	pcpp::SipRequestLayer sipReqLayer(pcpp::SipRequestLayer::SipINVITE, "sip:francisco@bestel.com:55060");

	PTF_ASSERT_NOT_NULL(sipReqLayer.addField(PCPP_SIP_CALL_ID_FIELD, "12013223@200.57.7.195"));
	PTF_ASSERT_NOT_NULL(sipReqLayer.addField(PCPP_SIP_CONTENT_TYPE_FIELD, "application/sdp"));
	PTF_ASSERT_TRUE(sipReqLayer.addEndOfHeader());
	PTF_ASSERT_NOT_NULL(sipReqLayer.insertField(NULL, PCPP_SIP_VIA_FIELD, "SIP/2.0/UDP 200.57.7.195:55061;branch=z9hG4bK291d90e31a47b225bd0ddff4353e9cc0"));
	PTF_ASSERT_NOT_NULL(sipReqLayer.insertField(NULL, PCPP_SIP_VIA_FIELD, "SIP/2.0/UDP 200.57.7.195;branch=z9hG4bKff9b46fb055c0521cc24024da96cd290"));
	pcpp::HeaderField* callIDField = sipReqLayer.getFieldByName(PCPP_SIP_CALL_ID_FIELD);
	PTF_ASSERT_NOT_NULL(callIDField);
	pcpp::HeaderField* newField = sipReqLayer.insertField(callIDField, PCPP_SIP_CSEQ_FIELD, "1 INVITE");
	PTF_ASSERT_NOT_NULL(newField);
	newField = sipReqLayer.insertField(newField, PCPP_SIP_CONTACT_FIELD, "<sip:200.57.7.195:5060>");
	PTF_ASSERT_NOT_NULL(newField);
	pcpp::HeaderField* secondViaField = sipReqLayer.getFieldByName(PCPP_SIP_VIA_FIELD, 0);
	PTF_ASSERT_NOT_NULL(secondViaField);
	newField = sipReqLayer.insertField(secondViaField, PCPP_SIP_FROM_FIELD, "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34");
	PTF_ASSERT_NOT_NULL(newField);
	newField = sipReqLayer.insertField(newField, PCPP_SIP_TO_FIELD, "\"francisco@bestel.com\" <sip:francisco@bestel.com:55060>");
	PTF_ASSERT_NOT_NULL(newField);
	pcpp::HeaderField* contentLengthField = sipReqLayer.setContentLength(229, PCPP_SIP_CONTENT_TYPE_FIELD);
	PTF_ASSERT_NOT_NULL(contentLengthField);
	contentLengthField->setFieldValue("  229");


	PTF_ASSERT_TRUE(newSipPacket.addLayer(&sipReqLayer));

	pcpp::SipRequestLayer* samplePacketSipLayer = sipReqSamplePacket.getLayerOfType<pcpp::SipRequestLayer>();
	pcpp::PayloadLayer payloadLayer(samplePacketSipLayer->getLayerPayload(), samplePacketSipLayer->getLayerPayloadSize(), true);
	PTF_ASSERT_TRUE(newSipPacket.addLayer(&payloadLayer));

	newSipPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(newSipPacket.getRawPacket()->getRawDataLen(), bufferLength1, int);
	PTF_ASSERT_BUF_COMPARE(newSipPacket.getRawPacket()->getRawData(), buffer1, newSipPacket.getRawPacket()->getRawDataLen());
} // SipRequestLayerCreationTest



PTF_TEST_CASE(SipRequestLayerEditTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/sip_req2.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/sip_req3.dat");

	pcpp::Packet secondSipPacket(&rawPacket2);
	pcpp::Packet editedPacket(&rawPacket3);

	pcpp::SipRequestLayer* sipReqLayer = editedPacket.getLayerOfType<pcpp::SipRequestLayer>();

	PTF_ASSERT_NOT_NULL(sipReqLayer);

	PTF_ASSERT_TRUE(sipReqLayer->getFirstLine()->setMethod(pcpp::SipRequestLayer::SipBYE));
	PTF_ASSERT_TRUE(sipReqLayer->getFirstLine()->setMethod(pcpp::SipRequestLayer::SipREGISTER));
	PTF_ASSERT_TRUE(sipReqLayer->getFirstLine()->setMethod(pcpp::SipRequestLayer::SipCANCEL));

	PTF_ASSERT_TRUE(sipReqLayer->getFirstLine()->setUri("sip:francisco@bestel.com:55060"));
	PTF_ASSERT_TRUE(sipReqLayer->getFirstLine()->setUri("sip:echo@iptel.org"));

	pcpp::LoggerPP::getInstance().supressErrors();
	PTF_ASSERT_FALSE(sipReqLayer->getFirstLine()->setUri(""));
	pcpp::LoggerPP::getInstance().enableErrors();

	PTF_ASSERT_TRUE(sipReqLayer->getFieldByName(PCPP_SIP_VIA_FIELD, 1)->setFieldValue("SIP/2.0/UDP 178.45.73.241:5060;branch=z9hG4bKb26f2c0b-146f-e011-809a-0019cb53db77;rport"));
	PTF_ASSERT_TRUE(sipReqLayer->getFieldByName(PCPP_SIP_MAX_FORWARDS_FIELD)->setFieldValue("70"));
	PTF_ASSERT_TRUE(sipReqLayer->removeField(PCPP_SIP_VIA_FIELD, 0));
	PTF_ASSERT_TRUE(sipReqLayer->removeField(PCPP_SIP_RECORD_ROUTE_FIELD));
	PTF_ASSERT_TRUE(sipReqLayer->removeField("P-hint"));
	PTF_ASSERT_NOT_NULL(sipReqLayer->addEndOfHeader());
	PTF_ASSERT_NOT_NULL(sipReqLayer->setContentLength(0, PCPP_SIP_TO_FIELD));
	PTF_ASSERT_TRUE(sipReqLayer->removeField(PCPP_SIP_CALL_ID_FIELD));
	PTF_ASSERT_TRUE(sipReqLayer->removeField(PCPP_SIP_CSEQ_FIELD));
	PTF_ASSERT_NOT_NULL(sipReqLayer->insertField(PCPP_SIP_FROM_FIELD, PCPP_SIP_CALL_ID_FIELD, "2091060b-146f-e011-809a-0019cb53db77@admind-desktop"));
	PTF_ASSERT_NOT_NULL(sipReqLayer->insertField("", PCPP_SIP_CSEQ_FIELD, "2 CANCEL"));
	PTF_ASSERT_TRUE(sipReqLayer->getFieldByName(PCPP_SIP_FROM_FIELD)->setFieldValue("\"sam netmon \" <sip:admind@178.45.73.241>;tag=bc86060b-146f-e011-809a-0019cb53db77"));
	PTF_ASSERT_TRUE(sipReqLayer->getFieldByName(PCPP_SIP_TO_FIELD)->setFieldValue("<sip:echo@iptel.org>"));

	editedPacket.computeCalculateFields();

	pcpp::SipRequestLayer* secondSipReqLayer = secondSipPacket.getLayerOfType<pcpp::SipRequestLayer>();
	secondSipReqLayer->getFieldByName(PCPP_SIP_MAX_FORWARDS_FIELD)->setFieldValue(" 70");

	PTF_ASSERT_EQUAL(secondSipReqLayer->getHeaderLen(), sipReqLayer->getHeaderLen(), size);
	PTF_ASSERT_EQUAL(secondSipReqLayer->getFirstLine()->getSize(), sipReqLayer->getFirstLine()->getSize(), int);
	PTF_ASSERT_EQUAL(secondSipReqLayer->getFirstLine()->getMethod(), sipReqLayer->getFirstLine()->getMethod(), enum);
	PTF_ASSERT_EQUAL(secondSipReqLayer->getFirstLine()->getUri(), sipReqLayer->getFirstLine()->getUri(), string);
	PTF_ASSERT_EQUAL(secondSipReqLayer->getFirstLine()->getVersion(), sipReqLayer->getFirstLine()->getVersion(), string);
	PTF_ASSERT_EQUAL(secondSipReqLayer->getFieldCount(), sipReqLayer->getFieldCount(), int);
	PTF_ASSERT_BUF_COMPARE(secondSipReqLayer->getData(), sipReqLayer->getData(), secondSipReqLayer->getHeaderLen());
} // SipRequestLayerEditTest



PTF_TEST_CASE(SipResponseLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/sip_resp1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/sip_resp2.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/sip_resp3.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/sip_resp4.dat");
	READ_FILE_AND_CREATE_PACKET(7, "PacketExamples/sip_resp7.dat");

	pcpp::Packet sipRespPacket1(&rawPacket1);
	pcpp::Packet sipRespPacket2(&rawPacket2);
	pcpp::Packet sipRespPacket3(&rawPacket3);
	pcpp::Packet sipRespPacket4(&rawPacket4);
	pcpp::Packet sipRespPacket7(&rawPacket7);

	PTF_ASSERT_TRUE(sipRespPacket1.isPacketOfType(pcpp::SIP));
	PTF_ASSERT_TRUE(sipRespPacket1.isPacketOfType(pcpp::SIPResponse));

	PTF_ASSERT_TRUE(sipRespPacket2.isPacketOfType(pcpp::SIP));
	PTF_ASSERT_TRUE(sipRespPacket2.isPacketOfType(pcpp::SIPResponse));

	PTF_ASSERT_TRUE(sipRespPacket3.isPacketOfType(pcpp::SIP));
	PTF_ASSERT_TRUE(sipRespPacket3.isPacketOfType(pcpp::SIPResponse));

	PTF_ASSERT_TRUE(sipRespPacket4.isPacketOfType(pcpp::SIP));
	PTF_ASSERT_TRUE(sipRespPacket4.isPacketOfType(pcpp::SIPResponse));

	PTF_ASSERT_TRUE(sipRespPacket7.isPacketOfType(pcpp::SIP));
	PTF_ASSERT_TRUE(sipRespPacket7.isPacketOfType(pcpp::SIPResponse));

	pcpp::SipResponseLayer* sipRespLayer = sipRespPacket1.getLayerOfType<pcpp::SipResponseLayer>();

	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCode(), pcpp::SipResponseLayer::Sip100Trying, enum);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCodeAsInt(), 100, int);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCodeString(), "Trying", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getVersion(), "SIP/2.0", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getSize(), 20, int);

	PTF_ASSERT_NOT_NULL(sipRespLayer->getFieldByName(PCPP_SIP_FROM_FIELD));
	PTF_ASSERT_EQUAL(sipRespLayer->getFieldByName(PCPP_SIP_FROM_FIELD)->getFieldValue(), "<sip:200.57.7.195:55061;user=phone>;tag=GR52RWG346-34", string);
	PTF_ASSERT_NOT_NULL(sipRespLayer->getFieldByName(PCPP_SIP_CALL_ID_FIELD));
	PTF_ASSERT_EQUAL(sipRespLayer->getFieldByName(PCPP_SIP_CALL_ID_FIELD)->getFieldValue(), "12013223@200.57.7.195", string);
	PTF_ASSERT_NOT_NULL(sipRespLayer->getFieldByName(PCPP_SIP_SERVER_FIELD));
	PTF_ASSERT_EQUAL(sipRespLayer->getFieldByName(PCPP_SIP_SERVER_FIELD)->getFieldValue(), "X-Lite release 1103m", string);
	PTF_ASSERT_NOT_NULL(sipRespLayer->getFieldByName(PCPP_SIP_CONTENT_LENGTH_FIELD));
	PTF_ASSERT_EQUAL(sipRespLayer->getFieldByName(PCPP_SIP_CONTENT_LENGTH_FIELD)->getFieldValue(), "0", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getContentLength(), 0, int);


	sipRespLayer = sipRespPacket2.getLayerOfType<pcpp::SipResponseLayer>();

	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCode(), pcpp::SipResponseLayer::Sip180Ringing, enum);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCodeAsInt(), 180, int);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCodeString(), "Ringing", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getVersion(), "SIP/2.0", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getSize(), 21, int);

	PTF_ASSERT_EQUAL(sipRespLayer->getFirstField()->getFieldName(), PCPP_SIP_VIA_FIELD, string);
	PTF_ASSERT_NOT_NULL(sipRespLayer->getFieldByName(PCPP_SIP_VIA_FIELD));
	PTF_ASSERT_EQUAL(sipRespLayer->getFieldByName(PCPP_SIP_VIA_FIELD)->getFieldValue(), "SIP/2.0/UDP 200.57.7.195;branch=z9hG4bKff9b46fb055c0521cc24024da96cd290", string);
	PTF_ASSERT_NOT_NULL(sipRespLayer->getFieldByName(PCPP_SIP_CSEQ_FIELD));
	PTF_ASSERT_EQUAL(sipRespLayer->getFieldByName(PCPP_SIP_CSEQ_FIELD)->getFieldValue(), "1 INVITE", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getContentLength(), 0, int);


	sipRespLayer = sipRespPacket3.getLayerOfType<pcpp::SipResponseLayer>();

	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCode(), pcpp::SipResponseLayer::Sip200OK, enum);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCodeAsInt(), 200, int);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCodeString(), "Ok", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getVersion(), "SIP/2.0", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getSize(), 16, int);

	PTF_ASSERT_NOT_NULL(sipRespLayer->getFieldByName(PCPP_SIP_CONTENT_TYPE_FIELD));
	PTF_ASSERT_EQUAL(sipRespLayer->getFieldByName(PCPP_SIP_CONTENT_TYPE_FIELD)->getFieldValue(), "application/sdp", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getContentLength(), 298, int);


	sipRespLayer = sipRespPacket4.getLayerOfType<pcpp::SipResponseLayer>();

	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCode(), pcpp::SipResponseLayer::Sip401Unauthorized, enum);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCodeAsInt(), 401, int);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCodeString(), "Unauthorized", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getVersion(), "SIP/2.0", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getSize(), 26, int);

	PTF_ASSERT_NOT_NULL(sipRespLayer->getFieldByName(PCPP_SIP_WWW_AUTHENTICATE_FIELD));
	PTF_ASSERT_EQUAL(sipRespLayer->getFieldByName(PCPP_SIP_WWW_AUTHENTICATE_FIELD)->getFieldValue(), "Digest  realm=\"ims.hom\",nonce=\"021fa2db5ff06518\",opaque=\"627f7bb95d5e2dcd\",algorithm=MD5,qop=\"auth\"", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getContentLength(), 0, int);


	sipRespLayer = sipRespPacket7.getLayerOfType<pcpp::SipResponseLayer>();

	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCode(), pcpp::SipResponseLayer::Sip503ServiceUnavailable, enum);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCodeAsInt(), 503, int);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCodeString(), "Service Unavailable", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getVersion(), "SIP/2.0", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getSize(), 33, int);

	PTF_ASSERT_NOT_NULL(sipRespLayer->getFieldByName(PCPP_SIP_RETRY_AFTER_FIELD));
	PTF_ASSERT_EQUAL(sipRespLayer->getFieldByName(PCPP_SIP_RETRY_AFTER_FIELD)->getFieldValue(), "0", string);
	PTF_ASSERT_EQUAL(sipRespLayer->getContentLength(), 0, int);
} // SipResponseLayerParsingTest



PTF_TEST_CASE(SipResponseLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(6, "PacketExamples/sip_resp6.dat");

	pcpp::Packet sipRespSamplePacket(&rawPacket6);

	pcpp::Packet newSipPacket;

	pcpp::EthLayer ethLayer(*sipRespSamplePacket.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_TRUE(newSipPacket.addLayer(&ethLayer));

	pcpp::IPv4Layer ip4Layer;
	ip4Layer = *(sipRespSamplePacket.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_TRUE(newSipPacket.addLayer(&ip4Layer));

	pcpp::UdpLayer udpLayer = *(sipRespSamplePacket.getLayerOfType<pcpp::UdpLayer>());
	PTF_ASSERT_TRUE(newSipPacket.addLayer(&udpLayer));

	pcpp::SipResponseLayer sipRespLayer(pcpp::SipResponseLayer::Sip504ServerTimeout);

	PTF_ASSERT_NOT_NULL(sipRespLayer.addField(PCPP_SIP_FROM_FIELD, "<sip:user103@ims.hom>;tag=2054531660"));
	PTF_ASSERT_NOT_NULL(sipRespLayer.addField(PCPP_SIP_CSEQ_FIELD, "1 REGISTER"));
	pcpp::HeaderField* contentLengthField = sipRespLayer.setContentLength(0, PCPP_SIP_CSEQ_FIELD);
	PTF_ASSERT_NOT_NULL(contentLengthField);
	contentLengthField->setFieldValue(" 0");
	PTF_ASSERT_NOT_NULL(sipRespLayer.addEndOfHeader());
	PTF_ASSERT_NOT_NULL(sipRespLayer.insertField(NULL, PCPP_SIP_CALL_ID_FIELD, "93803593"));
	PTF_ASSERT_NOT_NULL(sipRespLayer.insertField(NULL, PCPP_SIP_VIA_FIELD, "SIP/2.0/UDP 10.3.160.214:5060;rport=5060;received=10.3.160.214;branch=z9hG4bK19266132"));
	pcpp::HeaderField* fromField = sipRespLayer.getFieldByName(PCPP_SIP_FROM_FIELD);
	PTF_ASSERT_NOT_NULL(fromField);
	PTF_ASSERT_NOT_NULL(sipRespLayer.insertField(fromField, PCPP_SIP_TO_FIELD, "<sip:user103@ims.hom>;tag=z9hG4bKPjoKb0QlsN0Z-v4iW63WRm5UfjLn.Gm81V"));

	PTF_ASSERT_TRUE(newSipPacket.addLayer(&sipRespLayer));

	newSipPacket.computeCalculateFields();

	newSipPacket.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->headerChecksum = 0xced8;

	PTF_ASSERT_EQUAL(newSipPacket.getRawPacket()->getRawDataLen(), bufferLength6, int);
	PTF_ASSERT_BUF_COMPARE(newSipPacket.getRawPacket()->getRawData(), buffer6, newSipPacket.getRawPacket()->getRawDataLen());
} // SipResponseLayerCreationTest



PTF_TEST_CASE(SipResponseLayerEditTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/sip_resp3.dat");
	READ_FILE_AND_CREATE_PACKET(4, "PacketExamples/sip_resp4.dat");

	pcpp::Packet editedPacket(&rawPacket3);
	pcpp::Packet secondSipPacket(&rawPacket4);

	pcpp::SipResponseLayer* sipRespLayer = editedPacket.getLayerOfType<pcpp::SipResponseLayer>();

	PTF_ASSERT_NOT_NULL(sipRespLayer);

	PTF_ASSERT_TRUE(sipRespLayer->getFirstLine()->setStatusCode(pcpp::SipResponseLayer::Sip202Accepted));
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCode(), pcpp::SipResponseLayer::Sip202Accepted, enum);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getSize(), 22, int);
	PTF_ASSERT_TRUE(sipRespLayer->getFirstLine()->setStatusCode(pcpp::SipResponseLayer::Sip415UnsupportedMediaType));
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCode(), pcpp::SipResponseLayer::Sip415UnsupportedMediaType, enum);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getSize(), 36, int);
	PTF_ASSERT_TRUE(sipRespLayer->getFirstLine()->setStatusCode(pcpp::SipResponseLayer::Sip603Decline));
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCode(), pcpp::SipResponseLayer::Sip603Decline, enum);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getSize(), 21, int);
	PTF_ASSERT_TRUE(sipRespLayer->getFirstLine()->setStatusCode(pcpp::SipResponseLayer::Sip603Decline, "Some other string"));
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCode(), pcpp::SipResponseLayer::Sip603Decline, enum);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getSize(), 31, int);
	PTF_ASSERT_TRUE(sipRespLayer->getFirstLine()->setStatusCode(pcpp::SipResponseLayer::Sip401Unauthorized));
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getStatusCode(), pcpp::SipResponseLayer::Sip401Unauthorized, enum);
	PTF_ASSERT_EQUAL(sipRespLayer->getFirstLine()->getSize(), 26, int);

	pcpp::LoggerPP::getInstance().supressErrors();
	PTF_ASSERT_FALSE(sipRespLayer->getFirstLine()->setStatusCode(pcpp::SipResponseLayer::SipStatusCodeUnknown));
	pcpp::LoggerPP::getInstance().enableErrors();

	PTF_ASSERT_TRUE(sipRespLayer->removeField(PCPP_SIP_VIA_FIELD, 1));
	PTF_ASSERT_TRUE(sipRespLayer->removeField(PCPP_SIP_CONTACT_FIELD));
	PTF_ASSERT_TRUE(sipRespLayer->removeField(PCPP_SIP_CALL_ID_FIELD));
	PTF_ASSERT_TRUE(sipRespLayer->getFieldByName(PCPP_SIP_VIA_FIELD)->setFieldValue("SIP/2.0/UDP 10.3.160.214:5060;rport=5060;received=10.3.160.214;branch=z9hG4bK758266975"));
	PTF_ASSERT_TRUE(sipRespLayer->removeField(PCPP_SIP_CONTENT_TYPE_FIELD));
	PTF_ASSERT_TRUE(sipRespLayer->removeField(PCPP_SIP_SERVER_FIELD));
	PTF_ASSERT_NOT_NULL(sipRespLayer->setContentLength(0));
	PTF_ASSERT_TRUE(sipRespLayer->getFieldByName(PCPP_SIP_FROM_FIELD)->setFieldValue("<sip:user3@ims.hom>;tag=1597735002"));
	PTF_ASSERT_TRUE(sipRespLayer->getFieldByName(PCPP_SIP_TO_FIELD)->setFieldValue("<sip:user3@ims.hom>;tag=z9hG4bKPjNwtzXu2EwWIjxR8qftv00jzO9arV-iyh"));
	PTF_ASSERT_TRUE(sipRespLayer->getFieldByName(PCPP_SIP_CSEQ_FIELD)->setFieldValue("1 REGISTER"));
	PTF_ASSERT_NOT_NULL(sipRespLayer->insertField(PCPP_SIP_CSEQ_FIELD, PCPP_SIP_WWW_AUTHENTICATE_FIELD,
			"Digest  realm=\"ims.hom\",nonce=\"021fa2db5ff06518\",opaque=\"627f7bb95d5e2dcd\",algorithm=MD5,qop=\"auth\""));
	PTF_ASSERT_NOT_NULL(sipRespLayer->insertField(PCPP_SIP_VIA_FIELD, PCPP_SIP_CALL_ID_FIELD, "434981653"));
	PTF_ASSERT_TRUE(sipRespLayer->getFieldByName(PCPP_SIP_CONTENT_LENGTH_FIELD)->setFieldValue(" 0"));

	pcpp::SipResponseLayer* secondSipRespLayer = secondSipPacket.getLayerOfType<pcpp::SipResponseLayer>();

	PTF_ASSERT_EQUAL(secondSipRespLayer->getHeaderLen(), sipRespLayer->getHeaderLen(), size);
	PTF_ASSERT_EQUAL(secondSipRespLayer->getFirstLine()->getSize(), sipRespLayer->getFirstLine()->getSize(), int);
	PTF_ASSERT_EQUAL(secondSipRespLayer->getFirstLine()->getStatusCode(), sipRespLayer->getFirstLine()->getStatusCode(), enum);
	PTF_ASSERT_EQUAL(secondSipRespLayer->getFieldCount(), sipRespLayer->getFieldCount(), int);
	PTF_ASSERT_BUF_COMPARE(secondSipRespLayer->getData(), sipRespLayer->getData(), secondSipRespLayer->getHeaderLen());
} // SipResponseLayerEditTest



PTF_TEST_CASE(SdpLayerParsingTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/sip_req1.dat");
	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/sdp.dat");

	pcpp::Packet sdpPacket(&rawPacket1);
	pcpp::Packet sdpPacket2(&rawPacket2);

	PTF_ASSERT_TRUE(sdpPacket.isPacketOfType(pcpp::SDP));
	pcpp::SdpLayer* sdpLayer = sdpPacket.getLayerOfType<pcpp::SdpLayer>();
	PTF_ASSERT_NOT_NULL(sdpLayer);

	PTF_ASSERT_EQUAL(sdpLayer->getFieldCount(), 11, int);

	PTF_ASSERT_NOT_NULL(sdpLayer->getFieldByName(PCPP_SDP_PROTOCOL_VERSION_FIELD));
	PTF_ASSERT_EQUAL(sdpLayer->getFieldByName(PCPP_SDP_PROTOCOL_VERSION_FIELD)->getFieldValue(), "0", string);
	PTF_ASSERT_NOT_NULL(sdpLayer->getFieldByName(PCPP_SDP_ORIGINATOR_FIELD));
	PTF_ASSERT_EQUAL(sdpLayer->getFieldByName(PCPP_SDP_ORIGINATOR_FIELD)->getFieldValue(), "Clarent 120386 120387 IN IP4 200.57.7.196", string);
	PTF_ASSERT_NOT_NULL(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_NAME_FIELD));
	PTF_ASSERT_EQUAL(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_NAME_FIELD)->getFieldValue(), "audio 40376 RTP/AVP 8 18 4 0", string);
	PTF_ASSERT_NOT_NULL(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD));
	PTF_ASSERT_EQUAL(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD)->getFieldValue(), "rtpmap:8 PCMA/8000", string);
	PTF_ASSERT_NOT_NULL(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD, 2));
	PTF_ASSERT_EQUAL(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD, 2)->getFieldValue(), "rtpmap:4 G723/8000", string);
	PTF_ASSERT_NOT_NULL(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD, 4));
	PTF_ASSERT_EQUAL(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD, 4)->getFieldValue(), "SendRecv", string);
	PTF_ASSERT_NULL(sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD, 5));

	PTF_ASSERT_EQUAL(sdpLayer->getOwnerIPv4Address(), pcpp::IPv4Address("200.57.7.196"), object);
	PTF_ASSERT_EQUAL(sdpLayer->getMediaPort("audio"), 40376, u16);

	PTF_ASSERT_TRUE(sdpPacket2.isPacketOfType(pcpp::SDP));
	sdpLayer = sdpPacket2.getLayerOfType<pcpp::SdpLayer>();
	PTF_ASSERT_NOT_NULL(sdpLayer);

	PTF_ASSERT_EQUAL(sdpLayer->getFieldCount(), 18, int);

	PTF_ASSERT_NOT_NULL(sdpLayer->getFieldByName(PCPP_SDP_CONNECTION_INFO_FIELD));
	PTF_ASSERT_EQUAL(sdpLayer->getFieldByName(PCPP_SDP_CONNECTION_INFO_FIELD)->getFieldValue(), "IN IP4 10.33.6.100", string);
	PTF_ASSERT_NOT_NULL(sdpLayer->getFieldByName(PCPP_SDP_TIME_FIELD));
	PTF_ASSERT_EQUAL(sdpLayer->getFieldByName(PCPP_SDP_TIME_FIELD)->getFieldValue(), "0 0", string);
	PTF_ASSERT_NOT_NULL(sdpLayer->getFieldByName(PCPP_SDP_SESSION_NAME_FIELD));
	PTF_ASSERT_EQUAL(sdpLayer->getFieldByName(PCPP_SDP_SESSION_NAME_FIELD)->getFieldValue(), "Phone-Call", string);

	PTF_ASSERT_EQUAL(sdpLayer->getOwnerIPv4Address(), pcpp::IPv4Address("10.33.6.100"), object);
	PTF_ASSERT_EQUAL(sdpLayer->getMediaPort("audio"), 6010, u16);
	PTF_ASSERT_EQUAL(sdpLayer->getMediaPort("image"), 6012, u16);
} // SdpLayerParsingTest



PTF_TEST_CASE(SdpLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/sdp.dat");

	pcpp::Packet sdpPacket(&rawPacket1);

	pcpp::Packet newSdpPacket;

	pcpp::EthLayer ethLayer(*sdpPacket.getLayerOfType<pcpp::EthLayer>());
	PTF_ASSERT_TRUE(newSdpPacket.addLayer(&ethLayer));

	pcpp::IPv4Layer ip4Layer;
	ip4Layer = *(sdpPacket.getLayerOfType<pcpp::IPv4Layer>());
	PTF_ASSERT_TRUE(newSdpPacket.addLayer(&ip4Layer));

	pcpp::UdpLayer udpLayer = *(sdpPacket.getLayerOfType<pcpp::UdpLayer>());
	PTF_ASSERT_TRUE(newSdpPacket.addLayer(&udpLayer));

	pcpp::SipResponseLayer sipLayer = *(sdpPacket.getLayerOfType<pcpp::SipResponseLayer>());
	PTF_ASSERT_TRUE(newSdpPacket.addLayer(&sipLayer));

	pcpp::SdpLayer newSdpLayer("IPP", 782647527, 782647407, pcpp::IPv4Address("10.33.6.100"), "Phone-Call", 0, 0);

	std::vector<std::string> audioAttributes;
	audioAttributes.push_back("rtpmap:8 PCMA/8000");
	audioAttributes.push_back("rtpmap:96 telephone-event/8000");
	audioAttributes.push_back("fmtp:96 0-15,16");
	audioAttributes.push_back("ptime:20");
	audioAttributes.push_back("sendrecv");
	PTF_ASSERT_TRUE(newSdpLayer.addMediaDescription("audio", 6010, "RTP/AVP", "8 96", audioAttributes));

	std::vector<std::string> imageAttributes;
	imageAttributes.push_back("T38FaxVersion:0");
	imageAttributes.push_back("T38MaxBitRate:14400");
	imageAttributes.push_back("T38FaxMaxBuffer:1024");
	imageAttributes.push_back("T38FaxMaxDatagram:238");
	imageAttributes.push_back("T38FaxRateManagement:transferredTCF");
	imageAttributes.push_back("T38FaxUdpEC:t38UDPRedundancy");
	PTF_ASSERT_TRUE(newSdpLayer.addMediaDescription("image", 6012, "udptl", "t38", imageAttributes));

	PTF_ASSERT_TRUE(newSdpPacket.addLayer(&newSdpLayer));

	newSdpPacket.computeCalculateFields();

	PTF_ASSERT_TRUE(newSdpPacket.isPacketOfType(pcpp::SDP));

	pcpp::SdpLayer* sdpLayerPtr = newSdpPacket.getLayerOfType<pcpp::SdpLayer>();

	PTF_ASSERT_NOT_NULL(sdpLayerPtr);
	PTF_ASSERT_EQUAL(sdpLayerPtr->getFieldCount(), 18, int);
	PTF_ASSERT_EQUAL(sdpLayerPtr->getHeaderLen(), 406, size);

	pcpp::SdpLayer* sdpLayerPtr2 = sdpPacket.getLayerOfType<pcpp::SdpLayer>();
	PTF_ASSERT_BUF_COMPARE(sdpLayerPtr2->getData(), sdpLayerPtr->getData(), sdpLayerPtr2->getHeaderLen());

	pcpp::SdpLayer copiedSdpLayer = *sdpLayerPtr;
	PTF_ASSERT_EQUAL(copiedSdpLayer.getFieldCount(), 18, int);
	PTF_ASSERT_EQUAL(copiedSdpLayer.getHeaderLen(), 406, size);
	PTF_ASSERT_BUF_COMPARE(copiedSdpLayer.getData(), sdpLayerPtr->getData(), sdpLayerPtr->getHeaderLen());
} // SdpLayerCreationTest



PTF_TEST_CASE(SdpLayerEditTest)
{
	timeval time;
	gettimeofday(&time, NULL);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/sdp.dat");
	READ_FILE_AND_CREATE_PACKET(3, "PacketExamples/sip_resp3.dat");

	pcpp::Packet sourceSdpPacket(&rawPacket3);
	pcpp::Packet targetSdpPacket(&rawPacket1);

	pcpp::SdpLayer* sdpLayer = sourceSdpPacket.getLayerOfType<pcpp::SdpLayer>();
	PTF_ASSERT_NOT_NULL(sdpLayer);

	PTF_ASSERT_TRUE(sdpLayer->getFieldByName(PCPP_SDP_ORIGINATOR_FIELD)->setFieldValue("IPP 782647527 782647407 IN IP4 10.33.6.100"));
	PTF_ASSERT_TRUE(sdpLayer->getFieldByName(PCPP_SDP_SESSION_NAME_FIELD)->setFieldValue("Phone-Call"));
	PTF_ASSERT_TRUE(sdpLayer->getFieldByName(PCPP_SDP_CONNECTION_INFO_FIELD)->setFieldValue("IN IP4 10.33.6.100"));
	PTF_ASSERT_TRUE(sdpLayer->removeField(PCPP_SDP_MEDIA_NAME_FIELD));
	while (sdpLayer->getFieldByName(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD) != NULL)
	{
		sdpLayer->removeField(PCPP_SDP_MEDIA_ATTRIBUTE_FIELD);
	}

	std::vector<std::string> audioAttributes;
	audioAttributes.push_back("rtpmap:8 PCMA/8000");
	audioAttributes.push_back("rtpmap:96 telephone-event/8000");
	audioAttributes.push_back("fmtp:96 0-15,16");
	audioAttributes.push_back("ptime:20");
	audioAttributes.push_back("sendrecv");
	PTF_ASSERT_TRUE(sdpLayer->addMediaDescription("audio", 6010, "RTP/AVP", "8 96", audioAttributes));

	std::vector<std::string> imageAttributes;
	imageAttributes.push_back("T38FaxVersion:0");
	imageAttributes.push_back("T38MaxBitRate:14400");
	imageAttributes.push_back("T38FaxMaxBuffer:1024");
	imageAttributes.push_back("T38FaxMaxDatagram:238");
	imageAttributes.push_back("T38FaxRateManagement:transferredTCF");
	imageAttributes.push_back("T38FaxUdpEC:t38UDPRedundancy");
	PTF_ASSERT_TRUE(sdpLayer->addMediaDescription("image", 6012, "udptl", "t38", imageAttributes));

	sourceSdpPacket.computeCalculateFields();

	pcpp::SdpLayer* targetSdpLayer = targetSdpPacket.getLayerOfType<pcpp::SdpLayer>();

	PTF_ASSERT_EQUAL(sdpLayer->getFieldCount(), targetSdpLayer->getFieldCount(), int);
	PTF_ASSERT_EQUAL(sdpLayer->getHeaderLen(), targetSdpLayer->getHeaderLen(), size);
	PTF_ASSERT_EQUAL(sdpLayer->getOwnerIPv4Address(), targetSdpLayer->getOwnerIPv4Address(), object);
	PTF_ASSERT_EQUAL(sdpLayer->getMediaPort("audio"), targetSdpLayer->getMediaPort("audio"), u16);
	PTF_ASSERT_EQUAL(sdpLayer->getMediaPort("image"), targetSdpLayer->getMediaPort("image"), u16);
	PTF_ASSERT_BUF_COMPARE(sdpLayer->getData(), targetSdpLayer->getData(), targetSdpLayer->getHeaderLen());
} // SdpLayerEditTest
