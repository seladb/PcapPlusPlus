#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "PayloadLayer.h"
#include "SystemUtils.h"
#include <iostream>
PTF_TEST_CASE(HttpRequestParseMethodTest)
{
	PTF_ASSERT_EQUAL(pcpp::HttpRequestFirstLine::parseMethod(nullptr, 0),
	                 pcpp::HttpRequestLayer::HttpMethod::HttpMethodUnknown, enum);
	PTF_ASSERT_EQUAL(pcpp::HttpRequestFirstLine::parseMethod(std::string("GET").c_str(), 3),
	                 pcpp::HttpRequestLayer::HttpMethod::HttpMethodUnknown, enum);

	PTF_ASSERT_EQUAL(pcpp::HttpRequestFirstLine::parseMethod(std::string("OPTIONS").c_str(), 7),
	                 pcpp::HttpRequestLayer::HttpMethod::HttpMethodUnknown, enum);

	std::vector<std::pair<std::string, pcpp::HttpRequestLayer::HttpMethod>> possibleMethods = {
		{ "GET",     pcpp::HttpRequestLayer::HttpMethod::HttpGET     },
		{ "HEAD",    pcpp::HttpRequestLayer::HttpMethod::HttpHEAD    },
		{ "POST",    pcpp::HttpRequestLayer::HttpMethod::HttpPOST    },
		{ "PUT",     pcpp::HttpRequestLayer::HttpMethod::HttpPUT     },
		{ "DELETE",  pcpp::HttpRequestLayer::HttpMethod::HttpDELETE  },
		{ "TRACE",   pcpp::HttpRequestLayer::HttpMethod::HttpTRACE   },
		{ "OPTIONS", pcpp::HttpRequestLayer::HttpMethod::HttpOPTIONS },
		{ "CONNECT", pcpp::HttpRequestLayer::HttpMethod::HttpCONNECT },
		{ "PATCH",   pcpp::HttpRequestLayer::HttpMethod::HttpPATCH   }
	};

	for (const std::pair<std::string, pcpp::HttpRequestLayer::HttpMethod>& method : possibleMethods)
	{
		std::string firstLine = method.first + " ";
		PTF_ASSERT_EQUAL(pcpp::HttpRequestFirstLine::parseMethod(firstLine.c_str(), firstLine.length()), method.second,
		                 enum);
	}

	PTF_ASSERT_EQUAL(pcpp::HttpRequestFirstLine::parseMethod(std::string("UNKNOWN ").c_str(), 8),
	                 pcpp::HttpRequestLayer::HttpMethod::HttpMethodUnknown, enum);
}  // HttpRequestParseMethodTest

PTF_TEST_CASE(HttpRequestLayerParsingTest)
{
	// This is a basic parsing test
	// A much wider test is in Pcap++Test

	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TwoHttpRequests1.dat");

	pcpp::Packet httpPacket(&rawPacket1);

	PTF_ASSERT_TRUE(httpPacket.isPacketOfType(pcpp::HTTPRequest));
	PTF_ASSERT_TRUE(httpPacket.isPacketOfType(pcpp::HTTP));
	pcpp::HttpRequestLayer* requestLayer = httpPacket.getLayerOfType<pcpp::HttpRequestLayer>();
	PTF_ASSERT_NOT_NULL(requestLayer);

	PTF_ASSERT_EQUAL(requestLayer->getFirstLine()->getMethod(), pcpp::HttpRequestLayer::HttpGET, enum);
	PTF_ASSERT_EQUAL(requestLayer->getFirstLine()->getVersion(), pcpp::OneDotOne, enum);
	PTF_ASSERT_EQUAL(requestLayer->getFirstLine()->getUri(), "/home/0,7340,L-8,00.html");

	pcpp::HeaderField* userAgent = requestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD);
	PTF_ASSERT_NOT_NULL(userAgent);
	PTF_ASSERT_TRUE(userAgent->getFieldValue().find("Safari/537.36") != std::string::npos);

	PTF_ASSERT_EQUAL(requestLayer->getUrl(), "www.ynet.co.il/home/0,7340,L-8,00.html");

	READ_FILE_AND_CREATE_PACKET(2, "PacketExamples/PartialHttpRequest.dat");
	pcpp::Packet httpPacket2(&rawPacket2);

	PTF_ASSERT_TRUE(httpPacket2.isPacketOfType(pcpp::HTTPRequest));
	requestLayer = httpPacket2.getLayerOfType<pcpp::HttpRequestLayer>();
	PTF_ASSERT_NOT_NULL(requestLayer);

	PTF_ASSERT_EQUAL(requestLayer->getFirstLine()->getMethod(), pcpp::HttpRequestLayer::HttpGET, enum);
	PTF_ASSERT_EQUAL(requestLayer->getFirstLine()->getVersion(), pcpp::OneDotOne, enum);
	PTF_ASSERT_EQUAL(requestLayer->getUrl(), "auth.wi-fi.ru/spa/vendor.bundle.5d388fb8db38cec4d554.js");

	userAgent = requestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD);
	PTF_ASSERT_NOT_NULL(userAgent);
	PTF_ASSERT_TRUE(userAgent->getFieldValue().find("Chrome/73.0.3683.90") != std::string::npos);

	pcpp::HeaderField* acceptLang = requestLayer->getFieldByName(PCPP_HTTP_ACCEPT_LANGUAGE_FIELD);
	PTF_ASSERT_NOT_NULL(acceptLang);
	PTF_ASSERT_EQUAL(acceptLang->getFieldValue(), "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7");

	pcpp::HeaderField* cookie = requestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD);
	PTF_ASSERT_NOT_NULL(cookie);

	PTF_ASSERT_EQUAL(requestLayer->getFieldCount(), 8);
	PTF_ASSERT_FALSE(requestLayer->isHeaderComplete());
}  // HttpRequestLayerParsingTest

PTF_TEST_CASE(HttpRequestLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TwoHttpRequests1.dat");

	pcpp::Packet sampleHttpPacket(&rawPacket1);

	pcpp::EthLayer ethLayer(*sampleHttpPacket.getLayerOfType<pcpp::EthLayer>());
	pcpp::IPv4Layer ip4Layer;
	ip4Layer = *(sampleHttpPacket.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::TcpLayer tcpLayer = *(sampleHttpPacket.getLayerOfType<pcpp::TcpLayer>());

	pcpp::HttpRequestLayer httpLayer(pcpp::HttpRequestLayer::HttpOPTIONS, "/home/0,7340,L-8,00", pcpp::OneDotOne);
	PTF_ASSERT_NOT_NULL(httpLayer.addField(
	    PCPP_HTTP_ACCEPT_FIELD, "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"));
	PTF_ASSERT_NOT_NULL(httpLayer.addField("Dummy-Field", "some value"));
	pcpp::HeaderField* hostField = httpLayer.insertField(nullptr, PCPP_HTTP_HOST_FIELD, "www.ynet-ynet.co.il");
	PTF_ASSERT_NOT_NULL(hostField);
	PTF_ASSERT_NOT_NULL(httpLayer.insertField(hostField, PCPP_HTTP_CONNECTION_FIELD, "keep-alive"));
	pcpp::HeaderField* userAgentField = httpLayer.addField(
	    PCPP_HTTP_USER_AGENT_FIELD,
	    "(Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.104 Safari/537.36");
	httpLayer.getFirstLine()->setUri("bla.php");
	PTF_ASSERT_NOT_NULL(userAgentField);
	PTF_ASSERT_NOT_NULL(httpLayer.addField(PCPP_HTTP_ACCEPT_LANGUAGE_FIELD, "en-US,en;q=0.8"));
	PTF_ASSERT_NOT_NULL(httpLayer.addField("Dummy-Field2", "Dummy Value2"));
	PTF_ASSERT_TRUE(httpLayer.removeField("Dummy-Field"));
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(httpLayer.removeField("Kuku"));
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_NOT_NULL(httpLayer.addEndOfHeader());
	PTF_ASSERT_TRUE(httpLayer.insertField(userAgentField, PCPP_HTTP_ACCEPT_ENCODING_FIELD, "gzip,deflate,sdch"));
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_NULL(httpLayer.addField("Kuku", "Muku"));
	pcpp::Logger::getInstance().enableLogs();
	hostField->setFieldValue("www.walla.co.il");

	pcpp::Packet httpPacket(10);
	PTF_ASSERT_TRUE(httpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(httpPacket.addLayer(&ip4Layer));
	PTF_ASSERT_TRUE(httpPacket.addLayer(&tcpLayer));
	PTF_ASSERT_TRUE(httpPacket.addLayer(&httpLayer));

	hostField->setFieldValue("www.ynet.co.il");
	httpLayer.getFirstLine()->setMethod(pcpp::HttpRequestLayer::HttpGET);
	PTF_ASSERT_EQUAL(httpLayer.getFirstLine()->getMethod(), pcpp::HttpRequestLayer::HttpGET, enum);
	httpLayer.getFirstLine()->setVersion(pcpp::OneDotOne);
	PTF_ASSERT_EQUAL(httpLayer.getFirstLine()->getVersion(), pcpp::OneDotOne, enum);
	httpLayer.getFirstLine()->setUri("/home/0,7340,L-8,00.html");
	PTF_ASSERT_TRUE(httpLayer.removeField("Dummy-Field2"));
	userAgentField->setFieldValue(
	    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.104 Safari/537.36");

	httpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(bufferLength1, httpPacket.getRawPacket()->getRawDataLen());
	PTF_ASSERT_BUF_COMPARE(buffer1, httpPacket.getRawPacket()->getRawData(), bufferLength1);

}  // HttpRequestLayerCreationTest

PTF_TEST_CASE(HttpRequestLayerEditTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TwoHttpRequests1.dat");

	pcpp::Packet httpRequest(&rawPacket1);

	pcpp::IPv4Layer* ip4Layer = httpRequest.getLayerOfType<pcpp::IPv4Layer>();
	ip4Layer->getIPv4Header()->ipId = htobe16(30170);

	pcpp::TcpLayer* tcpLayer = httpRequest.getLayerOfType<pcpp::TcpLayer>();
	tcpLayer->getTcpHeader()->portSrc = htobe16(60383);
	tcpLayer->getTcpHeader()->sequenceNumber = htobe32(0x876143cb);
	tcpLayer->getTcpHeader()->ackNumber = htobe32(0xa66ed328);
	tcpLayer->getTcpHeader()->windowSize = htobe16(16660);

	pcpp::HttpRequestLayer* httpReqLayer = httpRequest.getLayerOfType<pcpp::HttpRequestLayer>();
	PTF_ASSERT_TRUE(
	    httpReqLayer->getFirstLine()->setUri("/Common/Api/Video/CmmLightboxPlayerJs/0,14153,061014181713,00.js"));
	pcpp::HeaderField* acceptField = httpReqLayer->getFieldByName(PCPP_HTTP_ACCEPT_FIELD);
	PTF_ASSERT_NOT_NULL(acceptField);
	acceptField->setFieldValue("*/*");
	pcpp::HeaderField* userAgentField = httpReqLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD);
	PTF_ASSERT_NOT_NULL(userAgentField);
	httpReqLayer->insertField(userAgentField, PCPP_HTTP_REFERER_FIELD, "http://www.ynet.co.il/home/0,7340,L-8,00.html");

	READ_FILE_INTO_BUFFER(2, "PacketExamples/TwoHttpRequests2.dat");

	PTF_ASSERT_EQUAL(bufferLength2, httpRequest.getRawPacket()->getRawDataLen());

	httpRequest.computeCalculateFields();

	PTF_ASSERT_BUF_COMPARE(buffer2, httpRequest.getRawPacket()->getRawData(), bufferLength2);

	delete[] buffer2;

}  // HttpRequestLayerEditTest

PTF_TEST_CASE(HttpResponseParseStatusCodeTest)
{
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseStatusCode(nullptr, 0),
	                 pcpp::HttpResponseLayer::HttpResponseStatusCode::HttpStatusCodeUnknown);
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseStatusCode(std::string("abc").c_str(), 3),
	                 pcpp::HttpResponseLayer::HttpResponseStatusCode::HttpStatusCodeUnknown);

	std::vector<pcpp::HttpResponseStatusCode> possibleStatusCodes = {
		pcpp::HttpResponseStatusCode::Http100Continue,
		pcpp::HttpResponseStatusCode::Http101SwitchingProtocols,
		pcpp::HttpResponseStatusCode::Http102Processing,
		pcpp::HttpResponseStatusCode::Http103EarlyHints,
		pcpp::HttpResponseStatusCode::Http200OK,
		pcpp::HttpResponseStatusCode::Http201Created,
		pcpp::HttpResponseStatusCode::Http202Accepted,
		pcpp::HttpResponseStatusCode::Http203NonAuthoritativeInformation,
		pcpp::HttpResponseStatusCode::Http204NoContent,
		pcpp::HttpResponseStatusCode::Http205ResetContent,
		pcpp::HttpResponseStatusCode::Http206PartialContent,
		pcpp::HttpResponseStatusCode::Http207MultiStatus,
		pcpp::HttpResponseStatusCode::Http208AlreadyReported,
		pcpp::HttpResponseStatusCode::Http226IMUsed,
		pcpp::HttpResponseStatusCode::Http300MultipleChoices,
		pcpp::HttpResponseStatusCode::Http301MovedPermanently,
		pcpp::HttpResponseStatusCode::Http302,
		pcpp::HttpResponseStatusCode::Http303SeeOther,
		pcpp::HttpResponseStatusCode::Http304NotModified,
		pcpp::HttpResponseStatusCode::Http305UseProxy,
		pcpp::HttpResponseStatusCode::Http306SwitchProxy,
		pcpp::HttpResponseStatusCode::Http307TemporaryRedirect,
		pcpp::HttpResponseStatusCode::Http308PermanentRedirect,
		pcpp::HttpResponseStatusCode::Http400BadRequest,
		pcpp::HttpResponseStatusCode::Http401Unauthorized,
		pcpp::HttpResponseStatusCode::Http402PaymentRequired,
		pcpp::HttpResponseStatusCode::Http403Forbidden,
		pcpp::HttpResponseStatusCode::Http404NotFound,
		pcpp::HttpResponseStatusCode::Http405MethodNotAllowed,
		pcpp::HttpResponseStatusCode::Http406NotAcceptable,
		pcpp::HttpResponseStatusCode::Http407ProxyAuthenticationRequired,
		pcpp::HttpResponseStatusCode::Http408RequestTimeout,
		pcpp::HttpResponseStatusCode::Http409Conflict,
		pcpp::HttpResponseStatusCode::Http410Gone,
		pcpp::HttpResponseStatusCode::Http411LengthRequired,
		pcpp::HttpResponseStatusCode::Http412PreconditionFailed,
		pcpp::HttpResponseStatusCode::Http413RequestEntityTooLarge,
		pcpp::HttpResponseStatusCode::Http414RequestURITooLong,
		pcpp::HttpResponseStatusCode::Http415UnsupportedMediaType,
		pcpp::HttpResponseStatusCode::Http416RequestedRangeNotSatisfiable,
		pcpp::HttpResponseStatusCode::Http417ExpectationFailed,
		pcpp::HttpResponseStatusCode::Http418ImATeapot,
		pcpp::HttpResponseStatusCode::Http419AuthenticationTimeout,
		pcpp::HttpResponseStatusCode::Http420,
		pcpp::HttpResponseStatusCode::Http421MisdirectedRequest,
		pcpp::HttpResponseStatusCode::Http422UnprocessableEntity,
		pcpp::HttpResponseStatusCode::Http423Locked,
		pcpp::HttpResponseStatusCode::Http424FailedDependency,
		pcpp::HttpResponseStatusCode::Http425TooEarly,
		pcpp::HttpResponseStatusCode::Http426UpgradeRequired,
		pcpp::HttpResponseStatusCode::Http428PreconditionRequired,
		pcpp::HttpResponseStatusCode::Http429TooManyRequests,
		pcpp::HttpResponseStatusCode::Http431RequestHeaderFieldsTooLarge,
		pcpp::HttpResponseStatusCode::Http440LoginTimeout,
		pcpp::HttpResponseStatusCode::Http444NoResponse,
		pcpp::HttpResponseStatusCode::Http449RetryWith,
		pcpp::HttpResponseStatusCode::Http450BlockedByWindowsParentalControls,
		pcpp::HttpResponseStatusCode::Http451,
		pcpp::HttpResponseStatusCode::Http494RequestHeaderTooLarge,
		pcpp::HttpResponseStatusCode::Http495CertError,
		pcpp::HttpResponseStatusCode::Http496NoCert,
		pcpp::HttpResponseStatusCode::Http497HTTPtoHTTPS,
		pcpp::HttpResponseStatusCode::Http498TokenExpiredInvalid,
		pcpp::HttpResponseStatusCode::Http499,
		pcpp::HttpResponseStatusCode::Http500InternalServerError,
		pcpp::HttpResponseStatusCode::Http501NotImplemented,
		pcpp::HttpResponseStatusCode::Http502BadGateway,
		pcpp::HttpResponseStatusCode::Http503ServiceUnavailable,
		pcpp::HttpResponseStatusCode::Http504GatewayTimeout,
		pcpp::HttpResponseStatusCode::Http505HTTPVersionNotSupported,
		pcpp::HttpResponseStatusCode::Http506VariantAlsoNegotiates,
		pcpp::HttpResponseStatusCode::Http507InsufficientStorage,
		pcpp::HttpResponseStatusCode::Http508LoopDetected,
		pcpp::HttpResponseStatusCode::Http509BandwidthLimitExceeded,
		pcpp::HttpResponseStatusCode::Http510NotExtended,
		pcpp::HttpResponseStatusCode::Http511NetworkAuthenticationRequired,
		pcpp::HttpResponseStatusCode::Http520OriginError,
		pcpp::HttpResponseStatusCode::Http521WebServerIsDown,
		pcpp::HttpResponseStatusCode::Http522ConnectionTimedOut,
		pcpp::HttpResponseStatusCode::Http523ProxyDeclinedRequest,
		pcpp::HttpResponseStatusCode::Http524aTimeoutOccurred,
		pcpp::HttpResponseStatusCode::Http598NetworkReadTimeoutError,
		pcpp::HttpResponseStatusCode::Http599NetworkConnectTimeoutError,
	};

	for (const auto& statusCode : possibleStatusCodes)
	{
		std::string firstLine = "HTTP/x.y " + statusCode.toString() + " " + statusCode.getMessage() + "\n";
		PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseStatusCode(firstLine.c_str(), firstLine.length()),
		                 statusCode, enum);
	}

	PTF_ASSERT_EQUAL(
	    pcpp::HttpResponseFirstLine::parseStatusCode(std::string("HTTP/x.y 001 any message\n").c_str(), 26),
	    pcpp::HttpResponseStatusCode::HttpStatusCodeUnknown, enum);
	PTF_ASSERT_EQUAL(
	    pcpp::HttpResponseFirstLine::parseStatusCode(std::string("HTTP/x.y 199 any message\n").c_str(), 26),
	    pcpp::HttpResponseStatusCode::HttpStatus1xxCodeUnknown, enum);
	PTF_ASSERT_EQUAL(
	    pcpp::HttpResponseFirstLine::parseStatusCode(std::string("HTTP/x.y 299 any message\n").c_str(), 26),
	    pcpp::HttpResponseStatusCode::HttpStatus2xxCodeUnknown, enum);
	PTF_ASSERT_EQUAL(
	    pcpp::HttpResponseFirstLine::parseStatusCode(std::string("HTTP/x.y 399 any message\n").c_str(), 26),
	    pcpp::HttpResponseStatusCode::HttpStatus3xxCodeUnknown, enum);
	PTF_ASSERT_EQUAL(
	    pcpp::HttpResponseFirstLine::parseStatusCode(std::string("HTTP/x.y 477 any message\n").c_str(), 26),
	    pcpp::HttpResponseStatusCode::HttpStatus4xxCodeUnknown, enum);
	PTF_ASSERT_EQUAL(
	    pcpp::HttpResponseFirstLine::parseStatusCode(std::string("HTTP/x.y 577 any message\n").c_str(), 26),
	    pcpp::HttpResponseStatusCode::HttpStatus5xxCodeUnknown, enum);
	PTF_ASSERT_EQUAL(
	    pcpp::HttpResponseFirstLine::parseStatusCode(std::string("HTTP/x.y 600 any message\n").c_str(), 26),
	    pcpp::HttpResponseStatusCode::HttpStatusCodeUnknown, enum);

	// test getMessage()
	PTF_ASSERT_EQUAL(
	    pcpp::HttpResponseFirstLine::parseStatusCode(std::string("HTTP/x.y 200 OK\n").c_str(), 17).getMessage(), "OK");
	PTF_ASSERT_EQUAL(
	    pcpp::HttpResponseFirstLine::parseStatusCode(std::string("HTTP/x.y 404 Not Found\n").c_str(), 24).getMessage(),
	    "Not Found");

	std::string testLine;
	testLine = "HTTP/x.y 404 My Not Found\r\n";
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseStatusCode(testLine.c_str(), testLine.size()).getMessage(),
	                 "My Not Found");

	testLine = "HTTP/x.y 404 My Not Found 2\n";
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseStatusCode(testLine.c_str(), testLine.size()).getMessage(),
	                 "My Not Found 2");

	testLine = "HTTP/x.y 404 Unfinished Line Here";
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseStatusCode(testLine.c_str(), testLine.size()),
	                 pcpp::HttpResponseStatusCode::HttpStatusCodeUnknown);

	testLine = "HTTP/x.y 404\n";  // no status message
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseStatusCode(testLine.c_str(), testLine.size()),
	                 pcpp::HttpResponseStatusCode::HttpStatusCodeUnknown);

	testLine = "HTTP/x.y 404 \n";  // no status message
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseStatusCode(testLine.c_str(), testLine.size()),
	                 pcpp::HttpResponseStatusCode::HttpStatusCodeUnknown);
}  // HttpResponseParseStatusCodeTest

PTF_TEST_CASE(HttpResponseParseVersionTest)
{
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseVersion(nullptr, 0), pcpp::HttpVersion::HttpVersionUnknown,
	                 enum);
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseVersion(std::string("1.1").c_str(), 3),
	                 pcpp::HttpVersion::HttpVersionUnknown, enum);

	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseVersion(std::string("XTTP/1.1").c_str(), 8),
	                 pcpp::HttpVersion::HttpVersionUnknown, enum);
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseVersion(std::string("HXTP/1.1").c_str(), 8),
	                 pcpp::HttpVersion::HttpVersionUnknown, enum);
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseVersion(std::string("HTXP/1.1").c_str(), 8),
	                 pcpp::HttpVersion::HttpVersionUnknown, enum);
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseVersion(std::string("HTTX/1.1").c_str(), 8),
	                 pcpp::HttpVersion::HttpVersionUnknown, enum);
	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseVersion(std::string("HTTP 1.1").c_str(), 8),
	                 pcpp::HttpVersion::HttpVersionUnknown, enum);

	std::vector<std::pair<std::string, pcpp::HttpVersion>> possibleVersions = {
		{ "0.9", pcpp::HttpVersion::ZeroDotNine },
		{ "1.0", pcpp::HttpVersion::OneDotZero  },
		{ "1.1", pcpp::HttpVersion::OneDotOne   }
	};

	for (const std::pair<std::string, pcpp::HttpVersion>& version : possibleVersions)
	{
		std::string firstLine = "HTTP/" + version.first;
		PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseVersion(firstLine.c_str(), firstLine.length()),
		                 version.second, enum);
	}

	PTF_ASSERT_EQUAL(pcpp::HttpResponseFirstLine::parseVersion(std::string("HTTP/2.0 ").c_str(), 8),
	                 pcpp::HttpVersion::HttpVersionUnknown, enum);
}  // HttpResponseParseVersionTest

PTF_TEST_CASE(HttpResponseLayerParsingTest)
{
	// This is a basic parsing test
	// A much wider test is in Pcap++Test

	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TwoHttpResponses1.dat");

	pcpp::Packet httpPacket(&rawPacket1);

	PTF_ASSERT_TRUE(httpPacket.isPacketOfType(pcpp::HTTPResponse));
	PTF_ASSERT_TRUE(httpPacket.isPacketOfType(pcpp::HTTP));
	pcpp::HttpResponseLayer* responseLayer = httpPacket.getLayerOfType<pcpp::HttpResponseLayer>();
	PTF_ASSERT_NOT_NULL(responseLayer);

	PTF_ASSERT_EQUAL(responseLayer->getFirstLine()->getStatusCode(), pcpp::HttpResponseStatusCode::Http200OK, enum);
	PTF_ASSERT_EQUAL(responseLayer->getFirstLine()->getVersion(), pcpp::OneDotOne, enum);

	pcpp::HeaderField* contentLengthField = responseLayer->getFieldByName(PCPP_HTTP_CONTENT_LENGTH_FIELD);
	PTF_ASSERT_NOT_NULL(contentLengthField);
	int contentLength = atoi(contentLengthField->getFieldValue().c_str());
	PTF_ASSERT_EQUAL(contentLength, 1616);

	pcpp::HeaderField* contentTypeField = responseLayer->getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
	PTF_ASSERT_NOT_NULL(contentTypeField);
	PTF_ASSERT_EQUAL(contentTypeField->getFieldValue(), "application/x-javascript");
}  // HttpResponseLayerParsingTest

PTF_TEST_CASE(HttpResponseLayerCreationTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TwoHttpResponses1.dat");

	pcpp::Packet sampleHttpPacket(&rawPacket1);

	pcpp::EthLayer ethLayer = *sampleHttpPacket.getLayerOfType<pcpp::EthLayer>();
	pcpp::IPv4Layer ip4Layer(*sampleHttpPacket.getLayerOfType<pcpp::IPv4Layer>());
	pcpp::TcpLayer tcpLayer(*sampleHttpPacket.getLayerOfType<pcpp::TcpLayer>());

	pcpp::HttpResponseLayer httpResponse(pcpp::OneDotOne, pcpp::HttpResponseStatusCode::Http200OK);
	PTF_ASSERT_NOT_NULL(httpResponse.addField(PCPP_HTTP_SERVER_FIELD, "Microsoft-IIS/5.0"));
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_NULL(httpResponse.addField(PCPP_HTTP_SERVER_FIELD, "Microsoft-IIS/6.0"));
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_NOT_NULL(httpResponse.addField(PCPP_HTTP_CONTENT_ENCODING_FIELD, "gzip"));
	PTF_ASSERT_NOT_NULL(httpResponse.insertField(httpResponse.getFieldByName(PCPP_HTTP_SERVER_FIELD),
	                                             PCPP_HTTP_CONTENT_TYPE_FIELD, "application/x-javascript"));
	PTF_ASSERT_NOT_NULL(
	    httpResponse.insertField(httpResponse.getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD), "Accept-Ranges", "bytes"));
	PTF_ASSERT_NOT_NULL(httpResponse.insertField(httpResponse.getFieldByName("Accept-Ranges"), "KuKu", "BlaBla"));
	PTF_ASSERT_NOT_NULL(httpResponse.insertField(httpResponse.getFieldByName("kuku"), "Last-Modified",
	                                             "Wed, 19 Dec 2012 14:06:29 GMT"));
	PTF_ASSERT_NOT_NULL(
	    httpResponse.insertField(httpResponse.getFieldByName("last-Modified"), "ETag", "\"3b846daf2ddcd1:e29\""));
	PTF_ASSERT_NOT_NULL(httpResponse.insertField(httpResponse.getFieldByName("etag"), "Vary", "Accept-Encoding"));
	PTF_ASSERT_NOT_NULL(httpResponse.setContentLength(1616, PCPP_HTTP_CONTENT_ENCODING_FIELD));
	PTF_ASSERT_NOT_NULL(httpResponse.addField("Kuku2", "blibli2"));
	PTF_ASSERT_NOT_NULL(httpResponse.addField("Cache-Control", "max-age=66137"));
	PTF_ASSERT_TRUE(httpResponse.removeField("KUKU"));

	pcpp::Packet httpPacket(100);
	PTF_ASSERT_TRUE(httpPacket.addLayer(&ethLayer));
	PTF_ASSERT_TRUE(httpPacket.addLayer(&ip4Layer));
	PTF_ASSERT_TRUE(httpPacket.addLayer(&tcpLayer));
	PTF_ASSERT_TRUE(httpPacket.addLayer(&httpResponse));

	auto payloadLayer = new pcpp::PayloadLayer(*sampleHttpPacket.getLayerOfType<pcpp::PayloadLayer>());
	PTF_ASSERT_TRUE(httpPacket.addLayer(payloadLayer, true));

	PTF_ASSERT_NOT_NULL(httpResponse.addField(PCPP_HTTP_CONNECTION_FIELD, "keep-alive"));
	PTF_ASSERT_NOT_NULL(httpResponse.addEndOfHeader());
	PTF_ASSERT_NOT_NULL(httpResponse.insertField(httpResponse.getFieldByName("Cache-Control"), "Expires",
	                                             "Mon, 20 Oct 2014 13:34:26 GMT"));
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_NULL(httpResponse.addField("kuku3", "kuka"));
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_NOT_NULL(
	    httpResponse.insertField(httpResponse.getFieldByName("ExpIRes"), "Date", "Sun, 19 Oct 2014 19:12:09 GMT"));
	pcpp::Logger::getInstance().suppressLogs();
	PTF_ASSERT_FALSE(httpResponse.removeField("kuku5"));
	pcpp::Logger::getInstance().enableLogs();
	PTF_ASSERT_TRUE(httpResponse.removeField("kuku2"));

	httpPacket.computeCalculateFields();

	PTF_ASSERT_EQUAL(httpResponse.getHeaderLen(), 382);

	PTF_ASSERT_BUF_COMPARE(buffer1, httpPacket.getRawPacket()->getRawData(),
	                       ethLayer.getHeaderLen() + ip4Layer.getHeaderLen() + tcpLayer.getHeaderLen() +
	                           httpResponse.getHeaderLen());

}  // HttpResponseLayerCreationTest

PTF_TEST_CASE(HttpResponseLayerEditTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/TwoHttpResponses2.dat");

	pcpp::Packet httpPacket(&rawPacket1);

	PTF_ASSERT_TRUE(httpPacket.isPacketOfType(pcpp::HTTPResponse));
	pcpp::HttpResponseLayer* responseLayer = httpPacket.getLayerOfType<pcpp::HttpResponseLayer>();
	PTF_ASSERT_NOT_NULL(responseLayer);

	PTF_ASSERT_TRUE(responseLayer->getFirstLine()->isComplete());
	responseLayer->getFirstLine()->setVersion(pcpp::OneDotOne);

	// original status code is 404 Not Found
	PTF_ASSERT_TRUE(
	    responseLayer->getFirstLine()->setStatusCode(pcpp::HttpResponseStatusCode::Http505HTTPVersionNotSupported));
	PTF_ASSERT_EQUAL(responseLayer->getFirstLine()->getStatusCode(),
	                 pcpp::HttpResponseStatusCode::Http505HTTPVersionNotSupported, enum);
	PTF_ASSERT_EQUAL(responseLayer->getFirstLine()->getStatusCodeAsInt(), 505);

	PTF_ASSERT_EQUAL(responseLayer->getFirstLine()->getStatusCodeString(), "HTTP Version Not Supported");
	PTF_ASSERT_NOT_NULL(responseLayer->setContentLength(345));

	std::string expectedHttpResponse("HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 345\r\n");

	PTF_ASSERT_BUF_COMPARE(expectedHttpResponse.c_str(), responseLayer->getData(), expectedHttpResponse.length());

	PTF_ASSERT_TRUE(responseLayer->getFirstLine()->setStatusCode(
	    pcpp::HttpResponseStatusCode(pcpp::HttpResponseStatusCode::Http413RequestEntityTooLarge, "This is a test")));
	PTF_ASSERT_EQUAL(responseLayer->getFirstLine()->getStatusCodeAsInt(), 413);
	PTF_ASSERT_EQUAL(responseLayer->getFirstLine()->getStatusCodeString(), "This is a test");

	expectedHttpResponse = "HTTP/1.1 413 This is a test\r\nContent-Length: 345\r\n";
	PTF_ASSERT_BUF_COMPARE(expectedHttpResponse.c_str(), responseLayer->getData(), expectedHttpResponse.length());
}  // HttpResponseLayerEditTest

/// In this test the first HTTP header field is malformed - it only has header name but not an header value
PTF_TEST_CASE(HttpMalformedResponseTest)
{
	timeval time;
	gettimeofday(&time, nullptr);

	READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/HttpMalformedResponse.dat");

	pcpp::Packet httpPacket(&rawPacket1);

	pcpp::HttpResponseLayer* httpResp = httpPacket.getLayerOfType<pcpp::HttpResponseLayer>();
	PTF_ASSERT_EQUAL(httpResp->getFieldCount(), 6);
	std::string fieldNames[] = { "x-amz-request-id2 CA4DB8F36423461F\r\n", "x-amz-id-2", PCPP_HTTP_CONTENT_TYPE_FIELD,
		                         PCPP_HTTP_TRANSFER_ENCODING_FIELD,        "Date",       PCPP_HTTP_SERVER_FIELD };
	std::string fieldValues[] = { "",
		                          "xcjboWLTcibyztI2kdnRoUvPdimtSPdYQYsQ4pHAebH4miKlux4Am0SBZrvVxsHN",
		                          "application/xml",
		                          "chunked",
		                          "Thu, 21 Feb 2013 06:27:11 GMT",
		                          "AmazonS3" };
	int index = 0;
	for (pcpp::HeaderField* field = httpResp->getFirstField(); field != nullptr && !field->isEndOfHeader();
	     field = httpResp->getNextField(field))
	{
		PTF_ASSERT_EQUAL(field->getFieldName(), fieldNames[index]);
		PTF_ASSERT_EQUAL(field->getFieldValue(), fieldValues[index]);
		index++;
	}
}  // HttpMalformedResponseTest
