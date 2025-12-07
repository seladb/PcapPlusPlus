#define LOG_MODULE PacketLogModuleSipLayer

#include "SipLayer.h"
#include "SdpLayer.h"
#include "PayloadLayer.h"
#include "Logger.h"
#include "GeneralUtils.h"
#include <algorithm>
#include <exception>
#include <utility>
#include <unordered_map>

namespace pcpp
{

	const std::string SipMethodEnumToString[14] = { "INVITE", "ACK",     "BYE",       "CANCEL", "REGISTER",
		                                            "PRACK",  "OPTIONS", "SUBSCRIBE", "NOTIFY", "PUBLISH",
		                                            "INFO",   "REFER",   "MESSAGE",   "UPDATE" };

	const std::unordered_map<std::string, SipRequestLayer::SipMethod> SipMethodStringToEnum{
		{ "INVITE",    SipRequestLayer::SipMethod::SipINVITE    },
		{ "ACK",       SipRequestLayer::SipMethod::SipACK       },
		{ "BYE",       SipRequestLayer::SipMethod::SipBYE       },
		{ "CANCEL",    SipRequestLayer::SipMethod::SipCANCEL    },
		{ "REGISTER",  SipRequestLayer::SipMethod::SipREGISTER  },
		{ "PRACK",     SipRequestLayer::SipMethod::SipPRACK     },
		{ "OPTIONS",   SipRequestLayer::SipMethod::SipOPTIONS   },
		{ "SUBSCRIBE", SipRequestLayer::SipMethod::SipSUBSCRIBE },
		{ "NOTIFY",    SipRequestLayer::SipMethod::SipNOTIFY    },
		{ "PUBLISH",   SipRequestLayer::SipMethod::SipPUBLISH   },
		{ "INFO",      SipRequestLayer::SipMethod::SipINFO      },
		{ "REFER",     SipRequestLayer::SipMethod::SipREFER     },
		{ "MESSAGE",   SipRequestLayer::SipMethod::SipMESSAGE   },
		{ "UPDATE",    SipRequestLayer::SipMethod::SipUPDATE    },
	};

	// -------- Class SipLayer -----------------

	int SipLayer::getContentLength() const
	{
		std::string contentLengthFieldName(PCPP_SIP_CONTENT_LENGTH_FIELD);
		std::transform(contentLengthFieldName.begin(), contentLengthFieldName.end(), contentLengthFieldName.begin(),
		               ::tolower);
		HeaderField* contentLengthField = getFieldByName(contentLengthFieldName);
		if (contentLengthField != nullptr)
			return atoi(contentLengthField->getFieldValue().c_str());
		return 0;
	}

	HeaderField* SipLayer::setContentLength(int contentLength, const std::string& prevFieldName)
	{
		std::ostringstream contentLengthAsString;
		contentLengthAsString << contentLength;
		std::string contentLengthFieldName(PCPP_SIP_CONTENT_LENGTH_FIELD);
		HeaderField* contentLengthField = getFieldByName(contentLengthFieldName);
		if (contentLengthField == nullptr)
		{
			HeaderField* prevField = getFieldByName(prevFieldName);
			contentLengthField = insertField(prevField, PCPP_SIP_CONTENT_LENGTH_FIELD, contentLengthAsString.str());
		}
		else
			contentLengthField->setFieldValue(contentLengthAsString.str());

		return contentLengthField;
	}

	void SipLayer::parseNextLayer()
	{
		if (getLayerPayloadSize() == 0)
			return;

		size_t headerLen = getHeaderLen();
		std::string contentType;
		if (getContentLength() > 0)
		{
			HeaderField* contentTypeField = getFieldByName(PCPP_SIP_CONTENT_TYPE_FIELD);
			if (contentTypeField != nullptr)
				contentType = contentTypeField->getFieldValue();
		}

		if (contentType.find("application/sdp") != std::string::npos)
		{
			m_NextLayer = new SdpLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		}
		else
		{
			m_NextLayer = new PayloadLayer(m_Data + headerLen, m_DataLen - headerLen, this, m_Packet);
		}
	}

	void SipLayer::computeCalculateFields()
	{
		HeaderField* contentLengthField = getFieldByName(PCPP_SIP_CONTENT_LENGTH_FIELD);
		if (contentLengthField == nullptr)
			return;

		size_t headerLen = getHeaderLen();
		if (m_DataLen > headerLen)
		{
			int currentContentLength = getContentLength();
			if (currentContentLength != static_cast<int>(m_DataLen - headerLen))
				setContentLength(m_DataLen - headerLen);
		}
	}

	// -------- Class SipRequestFirstLine -----------------

	SipRequestFirstLine::SipRequestFirstLine(SipRequestLayer* sipRequest) : m_SipRequest(sipRequest)
	{
		m_Method = parseMethod(reinterpret_cast<char*>(m_SipRequest->m_Data), m_SipRequest->getDataLen());
		if (m_Method == SipRequestLayer::SipMethodUnknown)
		{
			m_UriOffset = -1;
			PCPP_LOG_DEBUG("Couldn't resolve SIP request method");
		}
		else
			m_UriOffset = SipMethodEnumToString[m_Method].length() + 1;

		parseVersion();

		char* endOfFirstLine;
		if ((endOfFirstLine =
		         static_cast<char*>(memchr(reinterpret_cast<char*>(m_SipRequest->m_Data + m_VersionOffset), '\n',
		                                   m_SipRequest->m_DataLen - static_cast<size_t>(m_VersionOffset)))) != nullptr)
		{
			m_FirstLineEndOffset = endOfFirstLine - reinterpret_cast<char*>(m_SipRequest->m_Data) + 1;
			m_IsComplete = true;
		}
		else
		{
			m_FirstLineEndOffset = m_SipRequest->getDataLen();
			m_IsComplete = false;
		}

		if (Logger::getInstance().isDebugEnabled(PacketLogModuleSipLayer))
		{
			std::string method =
			    (m_Method == SipRequestLayer::SipMethodUnknown ? "Unknown" : SipMethodEnumToString[m_Method]);
			PCPP_LOG_DEBUG("Method='" << method << "'; SIP version='" << m_Version << "'; URI='" << getUri() << "'");
		}
	}

	SipRequestFirstLine::SipRequestFirstLine(SipRequestLayer* sipRequest, SipRequestLayer::SipMethod method,
	                                         const std::string& version, const std::string& uri)
	try  // throw(SipRequestFirstLineException)
	{
		if (method == SipRequestLayer::SipMethodUnknown)
		{
			m_Exception.setMessage("Method supplied was SipMethodUnknown");
			throw m_Exception;
		}

		if (version == "")
		{
			m_Exception.setMessage("Version supplied was empty string");
			throw m_Exception;
		}

		m_SipRequest = sipRequest;

		m_Method = method;
		m_Version = version;

		std::string firstLine = SipMethodEnumToString[m_Method] + " " + uri + " " + version + "\r\n";

		m_UriOffset = SipMethodEnumToString[m_Method].length() + 1;
		m_FirstLineEndOffset = firstLine.length();
		m_VersionOffset = m_UriOffset + uri.length() + 6;

		m_SipRequest->m_DataLen = firstLine.length();
		m_SipRequest->m_Data = new uint8_t[m_SipRequest->m_DataLen];
		memcpy(m_SipRequest->m_Data, firstLine.c_str(), m_SipRequest->m_DataLen);

		m_IsComplete = true;
	}
	catch (const SipRequestFirstLineException&)
	{
		throw;
	}
	catch (...)
	{
		std::terminate();
	}

	SipRequestLayer::SipMethod SipRequestFirstLine::parseMethod(const char* data, size_t dataLen)
	{
		if (!data || dataLen < 4)
		{
			return SipRequestLayer::SipMethodUnknown;
		}

		size_t spaceIndex = 0;
		while (spaceIndex < dataLen && data[spaceIndex] != ' ')
		{
			spaceIndex++;
		}

		if (spaceIndex == 0 || spaceIndex == dataLen)
		{
			return SipRequestLayer::SipMethodUnknown;
		}

		auto methodAdEnum = SipMethodStringToEnum.find(std::string(data, data + spaceIndex));
		if (methodAdEnum == SipMethodStringToEnum.end())
		{
			return SipRequestLayer::SipMethodUnknown;
		}
		return methodAdEnum->second;
	}

	void SipRequestFirstLine::parseVersion()
	{
		if (m_SipRequest->getDataLen() < static_cast<size_t>(m_UriOffset))
		{
			m_Version = "";
			m_VersionOffset = -1;
			return;
		}

		char* data = reinterpret_cast<char*>(m_SipRequest->m_Data + m_UriOffset);
		char* verPos = cross_platform_memmem(data, m_SipRequest->getDataLen() - m_UriOffset, " SIP/", 5);
		if (verPos == nullptr)
		{
			m_Version = "";
			m_VersionOffset = -1;
			return;
		}

		// verify packet doesn't end before the version, meaning still left place for " SIP/x.y" (7 chars)
		if (static_cast<uint16_t>(verPos + 7 - reinterpret_cast<char*>(m_SipRequest->m_Data)) >
		    m_SipRequest->getDataLen())
		{
			m_Version = "";
			m_VersionOffset = -1;
			return;
		}

		// skip the space char
		verPos++;

		int endOfVerPos = 0;
		while (((verPos + endOfVerPos) < reinterpret_cast<char*>(m_SipRequest->m_Data + m_SipRequest->m_DataLen)) &&
		       ((verPos + endOfVerPos)[0] != '\r') && ((verPos + endOfVerPos)[0] != '\n'))
			endOfVerPos++;

		m_Version = std::string(verPos, endOfVerPos);

		m_VersionOffset = verPos - reinterpret_cast<char*>(m_SipRequest->m_Data);
	}

	bool SipRequestFirstLine::setMethod(SipRequestLayer::SipMethod newMethod)
	{
		if (newMethod == SipRequestLayer::SipMethodUnknown)
		{
			PCPP_LOG_ERROR("Requested method is SipMethodUnknown");
			return false;
		}

		// extend or shorten layer
		int lengthDifference = SipMethodEnumToString[newMethod].length() - SipMethodEnumToString[m_Method].length();
		if (lengthDifference > 0)
		{
			if (!m_SipRequest->extendLayer(0, lengthDifference))
			{
				PCPP_LOG_ERROR("Cannot change layer size");
				return false;
			}
		}
		else if (lengthDifference < 0)
		{
			if (!m_SipRequest->shortenLayer(0, 0 - lengthDifference))
			{
				PCPP_LOG_ERROR("Cannot change layer size");
				return false;
			}
		}

		if (lengthDifference != 0)
		{
			m_SipRequest->shiftFieldsOffset(m_SipRequest->getFirstField(), lengthDifference);
			m_SipRequest->m_FieldsOffset += lengthDifference;
		}

		memcpy(m_SipRequest->m_Data, SipMethodEnumToString[newMethod].c_str(),
		       SipMethodEnumToString[newMethod].length());

		m_UriOffset += lengthDifference;
		m_VersionOffset += lengthDifference;
		m_FirstLineEndOffset += lengthDifference;

		m_Method = newMethod;

		return true;
	}

	std::string SipRequestFirstLine::getUri() const
	{
		std::string result;
		if (m_UriOffset != -1 && m_VersionOffset != -1)
			result.assign(reinterpret_cast<char*>(m_SipRequest->m_Data + m_UriOffset),
			              m_VersionOffset - 1 - m_UriOffset);

		// else first line is illegal, return empty string

		return result;
	}

	bool SipRequestFirstLine::setUri(const std::string& newUri)
	{
		if (newUri == "")
		{
			PCPP_LOG_ERROR("URI cannot be empty");
			return false;
		}

		// extend or shorten layer
		std::string currentUri = getUri();
		int lengthDifference = newUri.length() - currentUri.length();
		if (lengthDifference > 0)
		{
			if (!m_SipRequest->extendLayer(m_UriOffset, lengthDifference))
			{
				PCPP_LOG_ERROR("Cannot change layer size");
				return false;
			}
		}
		else if (lengthDifference < 0)
		{
			if (!m_SipRequest->shortenLayer(m_UriOffset, 0 - lengthDifference))
			{
				PCPP_LOG_ERROR("Cannot change layer size");
				return false;
			}
		}

		if (lengthDifference != 0)
		{
			m_SipRequest->shiftFieldsOffset(m_SipRequest->getFirstField(), lengthDifference);
			m_SipRequest->m_FieldsOffset += lengthDifference;
		}

		memcpy(m_SipRequest->m_Data + m_UriOffset, newUri.c_str(), newUri.length());

		m_VersionOffset += lengthDifference;
		m_FirstLineEndOffset += lengthDifference;

		return true;
	}

	// -------- Class SipRequestLayer -----------------

	SipRequestLayer::SipRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : SipLayer(data, dataLen, prevLayer, packet, SIPRequest)
	{
		m_FirstLine = new SipRequestFirstLine(this);
		m_FieldsOffset = m_FirstLine->getSize();
		parseFields();
	}

	SipRequestLayer::SipRequestLayer(SipMethod method, const std::string& requestUri, const std::string& version)
	{
		m_Protocol = SIPRequest;
		m_FirstLine = new SipRequestFirstLine(this, method, version, requestUri);
		m_FieldsOffset = m_FirstLine->getSize();
	}

	SipRequestLayer::SipRequestLayer(const SipRequestLayer& other) : SipLayer(other)
	{
		m_FirstLine = new SipRequestFirstLine(this);
	}

	SipRequestLayer& SipRequestLayer::operator=(const SipRequestLayer& other)
	{
		SipLayer::operator=(other);

		if (m_FirstLine != nullptr)
			delete m_FirstLine;

		m_FirstLine = new SipRequestFirstLine(this);

		return *this;
	}

	SipRequestLayer::~SipRequestLayer()
	{
		delete m_FirstLine;
	}

	std::string SipRequestLayer::toString() const
	{
		static const int maxLengthToPrint = 120;
		std::string result = "SIP request, ";
		int size = m_FirstLine->getSize() - 2;  // the -2 is to remove \r\n at the end of the first line
		if (size <= 0)
		{
			result += std::string("CORRUPT DATA");
			return result;
		}
		if (size <= maxLengthToPrint)
		{
			char* firstLine = new char[size + 1];
			strncpy(firstLine, reinterpret_cast<char*>(m_Data), size);
			firstLine[size] = 0;
			result += std::string(firstLine);
			delete[] firstLine;
		}
		else
		{
			char firstLine[maxLengthToPrint + 1];
			strncpy(firstLine, reinterpret_cast<char*>(m_Data), maxLengthToPrint - 3);
			firstLine[maxLengthToPrint - 3] = '.';
			firstLine[maxLengthToPrint - 2] = '.';
			firstLine[maxLengthToPrint - 1] = '.';
			firstLine[maxLengthToPrint] = 0;
			result += std::string(firstLine);
		}

		return result;
	}

	// -------- Class SipResponseLayer -----------------

	const std::string StatusCodeEnumToString[77] = { "Trying",
		                                             "Ringing",
		                                             "Call is Being Forwarded",
		                                             "Queued",
		                                             "Session in Progress",
		                                             "Early Dialog Terminated",
		                                             "OK",
		                                             "Accepted",
		                                             "No Notification",
		                                             "Multiple Choices",
		                                             "Moved Permanently",
		                                             "Moved Temporarily",
		                                             "Use Proxy",
		                                             "Alternative Service",
		                                             "Bad Request",
		                                             "Unauthorized",
		                                             "Payment Required",
		                                             "Forbidden",
		                                             "Not Found",
		                                             "Method Not Allowed",
		                                             "Not Acceptable",
		                                             "Proxy Authentication Required",
		                                             "Request Timeout",
		                                             "Conflict",
		                                             "Gone",
		                                             "Length Required",
		                                             "Conditional Request Failed",
		                                             "Request Entity Too Large",
		                                             "Request-URI Too Long",
		                                             "Unsupported Media Type",
		                                             "Unsupported URI Scheme",
		                                             "Unknown Resource-Priority",
		                                             "Bad Extension",
		                                             "Extension Required",
		                                             "Session Interval Too Small",
		                                             "Interval Too Brief",
		                                             "Bad Location Information",
		                                             "Bad Alert Message",
		                                             "Use Identity Header",
		                                             "Provide Referrer Identity",
		                                             "Flow Failed",
		                                             "Anonymity Disallowed",
		                                             "Bad Identity-Info",
		                                             "Unsupported Certificate",
		                                             "Invalid Identity Header",
		                                             "First Hop Lacks Outbound Support",
		                                             "Max-Breadth Exceeded",
		                                             "Bad Info Package",
		                                             "Consent Needed",
		                                             "Temporarily Unavailable",
		                                             "Call_Transaction Does Not Exist",
		                                             "Loop Detected",
		                                             "Too Many Hops",
		                                             "Address Incomplete",
		                                             "Ambiguous",
		                                             "Busy Here",
		                                             "Request Terminated",
		                                             "Not Acceptable Here",
		                                             "Bad Event",
		                                             "Request Pending",
		                                             "Undecipherable",
		                                             "Security Agreement Required",
		                                             "Server Internal Error",
		                                             "Not Implemented",
		                                             "Bad Gateway",
		                                             "Service Unavailable",
		                                             "Server Timeout",
		                                             "Version Not Supported",
		                                             "Message Too Large",
		                                             "Push Notification Service Not Supported",
		                                             "Precondition Failure",
		                                             "Busy Everywhere",
		                                             "Decline",
		                                             "Does Not Exist Anywhere",
		                                             "Not Acceptable",
		                                             "Unwanted",
		                                             "Rejected" };

	const int StatusCodeEnumToInt[77] = { 100, 180, 181, 182, 183, 199, 200, 202, 204, 300, 301, 302, 305,
		                                  380, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411,
		                                  412, 413, 414, 415, 416, 417, 420, 421, 422, 425, 423, 424, 428,
		                                  429, 430, 433, 436, 437, 438, 439, 440, 469, 470, 480, 481, 482,
		                                  483, 484, 485, 486, 487, 488, 489, 491, 493, 494, 500, 501, 502,
		                                  503, 504, 505, 513, 555, 580, 600, 603, 604, 606, 607, 608 };

	const std::unordered_map<std::string, SipResponseLayer::SipResponseStatusCode> StatusCodeStringToEnumMap{
		{ "100", SipResponseLayer::SipResponseStatusCode::Sip100Trying                              },
		{ "180", SipResponseLayer::SipResponseStatusCode::Sip180Ringing                             },
		{ "181", SipResponseLayer::SipResponseStatusCode::Sip181CallisBeingForwarded                },
		{ "182", SipResponseLayer::SipResponseStatusCode::Sip182Queued                              },
		{ "183", SipResponseLayer::SipResponseStatusCode::Sip183SessioninProgress                   },
		{ "199", SipResponseLayer::SipResponseStatusCode::Sip199EarlyDialogTerminated               },
		{ "200", SipResponseLayer::SipResponseStatusCode::Sip200OK                                  },
		{ "202", SipResponseLayer::SipResponseStatusCode::Sip202Accepted                            },
		{ "204", SipResponseLayer::SipResponseStatusCode::Sip204NoNotification                      },
		{ "300", SipResponseLayer::SipResponseStatusCode::Sip300MultipleChoices                     },
		{ "301", SipResponseLayer::SipResponseStatusCode::Sip301MovedPermanently                    },
		{ "302", SipResponseLayer::SipResponseStatusCode::Sip302MovedTemporarily                    },
		{ "305", SipResponseLayer::SipResponseStatusCode::Sip305UseProxy                            },
		{ "380", SipResponseLayer::SipResponseStatusCode::Sip380AlternativeService                  },
		{ "400", SipResponseLayer::SipResponseStatusCode::Sip400BadRequest                          },
		{ "401", SipResponseLayer::SipResponseStatusCode::Sip401Unauthorized                        },
		{ "402", SipResponseLayer::SipResponseStatusCode::Sip402PaymentRequired                     },
		{ "403", SipResponseLayer::SipResponseStatusCode::Sip403Forbidden                           },
		{ "404", SipResponseLayer::SipResponseStatusCode::Sip404NotFound                            },
		{ "405", SipResponseLayer::SipResponseStatusCode::Sip405MethodNotAllowed                    },
		{ "406", SipResponseLayer::SipResponseStatusCode::Sip406NotAcceptable                       },
		{ "407", SipResponseLayer::SipResponseStatusCode::Sip407ProxyAuthenticationRequired         },
		{ "408", SipResponseLayer::SipResponseStatusCode::Sip408RequestTimeout                      },
		{ "409", SipResponseLayer::SipResponseStatusCode::Sip409Conflict                            },
		{ "410", SipResponseLayer::SipResponseStatusCode::Sip410Gone                                },
		{ "411", SipResponseLayer::SipResponseStatusCode::Sip411LengthRequired                      },
		{ "412", SipResponseLayer::SipResponseStatusCode::Sip412ConditionalRequestFailed            },
		{ "413", SipResponseLayer::SipResponseStatusCode::Sip413RequestEntityTooLarge               },
		{ "414", SipResponseLayer::SipResponseStatusCode::Sip414RequestURITooLong                   },
		{ "415", SipResponseLayer::SipResponseStatusCode::Sip415UnsupportedMediaType                },
		{ "416", SipResponseLayer::SipResponseStatusCode::Sip416UnsupportedURIScheme                },
		{ "417", SipResponseLayer::SipResponseStatusCode::Sip417UnknownResourcePriority             },
		{ "420", SipResponseLayer::SipResponseStatusCode::Sip420BadExtension                        },
		{ "421", SipResponseLayer::SipResponseStatusCode::Sip421ExtensionRequired                   },
		{ "422", SipResponseLayer::SipResponseStatusCode::Sip422SessionIntervalTooSmall             },
		{ "423", SipResponseLayer::SipResponseStatusCode::Sip423IntervalTooBrief                    },
		{ "424", SipResponseLayer::SipResponseStatusCode::Sip424BadLocationInformation              },
		{ "425", SipResponseLayer::SipResponseStatusCode::Sip425BadAlertMessage                     },
		{ "428", SipResponseLayer::SipResponseStatusCode::Sip428UseIdentityHeader                   },
		{ "429", SipResponseLayer::SipResponseStatusCode::Sip429ProvideReferrerIdentity             },
		{ "430", SipResponseLayer::SipResponseStatusCode::Sip430FlowFailed                          },
		{ "433", SipResponseLayer::SipResponseStatusCode::Sip433AnonymityDisallowed                 },
		{ "436", SipResponseLayer::SipResponseStatusCode::Sip436BadIdentityInfo                     },
		{ "437", SipResponseLayer::SipResponseStatusCode::Sip437UnsupportedCertificate              },
		{ "438", SipResponseLayer::SipResponseStatusCode::Sip438InvalidIdentityHeader               },
		{ "439", SipResponseLayer::SipResponseStatusCode::Sip439FirstHopLacksOutboundSupport        },
		{ "440", SipResponseLayer::SipResponseStatusCode::Sip440MaxBreadthExceeded                  },
		{ "469", SipResponseLayer::SipResponseStatusCode::Sip469BadInfoPackage                      },
		{ "470", SipResponseLayer::SipResponseStatusCode::Sip470ConsentNeeded                       },
		{ "480", SipResponseLayer::SipResponseStatusCode::Sip480TemporarilyUnavailable              },
		{ "481", SipResponseLayer::SipResponseStatusCode::Sip481Call_TransactionDoesNotExist        },
		{ "482", SipResponseLayer::SipResponseStatusCode::Sip482LoopDetected                        },
		{ "483", SipResponseLayer::SipResponseStatusCode::Sip483TooManyHops                         },
		{ "484", SipResponseLayer::SipResponseStatusCode::Sip484AddressIncomplete                   },
		{ "485", SipResponseLayer::SipResponseStatusCode::Sip485Ambiguous                           },
		{ "486", SipResponseLayer::SipResponseStatusCode::Sip486BusyHere                            },
		{ "487", SipResponseLayer::SipResponseStatusCode::Sip487RequestTerminated                   },
		{ "488", SipResponseLayer::SipResponseStatusCode::Sip488NotAcceptableHere                   },
		{ "489", SipResponseLayer::SipResponseStatusCode::Sip489BadEvent                            },
		{ "491", SipResponseLayer::SipResponseStatusCode::Sip491RequestPending                      },
		{ "493", SipResponseLayer::SipResponseStatusCode::Sip493Undecipherable                      },
		{ "494", SipResponseLayer::SipResponseStatusCode::Sip494SecurityAgreementRequired           },
		{ "500", SipResponseLayer::SipResponseStatusCode::Sip500ServerInternalError                 },
		{ "501", SipResponseLayer::SipResponseStatusCode::Sip501NotImplemented                      },
		{ "502", SipResponseLayer::SipResponseStatusCode::Sip502BadGateway                          },
		{ "503", SipResponseLayer::SipResponseStatusCode::Sip503ServiceUnavailable                  },
		{ "504", SipResponseLayer::SipResponseStatusCode::Sip504ServerTimeout                       },
		{ "505", SipResponseLayer::SipResponseStatusCode::Sip505VersionNotSupported                 },
		{ "513", SipResponseLayer::SipResponseStatusCode::Sip513MessageTooLarge                     },
		{ "555", SipResponseLayer::SipResponseStatusCode::Sip555PushNotificationServiceNotSupported },
		{ "580", SipResponseLayer::SipResponseStatusCode::Sip580PreconditionFailure                 },
		{ "600", SipResponseLayer::SipResponseStatusCode::Sip600BusyEverywhere                      },
		{ "603", SipResponseLayer::SipResponseStatusCode::Sip603Decline                             },
		{ "604", SipResponseLayer::SipResponseStatusCode::Sip604DoesNotExistAnywhere                },
		{ "606", SipResponseLayer::SipResponseStatusCode::Sip606NotAcceptable                       },
		{ "607", SipResponseLayer::SipResponseStatusCode::Sip607Unwanted                            },
		{ "608", SipResponseLayer::SipResponseStatusCode::Sip608Rejected                            },
	};

	SipResponseLayer::SipResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : SipLayer(data, dataLen, prevLayer, packet, SIPResponse)
	{
		m_FirstLine = new SipResponseFirstLine(this);
		m_FieldsOffset = m_FirstLine->getSize();
		parseFields();
	}

	SipResponseLayer::SipResponseLayer(SipResponseLayer::SipResponseStatusCode statusCode, std::string statusCodeString,
	                                   const std::string& sipVersion)
	{
		m_Protocol = SIPResponse;
		m_FirstLine = new SipResponseFirstLine(this, sipVersion, statusCode, std::move(statusCodeString));
		m_FieldsOffset = m_FirstLine->getSize();
	}

	SipResponseLayer::~SipResponseLayer()
	{
		delete m_FirstLine;
	}

	SipResponseLayer::SipResponseLayer(const SipResponseLayer& other) : SipLayer(other)
	{
		m_FirstLine = new SipResponseFirstLine(this);
	}

	SipResponseLayer& SipResponseLayer::operator=(const SipResponseLayer& other)
	{
		SipLayer::operator=(other);

		if (m_FirstLine != nullptr)
			delete m_FirstLine;

		m_FirstLine = new SipResponseFirstLine(this);

		return *this;
	}

	std::string SipResponseLayer::toString() const
	{
		static const int maxLengthToPrint = 120;
		std::string result = "SIP response, ";
		int size = m_FirstLine->getSize() - 2;  // the -2 is to remove \r\n at the end of the first line
		if (size <= 0)
		{
			result += std::string("CORRUPT DATA");
			return result;
		}
		if (size <= maxLengthToPrint)
		{
			char* firstLine = new char[size + 1];
			strncpy(firstLine, reinterpret_cast<char*>(m_Data), size);
			firstLine[size] = 0;
			result += std::string(firstLine);
			delete[] firstLine;
		}
		else
		{
			char firstLine[maxLengthToPrint + 1];
			strncpy(firstLine, reinterpret_cast<char*>(m_Data), maxLengthToPrint - 3);
			firstLine[maxLengthToPrint - 3] = '.';
			firstLine[maxLengthToPrint - 2] = '.';
			firstLine[maxLengthToPrint - 1] = '.';
			firstLine[maxLengthToPrint] = 0;
			result += std::string(firstLine);
		}

		return result;
	}

	// -------- Class SipResponseFirstLine -----------------

	int SipResponseFirstLine::getStatusCodeAsInt() const
	{
		return StatusCodeEnumToInt[m_StatusCode];
	}

	std::string SipResponseFirstLine::getStatusCodeString() const
	{
		std::string result;
		const int statusStringOffset = 12;
		if (m_StatusCode != SipResponseLayer::SipStatusCodeUnknown)
		{
			int statusStringEndOffset = m_FirstLineEndOffset - 2;
			if ((*(m_SipResponse->m_Data + statusStringEndOffset)) != '\r')
				statusStringEndOffset++;
			result.assign(reinterpret_cast<char*>(m_SipResponse->m_Data + statusStringOffset),
			              statusStringEndOffset - statusStringOffset);
		}

		// else first line is illegal, return empty string

		return result;
	}

	bool SipResponseFirstLine::setStatusCode(SipResponseLayer::SipResponseStatusCode newStatusCode,
	                                         std::string statusCodeString)
	{
		if (newStatusCode == SipResponseLayer::SipStatusCodeUnknown)
		{
			PCPP_LOG_ERROR("Requested status code is SipStatusCodeUnknown");
			return false;
		}

		// extend or shorten layer

		size_t statusStringOffset = 12;
		if (statusCodeString == "")
			statusCodeString = StatusCodeEnumToString[newStatusCode];
		int lengthDifference = statusCodeString.length() - getStatusCodeString().length();

		if (lengthDifference > 0)
		{
			if (!m_SipResponse->extendLayer(statusStringOffset, lengthDifference))
			{
				PCPP_LOG_ERROR("Cannot change layer size");
				return false;
			}
		}
		else if (lengthDifference < 0)
		{
			if (!m_SipResponse->shortenLayer(statusStringOffset, 0 - lengthDifference))
			{
				PCPP_LOG_ERROR("Cannot change layer size");
				return false;
			}
		}

		if (lengthDifference != 0)
		{
			m_SipResponse->shiftFieldsOffset(m_SipResponse->getFirstField(), lengthDifference);
			m_SipResponse->m_FieldsOffset += lengthDifference;
		}

		// copy status string
		memcpy(m_SipResponse->m_Data + statusStringOffset, statusCodeString.c_str(), statusCodeString.length());

		// change status code
		std::ostringstream statusCodeAsString;
		statusCodeAsString << StatusCodeEnumToInt[newStatusCode];
		memcpy(m_SipResponse->m_Data + 8, statusCodeAsString.str().c_str(), 3);

		m_StatusCode = newStatusCode;
		m_FirstLineEndOffset += lengthDifference;

		return true;
	}

	void SipResponseFirstLine::setVersion(const std::string& newVersion)
	{
		if (newVersion == "")
			return;

		if (newVersion.length() != m_Version.length())
		{
			PCPP_LOG_ERROR("Expected version length is " << m_Version.length()
			                                             << " characters in the format of SIP/x.y");
			return;
		}

		char* verPos = reinterpret_cast<char*>(m_SipResponse->m_Data);
		memcpy(verPos, newVersion.c_str(), newVersion.length());
		m_Version = newVersion;
	}

	SipResponseLayer::SipResponseStatusCode SipResponseFirstLine::parseStatusCode(const char* data, size_t dataLen)
	{
		// minimum data should be 12B long: "SIP/x.y XXX "
		if (!data || dataLen < 12)
		{
			return SipResponseLayer::SipStatusCodeUnknown;
		}

		const char* statusCodeData = data + 8;
		if (statusCodeData[3] != ' ')
		{
			return SipResponseLayer::SipStatusCodeUnknown;
		}

		auto codeAsEnum = StatusCodeStringToEnumMap.find(std::string(statusCodeData, 3));
		if (codeAsEnum == StatusCodeStringToEnumMap.end())
		{
			return SipResponseLayer::SipStatusCodeUnknown;
		}
		return codeAsEnum->second;
	}

	SipResponseFirstLine::SipResponseFirstLine(SipResponseLayer* sipResponse) : m_SipResponse(sipResponse)
	{
		m_Version = parseVersion(reinterpret_cast<char*>(m_SipResponse->m_Data), m_SipResponse->getDataLen());
		if (m_Version == "")
		{
			m_StatusCode = SipResponseLayer::SipStatusCodeUnknown;
		}
		else
		{
			m_StatusCode = parseStatusCode(reinterpret_cast<char*>(m_SipResponse->m_Data), m_SipResponse->getDataLen());
		}

		char* endOfFirstLine;
		if ((endOfFirstLine = static_cast<char*>(
		         memchr(reinterpret_cast<char*>(m_SipResponse->m_Data), '\n', m_SipResponse->m_DataLen))) != nullptr)
		{
			m_FirstLineEndOffset = endOfFirstLine - reinterpret_cast<char*>(m_SipResponse->m_Data) + 1;
			m_IsComplete = true;
		}
		else
		{
			m_FirstLineEndOffset = m_SipResponse->getDataLen();
			m_IsComplete = false;
		}

		if (Logger::getInstance().isDebugEnabled(PacketLogModuleSipLayer))
		{
			int statusCode =
			    (m_StatusCode == SipResponseLayer::SipStatusCodeUnknown ? 0 : StatusCodeEnumToInt[m_StatusCode]);
			PCPP_LOG_DEBUG("Version='" << m_Version << "'; Status code=" << statusCode << " '" << getStatusCodeString()
			                           << "'");
		}
	}

	SipResponseFirstLine::SipResponseFirstLine(SipResponseLayer* sipResponse, const std::string& version,
	                                           SipResponseLayer::SipResponseStatusCode statusCode,
	                                           std::string statusCodeString)
	{
		if (statusCode == SipResponseLayer::SipStatusCodeUnknown)
		{
			m_Exception.setMessage("Status code supplied was SipStatusCodeUnknown");
			throw m_Exception;
		}

		if (version == "")
		{
			m_Exception.setMessage("Version supplied was unknown");
			throw m_Exception;
		}

		m_SipResponse = sipResponse;

		m_StatusCode = statusCode;
		m_Version = version;

		std::ostringstream statusCodeAsString;
		statusCodeAsString << StatusCodeEnumToInt[m_StatusCode];
		if (statusCodeString == "")
			statusCodeString = StatusCodeEnumToString[m_StatusCode];
		std::string firstLine = m_Version + " " + statusCodeAsString.str() + " " + statusCodeString + "\r\n";

		m_FirstLineEndOffset = firstLine.length();

		m_SipResponse->m_DataLen = firstLine.length();
		m_SipResponse->m_Data = new uint8_t[m_SipResponse->m_DataLen];
		memcpy(m_SipResponse->m_Data, firstLine.c_str(), m_SipResponse->m_DataLen);

		m_IsComplete = true;
	}

	std::string SipResponseFirstLine::parseVersion(const char* data, size_t dataLen)
	{
		if (!data || dataLen < 8)  // "SIP/x.y "
		{
			PCPP_LOG_DEBUG("SIP response length < 8, cannot identify version");
			return "";
		}

		if (data[0] != 'S' || data[1] != 'I' || data[2] != 'P' || data[3] != '/')
		{
			PCPP_LOG_DEBUG("SIP response does not begin with 'SIP/'");
			return "";
		}

		const char* nextSpace = static_cast<const char*>(memchr(data, ' ', dataLen));
		if (nextSpace == nullptr)
			return "";

		return std::string(data, nextSpace - data);
	}

}  // namespace pcpp
