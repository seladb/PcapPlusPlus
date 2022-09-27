#define LOG_MODULE PacketLogModuleReassembly

#include "Reassembly.h"
#include "Layer.h"
#include "ProtocolType.h"
#include <iostream>
#include <sstream>
#include <stack>
#include <string>

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
// TODO: error handling
ReassemblyStatus ReassembleMessage(Layer *layer, std::string tuple, void *cookie,
								   OnMessageHandled OnMessageHandledCallback)
{
	ReassemblyStatus response = Handled;
	std::string result = "";

	// use stack to store messages;
	// print from back to front
	// then pop and <<
	std::stack<std::string> stk;
	std::string temp = "";

	// parse to datalink layer
	while (layer != NULL && (layer->getOsiModelLayer() > OsiModelDataLinkLayer ||
							 layer->getProtocol() == pcpp::PPP_PPTP || layer->getProtocol() == pcpp::L2TP))
	{
		// TODO(ycyaoxdu): this line is use to debug, need to remove
		std::cout << "!" << layer->getOsiModelLayer() << "!" << std::hex << layer->getProtocol() << std::oct << "!"
				  << std::endl;

		temp = layer->toString();
		stk.push(temp);
		layer = layer->getPrevLayer();
	}
	std::cout << std::endl;

	while (!stk.empty())
	{
		temp = stk.top();
		stk.pop();

		result += temp;
	}

	if (response == Handled)
	{
		// call the callback to write result
		OnMessageHandledCallback(&result, tuple, cookie);
	}

	return response;
}

} // namespace pcpp
