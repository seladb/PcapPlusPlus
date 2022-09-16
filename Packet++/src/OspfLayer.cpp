#define LOG_MODULE PacketLogModuleOspfLayer

#include "OspfLayer.h"
#include "EndianPortable.h"
#include "Logger.h"
#include "PacketUtils.h"
#include "GeneralUtils.h"
#include <sstream>
#include <string.h>

namespace pcpp
{
//------------------------HelloContent------------------------------------------

HelloContent::HelloContent(std::istream& is, uint16_t len)
{
    is.read((char*)&header, sizeof(HelloHeader));
    mask = arr2num(header.mask, 4);
    dr   = arr2num(header.d_router, 4);
    br   = arr2num(header.b_router, 4);
    len  = len - sizeof(HelloHeader);
    while (len != 0)
    {
        uint8_t nei[4];
        is.read((char*)nei, 4);
        neighbors.push_back(arr2num(nei, 4));
        len = len - 4;
    }
    nr_num = neighbors.size();
}

void HelloContent::Print(std::ostream& os)
{
    os << '\t' << "HelloContent:" << '\n';
    os << "\t\t"
       << "mask: " << num2ip(mask) << '\n';
    os << "\t\t"
       << "designated router: " << num2ip(dr) << '\n';
    os << "\t\t"
       << "backup designated router: " << num2ip(br) << '\n';
    for (auto& var : neighbors)
    {
        os << "\t\t"
           << "active neighbor: " << num2ip(var) << '\n';
    }
}

bool HelloContent::IsAvailable()
{
    return true;
}

uint32_t HelloContent::get_mask()
{
    return mask;
}
uint32_t HelloContent::get_dr()
{
    return dr;
}
uint32_t HelloContent::get_br()
{
    return br;
}
uint32_t HelloContent::get_nr_num()
{
    return nr_num;
}
uint32_t HelloContent::get_nr(uint32_t index)
{
    return neighbors[index];
}

//--------------------------------Lsa-------------------------------------------

Lsa::Lsa(std::istream& is)
{
    is.read((char*)&header, sizeof(LsaHeader));
    lsa_type   = header.lsa_type;
    state_id   = arr2num(header.state_id, 4);
    adv_router = arr2num(header.adv_router, 4);
    tlen       = ntohs(header.tlen);
}

uint8_t Lsa::get_type()
{
    return lsa_type;
}
uint32_t Lsa::get_state_id()
{
    return state_id;
}
uint32_t Lsa::get_adv_router()
{
    return adv_router;
}
uint16_t Lsa::get_tlen()
{
    return tlen;
}

//--------------------------RouterLsa-------------------------------------------

RouterLsaContent::RouterLsaContent(std::istream& is)
{
    uint8_t arr[4];
    is.read((char*)&arr, 4);
    link_id = arr2num(arr, 4);
    is.read((char*)&arr, 4);
    link_data = arr2num(arr, 4);
    is.read((char*)&link_type, 1);
    is.read((char*)&tos_num, 1);
    is.read((char*)&tos0_metric, 2);
    tos0_metric = ntohs(tos0_metric);
    uint8_t num = tos_num;
    while (num != 0)
    {
        // 8bit: tos; 8bit: reserve; 16bit tos_metric. 可以没有。
        //数组的第一元素的值等于tos的值，因为保留字节通常为0，再加上网络字节顺序。
        //数组的第二元素的值还需要字节顺序转换。
        uint16_t temp_tos[2];
        is.read((char*)&temp_tos, 4);
        toses.push_back({temp_tos[0], ntohs(temp_tos[1])});
        --num;
    }
}

void RouterLsaContent::Print(std::ostream& os)
{
    if (link_type == 1)  //点对点
    {
        os << "\t\t\t"
           << "p2p link:" << '\n';
        os << "\t\t\t\t"
           << "link id(neighbor): " << num2ip(link_id) << '\n';
        os << "\t\t\t\t"
           << "link data(interface num): " << link_data << '\n';
    }
    else if (link_type == 2)  //穿越
    {
        os << "\t\t\t"
           << "transit link:" << '\n';
        os << "\t\t\t\t"
           << "link id(designated router): " << num2ip(link_id) << '\n';
        os << "\t\t\t\t"
           << "link(router ip): " << num2ip(link_data) << '\n';
    }
    else if (link_type == 3)  //残桩
    {
        os << "\t\t\t"
           << "stub link:" << '\n';
        os << "\t\t\t\t"
           << "link id(network ip): " << num2ip(link_id) << '\n';
        os << "\t\t\t\t"
           << "link data(network mask): " << num2ip(link_data) << '\n';
    }
    else if (link_type == 4)  //虚拟
    {
        os << "\t\t\t"
           << "virtual link:" << '\n';
        os << "\t\t\t\t"
           << "link id(neighbor): " << num2ip(link_id) << '\n';
        os << "\t\t\t\t"
           << "link data(router ip): " << num2ip(link_data) << '\n';
    }

    os << "\t\t\t\t"
       << "link type: " << (uint16_t)link_type << '\n';
    os << "\t\t\t\t"
       << "number of tos: " << (uint16_t)tos_num << '\n';
    os << "\t\t\t\t"
       << "tos0 metric: " << tos0_metric << '\n';
    for (auto& var : toses)
    {
        os << "\t\t\t\t"
           << "tos -- metric: " << var[0] << "--" << var[1] << '\n';
    }
}

uint32_t RouterLsaContent::get_link_id()
{
    return link_id;
}
uint32_t RouterLsaContent::get_link_data()
{
    return link_data;
}
uint8_t RouterLsaContent::get_link_type()
{
    return link_type;
}
uint8_t RouterLsaContent::get_tos_num()
{
    return tos_num;
}
uint16_t RouterLsaContent::get_tos0_metric()
{
    return tos0_metric;
}
std::vector<uint16_t> RouterLsaContent::get_tos(uint8_t index)
{
    return toses[index];
}

RouterLsa::RouterLsa(std::istream& is) : Lsa(is)
{
    is.read((char*)&options, 2);
    options = ntohs(options);
    is.read((char*)&link_num, 2);
    link_num          = ntohs(link_num);
    uint16_t temp_num = link_num;
    while (temp_num != 0)
    {
        auto content = std::make_shared<RouterLsaContent>(is);
        contents.push_back(content);
        --temp_num;
    }
}

void RouterLsa::Print(std::ostream& os)
{
    os << "\t\t"
       << "RouterLsa:" << '\n';
    os << "\t\t\t"
       << "lsa type: " << (uint16_t)lsa_type << '\n';
    os << "\t\t\t"
       << "link state id: " << num2ip(state_id) << '\n';
    os << "\t\t\t"
       << "advertising router: " << num2ip(adv_router) << '\n';
    os << "\t\t\t"
       << "total length: " << tlen << '\n';
    os << "\t\t\t"
       << "number of links: " << link_num << '\n';
    for (auto& var : contents)
    {
        var->Print(os);
    }
}

uint16_t RouterLsa::get_num()
{
    return link_num;
}
std::shared_ptr<RouterLsaContent> RouterLsa::get_content(uint16_t index)
{
    return contents[index];
}

//----------------------------NetworkLsa----------------------------------------

NetworkLsa::NetworkLsa(std::istream& is) : Lsa(is)
{
    uint16_t len = tlen - sizeof(LsaHeader);
    uint8_t  arr[4];
    is.read((char*)&arr, 4);
    mask = arr2num(arr, 4);
    len  = len - 4;
    while (len != 0)
    {
        is.read((char*)&arr, 4);
        attach_routers.push_back(arr2num(arr, 4));
        len = len - 4;
    }
    attach_num = attach_routers.size();
}

void NetworkLsa::Print(std::ostream& os)
{
    os << "\t\t"
       << "NetworkLsa:" << '\n';
    os << "\t\t\t"
       << "lsa type: " << (uint16_t)lsa_type << '\n';
    os << "\t\t\t"
       << "link state id: " << num2ip(state_id) << '\n';
    os << "\t\t\t"
       << "advertising router: " << num2ip(adv_router) << '\n';
    os << "\t\t\t"
       << "total length: " << tlen << '\n';
    os << "\t\t\t"
       << "netmask: " << num2ip(mask) << '\n';
    for (auto& var : attach_routers)
    {
        os << "\t\t\t"
           << "attach_router: " << var << '\n';
    }
}

uint32_t NetworkLsa::get_mask()
{
    return mask;
}
uint32_t NetworkLsa::get_attach_num()
{
    return attach_num;
}
uint32_t NetworkLsa::get_attach_router(uint32_t index)
{
    return attach_routers[index];
}

//------------------------------LsuContent--------------------------------------

LsuContent::LsuContent(std::istream& is)
{
    is.read((char*)&lsa_num, 4);
    lsa_num      = ntohl(lsa_num);
    uint32_t num = lsa_num;
    while (num != 0)
    {
        //取得lsa的type并将istream恢复位置
        LsaHeader temp_header;
        auto      pos = is.tellg();
        is.read((char*)&temp_header, sizeof(LsaHeader));
        uint8_t lsa_type = temp_header.lsa_type;
        is.seekg(pos);

        //根据type创建不同的lsa
        if (lsa_type == 1)  // router-lsa
        {
            auto lsa = std::make_shared<RouterLsa>(is);
            lsas.push_back(lsa);
        }
        else if (lsa_type == 2)  // network-lsa
        {
            auto lsa = std::make_shared<NetworkLsa>(is);
            lsas.push_back(lsa);
        }
        else  //其他lsa跳过 TODO
        {
            // std::cout << "ignore other lsa -- type: " << (uint16_t)lsa_type
            // << '\n';
            is.seekg(temp_header.tlen, std::ios::cur);
        }

        --num;
    }
}

void LsuContent::Print(std::ostream& os)
{
    os << '\t' << "LsuContent:" << '\n';
    os << "\t\t"
       << "num of lsas: " << lsa_num << '\n';
    for (auto& var : lsas)
    {
        var->Print(os);
    }
}

bool LsuContent::IsAvailable()
{
    if (lsas.size() != 0)
    {
        return true;
    }
    return false;
}

uint32_t LsuContent::get_lsa_num()
{
    return lsa_num;
}
std::shared_ptr<Lsa> LsuContent::get_lsa(uint32_t index)
{
    return lsas[index];
}

//--------------------------OspfLayer------------------------------------------

bool OspfLayer::IsComplete()
{
    if (m_content != nullptr && m_content->IsAvailable())
    {
        return true;
    }
    return false;
}
uint8_t OspfLayer::getVersion() const
{
    return m_header->version;
}
uint8_t OspfLayer::getType() const
{
    return m_type;
}
uint32_t OspfLayer::getSrcRouter() const
{
    return m_src_router;
}
uint32_t OspfLayer::getArea() const
{
    return m_area;
}
std::shared_ptr<OspfContent> OspfLayer::getContent()
{
    return m_content;
}

void OspfLayer::ToStructuredOutput(std::ostream &os) const
{
	os << "Ospf Packet:" << '\n';
    os << '\t' << "ospfhdr: " << '\n';
    os << "\t\t"
       << "total length: " << getDataLen() << '\n';
    os << "\t\t"
       << "source router: " << num2ip(getSrcRouter()) << '\n';
    os << "\t\t"
       << "area id: " << num2ip(getArea()) << '\n';
    if (m_content != nullptr)
    {
        m_content->Print(os);
    }
    os << std::endl;
}

void OspfLayer::computeCalculateFields()
{
    m_header = (ospfhdr *)m_Data;
    m_type = m_header->type;
    m_len = m_header->len;
    m_src_router = arr2num(m_header->src_router, 4);
    m_area = arr2num(m_header->area, 4);

    // calculate
		uint16_t len = Layer::getLayerPayloadSize();
		uint8_t *dt = Layer::getLayerPayload();
		// convert uint8_t to char then to string
		std::string s((char *)dt, len);
		std::istringstream iss(s);
		std::istream &stream = iss;


		if (m_type == 1) // hello
		{
			m_content = std::make_shared<HelloContent>(stream, len);
		}
		else if (m_type == 4) // lsu
		{
			m_content = std::make_shared<LsuContent>(stream);
		}
		else //其他ospf包跳过 TODO
		{
			stream.seekg(len - sizeof(ospfhdr), std::ios::cur);
		}
}

std::string OspfLayer::toString() const
{
	std::ostringstream versionStream;
	versionStream << getVersion();
	std::ostringstream typeStream;
	typeStream << getType();	

	return "OSPF Layer, version: " + versionStream.str() + ", type: " + typeStream.str();
}

} // namespace pcpp
