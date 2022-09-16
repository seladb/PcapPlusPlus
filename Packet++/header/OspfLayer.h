#ifndef PACKETPP_OSPF_LAYER
#define PACKETPP_OSPF_LAYER

#include <memory>
#include <sstream>
#include <vector>

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

/**
 * @struct ospfhdr
 * Represents an OSPF protocol header
 */
#pragma pack(push, 1)
struct ospfhdr
{
	// version
	uint8_t version;
	// message type:  1.Hello; 2.DD; 3.LSR; 4.LSU; 5.LSAck
	uint8_t type;
	// total length (in byte)
	uint16_t len;
	// router ID
	uint8_t src_router[4];
	// Area ID
	uint8_t area[4];
	// cehcksum
	uint16_t checksum;
	// auth type: 0.none; 1.simple; 2.MD5
	uint16_t auth_type;
	// auth data
	uint64_t auth_data;
};
#pragma pack(pop)

/**
 * @class OspfContent
 */
class OspfContent
{
  public:
	virtual void Print(std::ostream &os) = 0;
	virtual bool IsAvailable() = 0;
};

//----------------------------------------------------------------------------------------------
// hello

#pragma pack(push, 1)
struct HelloHeader
{
	// 子网掩码
	uint8_t mask[4];
	// 时间间隔
	uint16_t hello_interval;
	// 可选项：E：允许Flood AS-External-LSAs MC：转发IP组播报文 N/P：处理Type-7 LSAs DC：处理按需链路
	uint8_t options;
	// DR优先级。默认为1。如果设置为0，则路由器不能参与DR或BDR的选举。
	uint8_t priority;
	// 失效时间。如果在此时间内未收到邻居发来的Hello报文，则认为邻居失效。
	uint32_t dead_interval;
	// DR的接口地址。
	uint8_t d_router[4];
	// BDR的接口地址。
	uint8_t b_router[4];
};
#pragma pack(pop)

class HelloContent : public OspfContent
{
  public:
	HelloContent(std::istream &is, uint16_t len);
	void Print(std::ostream &os);
	bool IsAvailable();
	uint32_t get_mask();
	uint32_t get_dr();
	uint32_t get_br();
	uint32_t get_nr_num();
	uint32_t get_nr(uint32_t index);

  private:
	HelloHeader header;
	uint32_t mask;
	uint32_t dr;
	uint32_t br;
	uint32_t nr_num;
	std::vector<uint32_t> neighbors;
};
//----------------------------------------------------------------------------------------------
// las
// 所有的LSA都有相同的报文头

#pragma pack(push, 1)
struct LsaHeader
{
	// LSA产生后所经过的时间，以秒为单位。无论LSA是在链路上传送，还是保存在LSDB中，其值都会在不停的增长。
	uint16_t age;
	// 可选项：E：允许泛洪AS-External-LSA；MC：转发IP组播报文；N/P：处理Type-7 LSA；DC：处理按需链路。
	uint8_t option;
	// LSA的类型：Type1：Router-LSA Type2：Network-LSA Type3：Network-summary-LSA Type4：ASBR-summary-LSA
	// Type5：AS-External-LSA Type7：NSSA-LSA
	uint8_t lsa_type;
	// 与LSA中的LS Type和LSA description一起在路由域中描述一个LSA。
	uint8_t state_id[4];
	// 产生此LSA的路由器的Router ID。
	uint8_t adv_router[4];
	// LSA的序列号。其他路由器根据这个值可以判断哪个LSA是最新的。
	uint32_t seq;
	// 除了LS age外其它各域的校验和。
	uint16_t checksum;
	// LSA的总长度，包括LSA Header，以字节为单位。
	uint16_t tlen;
};
#pragma pack(pop)

class Lsa
{
  public:
	Lsa(std::istream &is);
	virtual void Print(std::ostream &os) = 0;
	uint8_t get_type();
	uint32_t get_state_id();
	uint32_t get_adv_router();
	uint16_t get_tlen();

  protected:
	LsaHeader header;
	uint8_t lsa_type;
	uint32_t state_id;
	uint32_t adv_router;
	uint16_t tlen;
};

//----------------------------------------------------------------------------------------------
// I
// Router-LSA（Type1）：每个路由器都会产生，描述了路由器的链路状态和花费，在所属的区域内传播。

class RouterLsaContent
{
  public:
	RouterLsaContent(std::istream &is);
	void Print(std::ostream &os);
	uint32_t get_link_id();
	uint32_t get_link_data();
	uint8_t get_link_type();
	uint8_t get_tos_num();
	uint16_t get_tos0_metric();
	std::vector<uint16_t> get_tos(uint8_t index);

  private:
	// 路由器所接入的目标，其值取决于连接的类型：1：Router
	// ID；2：DR的接口IP地址；3：网段／子网号；4：虚连接中对端的Router ID。
	uint32_t link_id;
	// 连接数据，其值取决于连接的类型：unnumbered P2P：接口的索引值；stub网络：子网掩码；其它连接：路由器接口的IP地址。
	uint32_t link_data; //在p2p下是整型
	// 路由器连接的基本描述：1：点到点连接到另一台路由器；2：连接到传输网络；3：连接到stub网络；4：虚拟链路。
	uint8_t link_type;
	// 连接不同的TOS数量。
	uint8_t tos_num;
	// 和指定TOS值相关联的度量。
	uint16_t tos0_metric;
	std::vector<std::vector<uint16_t> > toses;
};

class RouterLsa : public Lsa
{
  public:
	RouterLsa(std::istream &is);
	void Print(std::ostream &os);
	uint16_t get_num();
	std::shared_ptr<RouterLsaContent> get_content(uint16_t index);

  private:
	// V E B
	// V: 如果产生此LSA的路由器是虚连接的端点，则置为1。
	// E: 如果产生此LSA的路由器是ASBR，则置为1。
	// B: 如果产生此LSA的路由器是ABR，则置为1。
	uint16_t options;
	// LSA中所描述的链路信息的数量，包括路由器上处于某区域中的所有链路和接口。
	uint16_t link_num;
	std::vector<std::shared_ptr<RouterLsaContent> > contents;
};

//----------------------------------------------------------------------------------------------
// II
// Network-LSA（Type2）：由广播网或NBMA网络中的DR产生,Network-LSA中记录了这一网络上所有路由器的RouterID，描述本网段的链路状态，在所属的区域内传播。

class NetworkLsa : public Lsa
{
  public:
	NetworkLsa(std::istream &is);
	void Print(std::ostream &os);
	uint32_t get_mask();
	uint32_t get_attach_num();
	uint32_t get_attach_router(uint32_t index);

  private:
	// 该广播网或NBMA网络地址的掩码。
	uint32_t mask;
	// 连接在同一个网络上的所有路由器的Router ID，也包括DR的Router ID。
	uint32_t attach_num;
	std::vector<uint32_t> attach_routers;
};

//----------------------------------------------------------------------------------------------
// 用来向对端Router发送其所需要的LSA或者泛洪自己更新的LSA，内容是多条LSA（全部内容）的集合。LSU报文（Link State Update
// Packet）在支持组播和广播的链路上是以组播形式将LSA泛洪出去。为了实现Flooding的可靠性传输，需要LSAck报文对其进行确认。对没有收到确认报文的LSA进行重传，重传的LSA是直接发送到邻居的。

class LsuContent : public OspfContent
{
  public:
	LsuContent(std::istream &is);
	void Print(std::ostream &os);
	bool IsAvailable(); //判断数据包是否可用，即是否有1,2类型的lsa（其它的lsa被略过）
	uint32_t get_lsa_num();
	std::shared_ptr<Lsa> get_lsa(uint32_t index);

  private:
	// LSA的数量。
	uint32_t lsa_num;
	std::vector<std::shared_ptr<Lsa> > lsas;
};

//----------------------------------------------------------------------------------------------

/**
 * @class OspfLayer
 * Represents an OSPF protocol layer
 */
class OspfLayer : public Layer
{
  public:
	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data (will be casted to @ref ospfhdr)
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] prevLayer A pointer to the previous layer
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	OspfLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) : Layer(data, dataLen, prevLayer, packet)
	{
		// set protocol
		m_Protocol = OSPF;
	}

	/**
	 * Get a pointer to the OSPF header. Notice this points directly to the data, so every change will change the actual
	 * packet data
	 * @return A pointer to the @ref ospfhdr
	 */
	ospfhdr *getOspfHeader() const
	{
		return (ospfhdr *)m_Data;
	}

	bool IsComplete();

	uint8_t getVersion() const;

	/**
	 * @return OSPF command
	 */
	uint8_t getType() const;

	/**
	 * @return OSPF src router
	 */
	uint32_t getSrcRouter() const;

	uint32_t getArea() const;

	std::shared_ptr<OspfContent> getContent();

	void ToStructuredOutput(std::ostream &os) const;

	// implement abstract methods

	void parseNextLayer(){};

	/**
	 * @return Size of @ref ospfhdr
	 */
	size_t getHeaderLen() const
	{
		return sizeof(ospfhdr);
	}

	static bool isDataValid(const uint8_t *data, size_t dataLen)
	{
		return dataLen >= sizeof(ospfhdr);
	}

	void computeCalculateFields();

	std::string toString() const;

	OsiModelLayer getOsiModelLayer() const
	{
		return OsiModelTransportLayer;
	}

  private:
	ospfhdr* m_header;
	uint8_t m_type;
	uint16_t m_len;
	uint32_t m_src_router;
	uint32_t m_area;
	std::shared_ptr<OspfContent> m_content;
};

} // namespace pcpp

#endif /* PACKETPP_OSPF_LAYER */
