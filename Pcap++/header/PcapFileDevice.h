#ifndef PCAPPP_FILE_DEVICE
#define PCAPPP_FILE_DEVICE

#include "PcapDevice.h"
#include "RawPacket.h"

/// @file

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{

	/**
	 * @class IFileDevice
	 * An abstract class (cannot be instantiated, has a private c'tor) which is the parent class for all file devices
	 */
	class IFileDevice : public IPcapDevice
	{
	protected:
		char* m_FileName;

		IFileDevice(const char* fileName);
		virtual ~IFileDevice();

	public:

		/**
		* @return The name of the file
		*/
		std::string getFileName() const;


		//override methods

		/**
		 * Close the file
		 */
		virtual void close();
	};


	/**
	 * @class IFileReaderDevice
	 * An abstract class (cannot be instantiated, has a private c'tor) which is the parent class for file reader devices
	 */
	class IFileReaderDevice : public IFileDevice
	{
	protected:
		uint32_t m_NumOfPacketsRead;
		uint32_t m_NumOfPacketsNotParsed;

		/**
		 * A constructor for this class that gets the pcap full path file name to open. Notice that after calling this constructor the file
		 * isn't opened yet, so reading packets will fail. For opening the file call open()
		 * @param[in] fileName The full path of the file to read
		 */
		IFileReaderDevice(const char* fileName);

	public:

		/**
		 * A destructor for this class
		 */
		virtual ~IFileReaderDevice() {}

		/**
		* @return The file size in bytes
		*/
		uint64_t getFileSize() const;

		virtual bool getNextPacket(RawPacket& rawPacket) = 0;

		/**
		 * Read the next N packets into a raw packet vector
		 * @param[out] packetVec The raw packet vector to read packets into
		 * @param[in] numOfPacketsToRead Number of packets to read. If value <0 all remaining packets in the file will be read into the
		 * raw packet vector (this is the default value)
		 * @return The number of packets actually read
		 */
		int getNextPackets(RawPacketVector& packetVec, int numOfPacketsToRead = -1);

		/**
		 * A static method that creates an instance of the reader best fit to read the file. It decides by the file extension: for .pcapng
		 * files it returns an instance of PcapNgFileReaderDevice and for all other extensions it returns an instance of PcapFileReaderDevice
		 * @param[in] fileName The file name to open
		 * @return An instance of the reader to read the file. Notice you should free this instance when done using it
		 */
		static IFileReaderDevice* getReader(const char* fileName);
	};


	/**
	 * @class PcapFileReaderDevice
	 * A class for opening a pcap file in read-only mode. This class enable to open the file and read all packets, packet-by-packet
	 */
	class PcapFileReaderDevice : public IFileReaderDevice
	{
	private:
		LinkLayerType m_PcapLinkLayerType;

		// private copy c'tor
		PcapFileReaderDevice(const PcapFileReaderDevice& other);
		PcapFileReaderDevice& operator=(const PcapFileReaderDevice& other);

	public:
		/**
		 * A constructor for this class that gets the pcap full path file name to open. Notice that after calling this constructor the file
		 * isn't opened yet, so reading packets will fail. For opening the file call open()
		 * @param[in] fileName The full path of the file to read
		 */
		PcapFileReaderDevice(const char* fileName) : IFileReaderDevice(fileName), m_PcapLinkLayerType(LINKTYPE_ETHERNET) {}

		/**
		 * A destructor for this class
		 */
		virtual ~PcapFileReaderDevice() {}

		/**
		* @return The link layer type of this file
		*/
		LinkLayerType getLinkLayerType() const { return m_PcapLinkLayerType; }


		//overridden methods

		/**
		 * Read the next packet from the file. Before using this method please verify the file is opened using open()
		 * @param[out] rawPacket A reference for an empty RawPacket where the packet will be written
		 * @return True if a packet was read successfully. False will be returned if the file isn't opened (also, an error log will be printed)
		 * or if reached end-of-file
		 */
		bool getNextPacket(RawPacket& rawPacket);

		/**
		 * Open the file name which path was specified in the constructor in a read-only mode
		 * @return True if file was opened successfully or if file is already opened. False if opening the file failed for some reason (for example:
		 * file path does not exist)
		 */
		bool open();

		/**
		 * Get statistics of packets read so far. In the pcap_stat struct, only ps_recv member is relevant. The rest of the members will contain 0
		 * @param[out] stats The stats struct where stats are returned
		 */
		void getStatistics(pcap_stat& stats) const;
	};


	/**
	 * @class PcapNgFileReaderDevice
	 * A class for opening a pcap-ng file in read-only mode. This class enable to open the file and read all packets, packet-by-packet
	 */
	class PcapNgFileReaderDevice : public IFileReaderDevice
	{
	private:
		void* m_LightPcapNg;
		struct bpf_program m_Bpf;
		bool m_BpfInitialized;
		int m_BpfLinkType;
		std::string m_CurFilter;

		// private copy c'tor
		PcapNgFileReaderDevice(const PcapNgFileReaderDevice& other);
		PcapNgFileReaderDevice& operator=(const PcapNgFileReaderDevice& other);

		bool matchPacketWithFilter(const uint8_t* packetData, size_t packetLen, timespec packetTimestamp, uint16_t linkType);

	public:
		/**
		 * A constructor for this class that gets the pcap-ng full path file name to open. Notice that after calling this constructor the file
		 * isn't opened yet, so reading packets will fail. For opening the file call open()
		 * @param[in] fileName The full path of the file to read
		 */
		PcapNgFileReaderDevice(const char* fileName);

		/**
		 * A destructor for this class
		 */
		virtual ~PcapNgFileReaderDevice() { close(); }

		/**
		 * The pcap-ng format allows storing metadata at the header of the file. Part of this metadata is a string specifying the
		 * operating system that was used for capturing the packets. This method reads this string from the metadata (if exists) and
		 * returns it
		 * @return The operating system string if exists, or an empty string otherwise
		 */
		std::string getOS() const;

		/**
		 * The pcap-ng format allows storing metadata at the header of the file. Part of this metadata is a string specifying the
		 * hardware that was used for capturing the packets. This method reads this string from the metadata (if exists) and
		 * returns it
		 * @return The hardware string if exists, or an empty string otherwise
		 */
		std::string getHardware() const;

		/**
		 * The pcap-ng format allows storing metadata at the header of the file. Part of this metadata is a string specifying the
		 * capture application that was used for capturing the packets. This method reads this string from the metadata (if exists) and
		 * returns it
		 * @return The capture application string if exists, or an empty string otherwise
		 */
		std::string getCaptureApplication() const;

		/**
		 * The pcap-ng format allows storing metadata at the header of the file. Part of this metadata is a string containing a user-defined
		 * comment (can be any string). This method reads this string from the metadata (if exists) and
		 * returns it
		 * @return The comment written inside the file if exists, or an empty string otherwise
		 */
		std::string getCaptureFileComment() const;

		/**
		 * The pcap-ng format allows storing a user-defined comment for every packet (besides the comment per-file). This method reads
		 * the next packet and the comment attached to it (if such comment exists), and returns them both
		 * @param[out] rawPacket A reference for an empty RawPacket where the packet will be written
		 * @param[out] packetComment The comment attached to the packet or an empty string if no comment exists
		 * @return True if a packet was read successfully. False will be returned if the file isn't opened (also, an error log will be printed)
		 * or if reached end-of-file
		 */
		bool getNextPacket(RawPacket& rawPacket, std::string& packetComment);

		//overridden methods

		/**
		 * Read the next packet from the file. Before using this method please verify the file is opened using open()
		 * @param[out] rawPacket A reference for an empty RawPacket where the packet will be written
		 * @return True if a packet was read successfully. False will be returned if the file isn't opened (also, an error log will be printed)
		 * or if reached end-of-file
		 */
		bool getNextPacket(RawPacket& rawPacket);

		/**
		 * Open the file name which path was specified in the constructor in a read-only mode
		 * @return True if file was opened successfully or if file is already opened. False if opening the file failed for some reason (for example:
		 * file path does not exist)
		 */
		bool open();

		/**
		 * Get statistics of packets read so far. In the pcap_stat struct, only ps_recv member is relevant. The rest of the members will contain 0
		 * @param[out] stats The stats struct where stats are returned
		 */
		void getStatistics(pcap_stat& stats) const;

		/**
		 * Set a filter for PcapNG reader device. Only packets that match the filter will be received
		 * @param[in] filterAsString The filter to be set in Berkeley Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html)
		 * @return True if filter set successfully, false otherwise
		 */
		bool setFilter(std::string filterAsString);

		/**
		 * Close the pacp-ng file
		 */
		void close();
	};


	/**
	 * @class IFileWriterDevice
	 * An abstract class (cannot be instantiated, has a private c'tor) which is the parent class for file writer devices
	 */
	class IFileWriterDevice : public IFileDevice
	{
	protected:
		uint32_t m_NumOfPacketsWritten;
		uint32_t m_NumOfPacketsNotWritten;

		IFileWriterDevice(const char* fileName);

	public:

		/**
		 * A destructor for this class
		 */
		virtual ~IFileWriterDevice() {}

		virtual bool writePacket(RawPacket const& packet) = 0;

		virtual bool writePackets(const RawPacketVector& packets) = 0;

		using IFileDevice::open;
		virtual bool open(bool appendMode) = 0;
	};


	/**
	 * @class PcapFileWriterDevice
	 * A class for opening a pcap file for writing or create a new pcap file and write packets to it. This class adds
	 * a unique capability that isn't supported in WinPcap and in older libpcap versions which is to open a pcap file
	 * in append mode where packets are written at the end of the pcap file instead of running it over
	 */
	class PcapFileWriterDevice : public IFileWriterDevice
	{
	private:
		pcap_dumper_t* m_PcapDumpHandler;
		LinkLayerType m_PcapLinkLayerType;
		bool m_AppendMode;
		FILE* m_File;

		// private copy c'tor
		PcapFileWriterDevice(const PcapFileWriterDevice& other);
		PcapFileWriterDevice& operator=(const PcapFileWriterDevice& other);

		void closeFile();

	public:
		/**
		 * A constructor for this class that gets the pcap full path file name to open for writing or create. Notice that after calling this
		 * constructor the file isn't opened yet, so writing packets will fail. For opening the file call open()
		 * @param[in] fileName The full path of the file
		 * @param[in] linkLayerType The link layer type all packet in this file will be based on. The default is Ethernet
		 */
		PcapFileWriterDevice(const char* fileName, LinkLayerType linkLayerType = LINKTYPE_ETHERNET);

		/**
		 * A destructor for this class
		 */
		~PcapFileWriterDevice() {}

		/**
		 * Write a RawPacket to the file. Before using this method please verify the file is opened using open(). This method won't change the
		 * written packet
		 * @param[in] packet A reference for an existing RawPcket to write to the file
		 * @return True if a packet was written successfully. False will be returned if the file isn't opened
		 * or if the packet link layer type is different than the one defined for the file
		 * (in all cases, an error will be printed to log)
		 */
		bool writePacket(RawPacket const& packet);

		/**
		 * Write multiple RawPacket to the file. Before using this method please verify the file is opened using open(). This method won't change
		 * the written packets or the RawPacketVector instance
		 * @param[in] packets A reference for an existing RawPcketVector, all of its packets will be written to the file
		 * @return True if all packets were written successfully to the file. False will be returned if the file isn't opened (also, an error
		 * log will be printed) or if at least one of the packets wasn't written successfully to the file
		 */
		bool writePackets(const RawPacketVector& packets);

		//override methods

		/**
		 * Open the file in a write mode. If file doesn't exist, it will be created. If it does exist it will be
		 * overwritten, meaning all its current content will be deleted
		 * @return True if file was opened/created successfully or if file is already opened. False if opening the file failed for some reason
		 * (an error will be printed to log)
		 */
		virtual bool open();

		/**
		 * Same as open(), but enables to open the file in append mode in which packets will be appended to the file
		 * instead of overwrite its current content. In append mode file must exist, otherwise opening will fail
		 * @param[in] appendMode A boolean indicating whether to open the file in append mode or not. If set to false
		 * this method will act exactly like open(). If set to true, file will be opened in append mode
		 * @return True of managed to open the file successfully. In case appendMode is set to true, false will be returned
		 * if file wasn't found or couldn't be read, if file type is not pcap, or if link type specified in c'tor is
		 * different from current file link type. In case appendMode is set to false, please refer to open() for return
		 * values
		 */
		bool open(bool appendMode);

		/**
		 * Flush and close the pacp file
		 */
		virtual void close();

		/**
		 * Flush packets to disk.
		 */
		void flush();

		/**
		 * Get statistics of packets written so far. In the pcap_stat struct, only ps_recv member is relevant. The rest of the members will contain 0
		 * @param[out] stats The stats struct where stats are returned
		 */
		virtual void getStatistics(pcap_stat& stats) const;
	};


	/**
	 * @class PcapNgFileWriterDevice
	 * A class for opening a pcap-ng file for writing or creating a new pcap-ng file and write packets to it. This class adds
	 * unique capabilities such as writing metadata attributes into the file header, adding comments per packet and opening
	 * the file in append mode where packets are added to a file instead of overriding it. This capabilities are part of the
	 * pcap-ng standard but aren't supported in most tools and libraries
	 */
	class PcapNgFileWriterDevice : public IFileWriterDevice
	{
	private:
		void* m_LightPcapNg;
		int m_CompressionLevel;
		struct bpf_program m_Bpf;
		bool m_BpfInitialized;
		int m_BpfLinkType;
		std::string m_CurFilter;

		// private copy c'tor
		PcapNgFileWriterDevice(const PcapFileWriterDevice& other);
		PcapNgFileWriterDevice& operator=(const PcapNgFileWriterDevice& other);

		bool matchPacketWithFilter(const uint8_t* packetData, size_t packetLen, timespec packetTimestamp, uint16_t linkType);

	public:

		/**
		 * A constructor for this class that gets the pcap-ng full path file name to open for writing or create. Notice that after calling this
		 * constructor the file isn't opened yet, so writing packets will fail. For opening the file call open()
		 * @param[in] fileName The full path of the file
		 * @param[in] compressionLevel The compression level to use when writing the file, use 0 to disable compression or 10 for max compression. Default is 0 
		 */
		PcapNgFileWriterDevice(const char* fileName, int compressionLevel = 0);

		/**
		 * A destructor for this class
		 */
		virtual ~PcapNgFileWriterDevice() { close(); }

		/**
		 * Open the file in a write mode. If file doesn't exist, it will be created. If it does exist it will be
		 * overwritten, meaning all its current content will be deleted. As opposed to open(), this method also allows writing several
		 * metadata attributes that will be stored in the header of the file
		 * @param[in] os A string describing the operating system that was used to capture the packets. If this string is empty or null it
		 * will be ignored
		 * @param[in] hardware A string describing the hardware that was used to capture the packets. If this string is empty or null it
		 * will be ignored
		 * @param[in] captureApp A string describing the application that was used to capture the packets. If this string is empty or null it
		 * will be ignored
		 * @param[in] fileComment A string containing a user-defined comment that will be part of the metadata of the file.
		 * If this string is empty or null it will be ignored
		 * @return True if file was opened/created successfully or if file is already opened. False if opening the file failed for some reason
		 * (an error will be printed to log)
		 */
		bool open(const char* os, const char* hardware, const char* captureApp, const char* fileComment);

		/**
		 * The pcap-ng format allows adding a user-defined comment for each stored packet. This method writes a RawPacket to the file and
		 * adds a comment to it. Before using this method please verify the file is opened using open(). This method won't change the
		 * written packet or the input comment
		 * @param[in] packet A reference for an existing RawPcket to write to the file
		 * @param[in] comment The comment to be written for the packet. If this string is empty or null it will be ignored
		 * @return True if a packet was written successfully. False will be returned if the file isn't opened (an error will be printed to log)
		 */
		bool writePacket(RawPacket const& packet, const char* comment);

		//overridden methods

		/**
		 * Write a RawPacket to the file. Before using this method please verify the file is opened using open(). This method won't change the
		 * written packet
		 * @param[in] packet A reference for an existing RawPcket to write to the file
		 * @return True if a packet was written successfully. False will be returned if the file isn't opened (an error will be printed to log)
		 */
		bool writePacket(RawPacket const& packet);

		/**
		 * Write multiple RawPacket to the file. Before using this method please verify the file is opened using open(). This method won't change
		 * the written packets or the RawPacketVector instance
		 * @param[in] packets A reference for an existing RawPcketVector, all of its packets will be written to the file
		 * @return True if all packets were written successfully to the file. False will be returned if the file isn't opened (also, an error
		 * log will be printed) or if at least one of the packets wasn't written successfully to the file
		 */
		bool writePackets(const RawPacketVector& packets);

		/**
		 * Open the file in a write mode. If file doesn't exist, it will be created. If it does exist it will be
		 * overwritten, meaning all its current content will be deleted
		 * @return True if file was opened/created successfully or if file is already opened. False if opening the file failed for some reason
		 * (an error will be printed to log)
		 */
		bool open();

		/**
		 * Same as open(), but enables to open the file in append mode in which packets will be appended to the file
		 * instead of overwrite its current content. In append mode file must exist, otherwise opening will fail
		 * @param[in] appendMode A boolean indicating whether to open the file in append mode or not. If set to false
		 * this method will act exactly like open(). If set to true, file will be opened in append mode
		 * @return True of managed to open the file successfully. In case appendMode is set to true, false will be returned
		 * if file wasn't found or couldn't be read, if file type is not pcap-ng. In case appendMode is set to false, please refer to open()
		 * for return values
		 */
		bool open(bool appendMode);

		/**
		 * Flush packets to the pcap-ng file
		 */
		void flush();

		/**
		 * Flush and close the pcap-ng file
		 */
		void close();

		/**
		 * Get statistics of packets written so far. In the pcap_stat struct, only ps_recv member is relevant. The rest of the members will contain 0
		 * @param[out] stats The stats struct where stats are returned
		 */
		void getStatistics(pcap_stat& stats) const;

		/**
		 * Set a filter for PcapNG writer device. Only packets that match the filter will be persisted
		 * @param[in] filterAsString The filter to be set in Berkeley Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html)
		 * @return True if filter set successfully, false otherwise
		 */
		bool setFilter(std::string filterAsString);

	};

}// namespace pcpp

#endif
