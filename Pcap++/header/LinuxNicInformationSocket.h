#ifndef PCAPPP_LINUX_NIC_INFORMATION_SOCKET
#define PCAPPP_LINUX_NIC_INFORMATION_SOCKET

struct ifreq;

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * @class LinuxNicInformationSocket
	 * Simple wrapper over Linux socket for making the information
	 * requests about NICs or making some changes in NICs setup.
	 * All possible requests are described in
	 * <a href="http://man7.org/linux/man-pages/man7/netdevice.7.html">netdevice(7)</a>.
	 * The instance of this class handles underlying socket during its lifetime
	 * and takes an appropriate actions to close socket on destruction.
	 * The user must call LinuxNicInformationSocket#makeRequest method with
	 * known ioctl type and properly filled ifreq structure for this ioctl type.
	 * Filling of ifr_name may be omitted as it will be done automatically from
	 * provided NIC name.
	 * @note Usage of this class requires the inclusion of <sys/ioctl.h> and <net/if.h> Linux headers
	 */
	class LinuxNicInformationSocket
	{
	public:
		/**
		 * Simple type rename for convenience
		 */
		typedef int LinuxSocket;
		/**
		 * Simple type rename for convenience
		 */
		typedef unsigned long IoctlType;

		/**
		 * Tries to open handled socket on construction.
		 * If fails prints the debug message
		 */
		LinuxNicInformationSocket();
		/**
		 * Closes handled socket on destruction.
		 * If no socket was opened prints the debug message
		 */
		~LinuxNicInformationSocket();

		/**
		 * @brief Makes request to socket.
		 * Firstly tries to open socket if it is not opened.
		 * Then makes an ioctl(2) request to handled socket with provided request structure.
		 * See: <a href="http://man7.org/linux/man-pages/man7/netdevice.7.html">netdevice(7)</a>
		 * for description of possible values of ioctlType and content of request.
		 * @note User have no need to fill ifr_name field of request. It will be filled
		 * automatically from provided nicName argument.
		 * @param[in] nicName Name of internet controller as displayed by Linux
		 * @param[in] ioctlType Value of ioctl to make
		 * @param[in,out] request Pointer to ifreq structure that contains some information
		 *   or will be used for obtaining the information (depends on ioctlType)
		 * @return false if request was not made or socket can't be opened otherwise true
		 * @warning For some types of requests to succeed You need to be a root
		 * or have the CAP_NET_ADMIN capability.
		 */
		bool makeRequest(const char* nicName, const IoctlType ioctlType, ifreq* request);
	private:
		/* Hidden copy constructor. This structure is not copyable */
		LinuxNicInformationSocket(const LinuxNicInformationSocket&);
		/* Hidden copy assignment operator. This structure is not copyable */
		LinuxNicInformationSocket operator=(const LinuxNicInformationSocket&);
		LinuxSocket m_Socket;
	};
} // namespace pcpp
#endif /* PCAPPP_LINUX_NIC_INFORMATION_SOCKET */
