HTTP Traffic Analyzer
=====================

This application analyzes HTTP traffic and presents detailed and diverse information about it such as:
- Packet count and rate
- Bandwidth
- Flow count and rate
- HTTP requests + responses count and rate
- HTTP transaction count and rate
- HTTP pipelining count
- HTTP header size
- Hostname histogram
- Content-type histogram
- Status code histogram

It can analyze live traffic or read packets from a pcap/pcap-ng file

The output stats looks as follows:

	STATS SUMMARY
	=============

	General stats
	--------------------

	Sample time:                                     18.374 [Seconds]
	Number of HTTP packets:                            5662 [Packets]
	Rate of HTTP packets:                           291.910 [Packets/sec]
	Number of HTTP flows:                                55 [Flows]
	Rate of HTTP flows:                               2.836 [Flows/sec]
	Number of HTTP pipelining flows:                      0 [Flows]
	Number of HTTP transactions:                        322 [Transactions]
	Rate of HTTP transactions:                       16.601 [Transactions/sec]
	Total HTTP data:                                5916120 [Bytes]
	Rate of HTTP data:                           305011.600 [Bytes/sec]
	Average packets per flow:                       102.945 [Packets]
	Average transactions per flow:                    5.963 [Transactions]
	Average data per flow:                       107565.818 [Bytes]

	HTTP request stats
	--------------------

	Number of HTTP requests:                            323 [Requests]
	Rate of HTTP requests:                           16.653 [Requests/sec]
	Total data in headers:                           188596 [Bytes]
	Average header size:                            583.889 [Bytes]

	HTTP response stats
	--------------------

	Number of HTTP responses:                           332 [Responses]
	Rate of HTTP responses:                          17.117 [Responses/sec]
	Total data in headers:                           119577 [Bytes]
	Average header size:                            360.172 [Bytes]
	Num of responses with content-length:               320 [Responses]
	Total body size (may be compressed):            5409410 [Bytes]
	Average body size:                            16904.406 [Bytes]

	HTTP request methods
	--------------------

	| Method    | Count |
	---------------------
	| GET       | 321   |
	| POST      | 2     |
	---------------------

	Hostnames count
	--------------------

	| Hostname                                 | Count |
	----------------------------------------------------
	| images1.teny.co.qq                       | 180   |
	| www.teny.co.qq                           | 82    |
	| go.teny.co.qq                            | 14    |
	| www.niwwin.co.qq                         | 8     |
	| az835984.vo.msecnd.net                   | 5     |
	| asset.pagefair.com                       | 3     |
	| b.scorecardresearch.com                  | 3     |
	| cdn.oolala.com                           | 3     |
	| asset.pagefair.net                       | 2     |
	| dy2.teny.co.qq                           | 2     |
	| ecdn.firstimpression.io                  | 2     |
	| pagead2.googlesyndication.com            | 2     |
	| server.exposebox.com                     | 2     |
	| totalmedia2.teny.co.qq                   | 2     |
	| vrp.mybrain.com                          | 1     |
	| trc.oolala.com                           | 1     |
	| zdwidget3-bs.sphereup.com                | 1     |
	| vrt.mybrain.com                          | 1     |
	| www.googletagmanager.com                 | 1     |
	| a.visualrevenue.com                      | 1     |
	| tpc.googlesyndication.com                | 1     |
	| static.dynamicyield.com                  | 1     |
	| st.dynamicyield.com                      | 1     |
	| sf.exposebox.com                         | 1     |
	| mediadownload.teny.co.qq                 | 1     |
	| cdn.firstimpression.io                   | 1     |
	| ajax.googleapis.com                      | 1     |
	----------------------------------------------------

	Status code count
	--------------------

	| Status Code                  | Count |
	----------------------------------------
	| 200 OK                       | 327   |
	| 204 No Content               | 1     |
	| 301 Moved Permanently        | 1     |
	| 302 Moved Temporarily        | 1     |
	| 304 Not Modified             | 2     |
	----------------------------------------

	Content-type count
	--------------------

	| Content-type                   | Count |
	------------------------------------------
	| application/javascript         | 11    |
	| application/json               | 1     |
	| application/x-javascript       | 23    |
	| image/gif                      | 22    |
	| image/jpeg                     | 157   |
	| image/png                      | 85    |
	| text/css                       | 9     |
	| text/html                      | 8     |
	| text/javascript                | 13    |
	------------------------------------------

Using the utility
-----------------
When analyzing HTTP traffic from a pcap/pcap-ng file:

	Basic usage:
		HttpAnalyzer [-h] -f input_file
	Options:
		-f           : The input pcap file to analyze. Required argument for this mode
		-h           : Displays this help message and exits

When analyzing HTTP traffic on live traffic:

	Basic usage:
		HttpAnalyzer [-hld] [-o output_file] [-r calc_period] -i interface

	Options:
		-i interface   : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address
		-o output_file : Save all captured HTTP packets to a pcap file. Notice this may cause performance degradation
		-r calc_period : The period in seconds to calculate rates. If not provided default is 2 seconds
		-d             : Disable periodic rates calculation
		-h             : Displays this help message and exits
		-l             : Print the list of interfaces and exists