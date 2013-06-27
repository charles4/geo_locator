import pygeoip
import dpkt
import socket
import pcap
import pickle
import time


gi = pygeoip.GeoIP("GeoLiteCity.dat")

all_packets = []
count = 0

def printRecord(tgt):
	rec = gi.record_by_name(tgt)
	try:
		city = rec['city']
		region = rec['region_name']
		country = rec['country_name']
		long = rec['longitude']
		lat = rec['latitude']
		print '[*] Target: %s Geo-Located.' % tgt
		print '[+] %s, %s, %s' % (city, region, country)
		print '[+] latitude: %s, longitude: %s' % (str(lat), str(long))
	except Exception, e:
		print "Target: %s not in database." % tgt

def printer(timestamp, pkt, *args):
	global all_packets
	global count
	## dpkt.ethernet.Ethernet reads the binary data out of the packet into a python object
	try:
		pkt = dpkt.ethernet.Ethernet(pkt)

		all_packets.append(pkt)
		ip = pkt.data
		src = socket.inet_ntoa(ip.src)
		dest = socket.inet_ntoa(ip.dst)

		##print "[*] src IP %s, dest IP %s using port: %d" % (src, dest, ip.data.sport)
		printRecord(dest)

		if len(all_packets) > 3000:
			f = open("packet.log", "a")
			for packet in all_packets:
				count += 1
				f.write(str(count) + " port: " + str(packet.data.data.sport) +", src:" + socket.inet_ntoa(packet.data.src) + ", dest: " + socket.inet_ntoa(packet.data.dst) +"\n")

			f.close()
			
			### delete everything in the array
			del all_packets[0:len(all_packets)]

	except Exception, e:
		with open("error.log", "a") as f:
			t = time.time()
			f.write("%d: error: %s\n" % (t, e))

		pass

def main():
	pc = pcap.pcap(name="en0", snaplen=3000, promisc=True, timeout_ms=0, immediate=False)
	### loop 100 times, calling callback function printer
	pc.loop(0, printer)



if __name__ == "__main__":
	main()