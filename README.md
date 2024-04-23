## Description.

There are two Debian GNU/Linux 12 (bookworm) virtual machines named virt01 (IP - 192.168.122.153) and virt02 (IP -192.168.122.153).

## Install strongSwan.

Do this as root user.

	$ install strongswan
	$ ipsec version
		Linux strongSwan U5.9.8/K6.1.0-18-amd64
		University of Applied Sciences Rapperswil, Switzerland

## Build the public key infrastructure.

Do this as root user. Create a self-signed root CA certificate

	$ cd /etc/ipsec.d
	$ ipsec pki --gen --type rsa --size 4096 --outform pem > private/key.pem
	$ chmod 600 private/key.pem
	$ ipsec pki --self --ca --lifetime 3650 --in private/key.pem --type rsa --digest sha256 --dn "CN=ipsec" --outform pem > cacerts/ca.pem

Create vpn virt01 certificate

	$ cd /etc/ipsec.d/
	$ ipsec pki --gen --type rsa --size 2048 --outform pem > private/virt01-private.pem
	$ chmod 600 private/virt01-private.pem
	$ ipsec pki --pub --in private/virt01-private.pem --type rsa | ipsec pki --issue --lifetime 3650 --cacert cacerts/ca.pem --cakey private/key.pem --dn "CN=virt01" --san 10.1.0.1 --flag serverAuth --outform pem > certs/virt01-public.pem

Create vpn virt02 certificate

	$ cd /etc/ipsec.d/
	$ ipsec pki --gen --type rsa --size 2048 --outform pem > private/virt02-private.pem
	$ chmod 600 private/virt02-private.pem
	$ ipsec pki --pub --in private/virt02-private.pem --type rsa | ipsec pki --issue --lifetime 3650 --cacert cacerts/ca.pem --cakey private/key.pem --dn "CN=virt02" --san 10.1.0.2 --flag serverAuth --outform pem > certs/virt02-public.pem

Export virt02 cert

	/etc/ipsec.d/cacerts/ca.pem
	/etc/ipsec.d/private/virt02-private.pem
	/etc/ipsec.d/certs/virt01-public.pem
	/etc/ipsec.d/certs/virt02-public.pem

Virt01 configuration file. 
/etc/ipsec.conf file virt01:
ipsec.conf - strongSwan IPsec configuration file

	conn myvpn
	    left=192.168.122.153	# IP-address virt01
	    leftsubnet=10.1.0.0/24	# VPN network virt01
	    #lefttsourceip=10.1.0.1
	    leftid=@virt01		# ID virt01
	    leftcert=virt01-public.pem
	    right=192.168.122.154	# IP-address virt02
	    rightsubnet=10.1.0.0/24	# VPN network virt02
	    #rightsourceip=10.1.0.2
	    rightid=@virt02		# ID virt02
	    rightcert=virt02-public.pem
	    authby=pubkey
	    auto=start
   
/etc/ipsec.secrets file virt01:

	# This file holds shared secrets or RSA private keys for authentication.

	# RSA private key for this host, authenticating it to any other host
	# which knows the public part.
	: RSA "virt01-private.pem"
 
Virt02 configuration file.
/etc/ipsec.conf file virt02:
ipsec.conf - strongSwan IPsec configuration file

	conn myvpn
	    left=192.168.122.154	# IP-address virt01
	    leftsubnet=10.1.0.0/24	# VPN network virt01
	    #leftsourceip=10.1.0.2
	    leftid=@virt02		# ID virt01
	    leftcert=virt02-public.pem
	    right=192.168.122.153	# IP-address virt02
	    rightsubnet=10.1.0.0/24	# VPN network virt02
	    #rightsourceip=10.1.0.1
	    rightid=@virt01 		# ID virt02
	    rightcert=virt01-public.pem
	    authby=pubkey
	    auto=start
    
/etc/ipsec.secrets file virt02:

	# This file holds shared secrets or RSA private keys for authentication.

	# RSA private key for this host, authenticating it to any other host
	# which knows the public part.
	: RSA "virt02-private.pem"

## Restart strongSway and check status.

	$ systemctl stop strongswan-starter; systemctl start strongswan-starter
	$ journalctl -u strongswan-starter
	virt02 charon[1385]: 10[IKE] authentication of 'CN=virt01' with RSA_EMSA_PKCS1_SHA2_256 successful
	virt02 charon[1385]: 10[IKE] peer supports MOBIKE
	virt02 charon[1385]: 10[IKE] IKE_SA myvpn[1] established between 192.168.122.154[CN=virt02]...192.168.122.153[CN=virt01]
	virt02 charon[1385]: 10[IKE] IKE_SA myvpn[1] established between 192.168.122.154[CN=virt02]...192.168.122.153[CN=virt01]
	virt02 charon[1385]: 10[IKE] scheduling reauthentication in 9732s
	virt02 charon[1385]: 10[IKE] maximum IKE_SA lifetime 10272s
	virt02 charon[1385]: 10[CFG] selected proposal: ESP:AES_CBC_128/HMAC_SHA2_256_128/NO_EXT_SEQ
	virt02 charon[1385]: 10[IKE] CHILD_SA myvpn{1} established with SPIs ca43f5c8_i c79b1fbf_o and TS 10.1.0.0/24 === 10.1.0.0/24
	virt02 charon[1385]: 10[IKE] CHILD_SA myvpn{1} established with SPIs ca43f5c8_i c79b1fbf_o and TS 10.1.0.0/24 === 10.1.0.0/24

	$ ipsec status
	Security Associations (1 up, 0 connecting):
	       myvpn[1]: ESTABLISHED 20 minutes ago, 192.168.122.154[CN=virt02]...192.168.122.153[CN=virt01]
	       myvpn{1}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: ca43f5c8_i c79b1fbf_o
	       myvpn{1}:   10.1.0.0/24 === 10.1.0.0/24

Add route and ip address for virt01.

	$ ip route add 10.1.0.0/24 via 192.168.122.153
	$ ip addr add 10.1.0.1/32 dev enp1s0

Add route and ip address for virt02.

	$ ip route add 10.1.0.0/24 via 192.168.122.154
	$ ip addr add 10.1.0.2/32 dev enp1s0

Check connection.

	$ ping 10.1.0.2
	PING 10.1.0.2 (10.1.0.2) 56(84) bytes of data.
	64 bytes from 10.1.0.2: icmp_seq=1 ttl=64 time=0.497 ms
	64 bytes from 10.1.0.2: icmp_seq=2 ttl=64 time=0.773 ms

	$ tcpdump -i enp1s0 -nnvvvXX 'esp'
	tcpdump: listening on enp1s0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
	00:29:51.867724 IP (tos 0x0, ttl 64, id 11676, offset 0, flags [DF], proto ESP (50), length 156)
	    192.168.122.153 > 192.168.122.154: ESP(spi=0xcf99bf71,seq=0x1), length 136
		0x0000:  5254 00db 309d 5254 0069 e3ef 0800 4500  RT..0.RT.i....E.
		0x0010:  009c 2d9c 4000 4032 960f c0a8 7a99 c0a8  ..-.@.@2....z...
		0x0020:  7a9a cf99 bf71 0000 0001 98da b384 8475  z....q.........u
		0x0030:  b9c1 982b 960a c107 0b16 2b49 4df6 18d3  ...+......+IM...
		0x0040:  325c c945 deb6 7b59 3a89 004e e2cd 6309  2\.E..{Y:..N..c.
		0x0050:  beb1 e4f8 a04c 8c98 71b2 d66b 4085 52a1  .....L..q..k@.R.
		0x0060:  59ae 0db3 347f afa8 348a 3bc3 51bd 6a3d  Y...4...4.;.Q.j=
		0x0070:  c1d4 57cb 25dc 8517 ee33 2ead e535 b313  ..W.%....3...5..
		0x0080:  2ab7 f0e6 8421 ffac 7e8f 5a89 c384 7b7d  *....!..~.Z...{}
		0x0090:  a444 b0a0 c682 8c62 f308 b8b2 ef5e df82  .D.....b.....^..
		0x00a0:  aa70 3ed9 db38 5b10 0460                 .p>..8[..`
	00:29:51.867829 IP (tos 0x0, ttl 64, id 4898, offset 0, flags [none], proto ESP (50), length 156)
	    192.168.122.154 > 192.168.122.153: ESP(spi=0xc07f3c0a,seq=0x1), length 136
		0x0000:  5254 0069 e3ef 5254 00db 309d 0800 4500  RT.i..RT..0...E.
		0x0010:  009c 1322 0000 4032 f089 c0a8 7a9a c0a8  ..."..@2....z...
		0x0020:  7a99 c07f 3c0a 0000 0001 1f9b 6687 f16f  z...<.......f..o
		0x0030:  07d5 1d41 e635 e4de 1987 e337 f666 dd39  ...A.5.....7.f.9

## Make and install module.

	$ make
	$ insmod xfrm_fragmentation.ko
	
## Check module.

Check do_fragment_xfrm values ​​in sysfs.

	$ cat /sys/kernel/xfrm_fragmentation/do_fragment_xfrm 
	0
	
Send a packet with a length greater than mtu from virt01 to virt02.
on virt01

	$ head -c 2000 xfrm_fragmentation.c | netcat -u 10.1.0.2 12345
	
on virt02

	$ netcat -ul -p 12345
	
The encrypted ESP packet is split into two packets with a fragmentation flag.
	
	$ tcpdump -i enp1s0 -nnvvvXX 'esp'
	tcpdump: listening on enp1s0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
	22:38:10.182850 IP (tos 0x0, ttl 64, id 27726, offset 0, flags [+], proto ESP (50), length 1436)
    	192.168.122.153 > 192.168.122.154: ESP(spi=0xcac60e33,seq=0x1), length 1416
		0x0000:  5254 00db 309d 5254 0069 e3ef 0800 4500  RT..0.RT.i....E.
		0x0010:  059c 6c4e 2000 4032 725d c0a8 7a99 c0a8  ..lN..@2r]..z...

		..................................................................

		0x0590:  ab87 74c4 6b04 692c bb3f a15c f564 5928  ..t.k.i,.?.\.dY(
		0x05a0:  65bd 4f2a a91c 1913 c913                 e.O*......
	22:38:10.182855 IP (tos 0x0, ttl 64, id 27726, offset 1416, flags [none], proto ESP (50), length 676)
    	192.168.122.153 > 192.168.122.154: ip-proto-50
		0x0000:  5254 00db 309d 5254 0069 e3ef 0800 4500  RT..0.RT.i....E.
	
		..................................................................

		0x02a0:  b5c6 5ede 3108 dd80 8e60 a6e4 7b09 14f6  ..^.1....`..{...
		0x02b0:  25c8                                     %.

Enable fragmentation before encryption.

	$ echo 1 > /sys/kernel/xfrm_fragmentation/do_fragment_xfrm

Send a packet with a length greater than mtu from virt01 to virt02 and check fragmentation. The packet does not have a fragmentation flag - it is first fragmented and then encrypted.

	$tcpdump -i enp1s0 -nnvvvXX 'esp'
	tcpdump: listening on enp1s0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
	23:00:19.154579 IP (tos 0x0, ttl 64, id 57985, offset 0, flags [none], proto ESP (50), length 1500)
    	192.168.122.153 > 192.168.122.154: ESP(spi=0xcac60e33,seq=0x6), length 1480
		0x0000:  5254 00db 309d 5254 0069 e3ef 0800 4500  RT..0.RT.i....E.
	
		.................................................................
		
		0x05d0:  291f 7ee6 837a dc45 08cb b31a 046e ab66  ).~..z.E.....n.f
		0x05e0:  07c2 1780 a34c fa00 5cb8                 .....L..\.
	23:00:19.154584 IP (tos 0x0, ttl 64, id 57986, offset 0, flags [none], proto ESP (50), length 684)
    	192.168.122.153 > 192.168.122.154: ESP(spi=0xcac60e33,seq=0x7), length 664
		0x0000:  5254 00db 309d 5254 0069 e3ef 0800 4500  RT..0.RT.i....E.
	
		.................................................................
	
		0x02a0:  ef8a 2f11 c804 b13a 09e6 35c9 1b5d efed  ../....:..5..]..
		0x02b0:  3992 3ee8 ccc8 a9ab 5fc1                 9.>....._.


