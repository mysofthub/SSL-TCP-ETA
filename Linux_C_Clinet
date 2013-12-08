    #include <openssl/bio.h> // BIO objects for I/O
    #include <openssl/ssl.h> // SSL and SSL_CTX for SSL connections
    #include <openssl/err.h> // Error reporting
    #include <openssl/evp.h>
    #include <stdio.h> 
    #include <sys/time.h>
    #define BILLION 1E9 // for timing results 
    void opensslconn(void);
    
    struct timespec nm_d,nm_e;// start time and end time to connect to AP1
    double nm_t_time_spent;// time connecting to AP1

    struct timespec ap1_c,ap1_e;// start time and end time to connect to AP1
    double ap1_c_time_spent;// time connecting to AP1

    struct timespec ap1_3_c,ap1_3_e;// start time and end time for 3-way handshake
    double ap1_3_c_time_spent;// time for 3-way handshake

    struct timespec ap2_c,ap2_e;// start time and end time to connect to AP2
    double ap2_c_time_spent;// time connecting to AP2

    struct timespec ap2_r_c,ap2_r_e;// start time and end to get the server response
    double ap2_r_c_time_spent;// time to get the server response

    struct timespec s,e;// start time and end time for the testing procedure.
    double time_spent;// time for the testing procedure.

    int main(int argc, char** argv) {

    clock_gettime(CLOCK_MONOTONIC_RAW, &s);// for time measurement  
    CRYPTO_malloc_init(); // Initialize malloc, free, etc for OpenSSL's use
    SSL_library_init(); // Initialize OpenSSL's SSL libraries
    SSL_load_error_strings(); // Load SSL error strings
    ERR_load_BIO_strings(); // Load BIO error strings
    OpenSSL_add_all_algorithms(); // Load all available encryption algorithms

	printf("[~~~] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.\n"); 
	// First we need to stop Linux network manager so that 
	// our program can control the WLAN card
	printf("[1-1] Stopping network-manager\n"); 
	     int r_1=system("stop network-manager");
		 if (r_1==0)
			printf("[1-2] Linux network-manager was successfully stopped (CODE==%d)\n",r_1);   
		 else
		    {
		    printf("Error stopping Linux network-manager(CODE==%d)\n",r_1); 
			exit(0)
			} 
	printf("[1-3] Setting wlan0 to up\n"); 
	     int r_3=system("ifconfig wlan0 up");
		 if (r_3==0)
			printf("[1-4] wlan0 successfully up (CODE==%d)\n",r_3);  
		 else
		    {
		    printf("Error setting up wlan0(CODE==%d)\n",r_3); 
			exit(0)
			} 
	printf("[1-5] Connecting to FreeNet WLAN, AP1 MAC xx:xx:xx:xx:xx:x \n");
	     int r_5=system("iwconfig wlan0 mode managed essid 'FreeNet' ap xx:xx:x:xx:xx:xx"); // MAC address of AP1
		 if (r_5==0)
			printf("[1-6] Wireless client successfully connected to AP1 (CODE==%d)\n",r_5); 
		 else
		    {
		    printf("Error connecting to AP1(CODE==%d)\n",r_5); 
			exit(0)
			} 
	printf("[1-7] Getting IP address configuration from the dhcp server\n"); 
	     int r_7=system("dhclient wlan0");
		 if (r_7==0)
			printf("[1-8] Wireless client successfully obtained IP (CODE==%d)\n",r_7); 	 
		 else
		    {
		    printf("Error obtaining IP form DHCP(CODE==%d)\n",r_7); 
			exit(0)
			} 
    clock_gettime(CLOCK_MONOTONIC_RAW, &ap1_e);// for time measurement (connecting to AP1 and Getting IP address)  
	ap1_c_time_spent = ( ap1_e.tv_sec - s.tv_sec )  + ( ap1_e.tv_nsec - s.tv_nsec ) / BILLION;
	printf("[1-9] Time spent to connect to AP1=%f\n",ap1_c_time_spent); 
	
    clock_gettime(CLOCK_MONOTONIC_RAW, &ap1_3_c);//for time measurement 
	
    opensslconn(); // start ssl connection to the web server 
	printf("[4-1] Staring network-manager\n"); 
	     int r_8=system("start network-manager");
		 if (r_8==0)
			printf("[4-2] Network-manage was successfully started (CODE==%d)\n",r_8); 	
		 else
		    {
		    printf("Error starting network-manager(CODE==%d)\n",r_8); 
			exit(0)
			} 
	clock_gettime(CLOCK_MONOTONIC_RAW, &e);// for time measurement (Total checking time) 
	time_spent = ( e.tv_sec - s.tv_sec )  + ( e.tv_nsec - s.tv_nsec ) / BILLION;
	printf("[4-3] Total testing time=%f Sec\n",time_spent); 
        return 0;
    }
      void opensslconn() {
     // Set up a SSL_CTX object, which will tell our BIO object how to do its work
       SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    /* Load the trust store */

    if(! SSL_CTX_load_verify_locations(ctx, "cacert.pem", NULL))
    {
        fprintf(stderr, "Error loading trust store\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(0);
    }
       // Create a SSL object pointer, which our BIO object will provide.
       SSL* ssl;
       // Create our BIO object for SSL connections.
       BIO* bio = BIO_new_ssl_connect(ctx);
       // Failure?
       if (bio == NULL) {
          printf("Error creating BIO!\n");
               ERR_print_errors_fp(stderr);
          // We need to free up the SSL_CTX before we leave.
               SSL_CTX_free(ctx);
               return;
       }
       // Makes ssl point to bio's SSL object.
       BIO_get_ssl(bio, &ssl);
       // Set the SSL to automatically retry on failure.
       SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
       // We're connection to google.com on port 443.
       BIO_set_conn_hostname(bio, "www.google.com:https");

       // Same as before, try to connect.
       if (BIO_do_connect(bio) <= 0) {
          printf("Failed to connect!");
          BIO_free_all(bio);
          SSL_CTX_free(ctx);
          return;
       }
       // Now we need to do the SSL handshake, so we can communicate.
       if (BIO_do_handshake(bio) <= 0) {
          printf("Failed to do SSL handshake!");
          BIO_free_all(bio);
          SSL_CTX_free(ctx);
          return;

       }
 /* Check the certificate */

    if(SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Certificate verification error:");
        fprintf(stderr,"\n%i\n",SSL_get_verify_result(ssl));
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(0);
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &ap1_3_e);// for time measuring (3-way handshake)  
	ap1_3_c_time_spent = ( ap1_3_e.tv_sec - ap1_3_c.tv_sec )  + ( ap1_3_e.tv_nsec - ap1_3_c.tv_nsec ) / BILLION;
	printf("[1-10] SSL connection was successfully established to www.google.com using AP1.\n");
    printf("[1-11] Time spent to finish 3-way handshake = %f \n",ap1_3_c_time_spent);     
    clock_gettime(CLOCK_MONOTONIC_RAW, &ap2_c); // for time measurement 
 
	printf("[~~~] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.\n"); 
	printf("[2-1] Switching to AP2.\n");
	
	printf("[2-2] Setting wlan0 to down\n"); 
	     int r_1=system("ifconfig wlan0 down");
		 if (r_7==0)
			printf("[2-3] wlan0 successfully down (CODE==%d)\n",r_1);  		 
		 else
		    {
		    printf("Error setting wlan0 down(CODE==%d)\n",r_1); 
			exit(0)
			} 

	printf("[2-4] Setting wlan0 to up\n"); 
	     int r_2=system("ifconfig wlan0 up");
		 if (r_2==0)
			printf("[2-5] wlan0 successfully down (CODE==%d)\n",r_2);   		 
		 else
		    {
		    printf("Error setting wlan0 up(CODE==%d)\n",r_2); 
			exit(0)
			} 
			
	printf("[2-6] Connecting to FREE WLAN, AP2 MAC xx:xx:xx:xx:xx:xx\n"); 
	     int r_3=system("iwconfig wlan0 mode managed essid 'FreeNet' ap xx:xx:xx:xx:xx:xx");
		 if (r_3==0)
			printf("[2-7] Wireless client successfully connected to AP2 (CODE==%d)\n",r_3); 	   		 
		 else
		    {
		    printf("Error connecting to AP2(CODE==%d)\n",r_3); 
			exit(0)
			} 
			
	printf("[2-8] Getting IP address configuration from the dhcp server\n"); 	
	     int r_5=system("dhclient wlan0");
		 if (r_5==0)
			printf("[2-9] Wireless client successfully obtained IP (CODE==%d)\n",r_5);	   		 
		 else
		    {
		    printf("Error getting IP address from DHCP(CODE==%d)\n",r_5); 
			exit(0)
			} 

        clock_gettime(CLOCK_MONOTONIC_RAW, &ap2_e);// for time measuring (connecting to AP2 and Getting IP address)  
	ap2_c_time_spent = ( ap2_e.tv_sec - ap2_c.tv_sec )  + ( ap2_e.tv_nsec - ap2_c.tv_nsec ) / BILLION;
        printf("[2-10] Time spent to switch to AP2= %f \n",ap2_c_time_spent);  
	clock_gettime(CLOCK_MONOTONIC_RAW, &ap2_r_c);

       // Create a buffer for grabbing information from the page.
       char buf[1024];
       memset(buf, 0, sizeof(buf));
       // Create a buffer for the reqest we'll send to the server
       char send[1024];
       memset(send, 0, sizeof(send));
       // Create our GET request.
       strcat(send, "GET / HTTP/1.1\nHost:www.google.com\nUser Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)\nConnection: Close\n\n");
       // BIO_puts sends a null-terminated string to the server. In this case it's our GET request.
       BIO_puts(bio, send);
	printf("[~~~] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.\n"); 
       // Loop while there's information to be read.
       while (1) {
          // BIO_read() reads data from the server into a buffer. It returns the number of characters read in.
          int x = BIO_read(bio, buf, sizeof(buf) - 1);
              if (x < 0) {
							printf("[3-1] Error, Evil Twin maybe present!!\n");
						 }
          // We actually got some data, without errors!
			  else 		{
							printf("[3-1] Data Received Successfully using AP1 and AP2\n");
						}
		   }
	clock_gettime(CLOCK_MONOTONIC_RAW, &ap2_r_e);// for time measurement (receiving a response from webserver)  
	ap2_r_c_time_spent = ( ap2_r_e.tv_sec - ap2_r_c.tv_sec )  + ( ap2_r_e.tv_nsec - ap2_r_c.tv_nsec ) / BILLION;
    printf("[3-2] Time spent to receive a response from www.google.com = %f \n",ap2_r_c_time_spent); 
	printf("[3-3] Setting wlan0 to down\n"); 
	printf("[~~~] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.\n"); 
       // Free up that BIO object we created.
       BIO_free_all(bio);
       // Remember, we also need to free up that SSL_CTX object!
       SSL_CTX_free(ctx);
       // Return.
       return;
    }
