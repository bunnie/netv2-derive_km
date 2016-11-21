/***
Copyright (c) 2016, Andrew "bunnie" Huang / bunnie@alphamaxmedia.com
All rights reserved.

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
***/
/*
 * derive_km
 *
 * Km derivation routine from snooped HDCP public keys & HDCP master key
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SOURCE 1
#define SINK 0

void compute_keys( unsigned long long Ksv, unsigned int source, unsigned long long *key );

#define PRINT_ERROR \
	do { \
		fprintf(stderr, "Error at line %d, file %s (%d) [%s]\n", \
		__LINE__, __FILE__, errno, strerror(errno)); exit(1); \
	} while(0)

#define MAP_SIZE (65536)
#define MAP_MASK (MAP_SIZE - 1)

#define GPIO1_DATA  (*((volatile uint32_t *) (virt_addr + 0x0)))
#define GPIO2_DATA  (*((volatile uint32_t *) (virt_addr + 0x8)))

int fd;
void *map_base, *virt_addr;

// these are global as they track write-only state inside the PCI space
uint8_t reg_addr = 0;
uint8_t i2c_snoop_addr2 = 0xa0;
uint8_t hpd_override = 0;
uint8_t bypass = 0;
uint8_t bypass_vid = 1;

void map_pci(char *filename) {
  
  if((fd = open(filename, O_RDWR | O_SYNC)) == -1) PRINT_ERROR;

  map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_32BIT, fd, 0 & ~MAP_MASK);
  if(map_base == (void *) -1) PRINT_ERROR;
  printf("PCI Memory mapped to address 0x%016lx.\n", (unsigned long) map_base);
  fflush(stdout);

  virt_addr = map_base;
}

 
// GPIO1 bit 0        0 = internal data, 1 = bypass
// GPIO1 bit 1        0 = internal data, 1 = bypass video only
// GPIO1 bit 12:8     alpha1 (video stream)
// GPIO1 bit 20:16    alpha2 (local computer stream)
// GPIO1 bit 31    w  we_reg_expander write enable -- must be toggled 0 between each write, does not auto-clear
// GPIO1 bit 23:16 w  we_reg_expander data
// GPIO1 bit 26:24 w  we_reg_exapnder address
// GPIO1 block has the internal/bypass switch, and the Km block expander
// reg_expander bytes 6 - 0 : Km
// reg_expander byte 7, bit 0: Km ready

// GPIO2 bit 4:0   w  reg_addr (for readback)
// GPIO2 bit 15:8  w  <unused>
// GPIO2 bit 23:16 w  i2c_snoop_addr_2
// GPIO2 bit 31    w  HPD_override
// GPIO2 bit 7:0   r  reg_data_1  (edid)
// GPIO2 bit 15:8  r  reg_data_2  (hdcp)
// GPIO2 controls the EDID/HDCP snoopers
// There are two independent snoopers on the I2C bus, one looking for EDID, other for HDCP
// reg_addr specifies the address to read back from the snoopers shadow storage registers
// reg_addr is ganged together for both blocks, so a single transaction will return
// the value of both always by reading GPIO2 and looking at the lowest or second-lowest bytes
// HPD override and the address for EDID snooping is also maintained in this register
// Note that data read back has nothing to do with data written.

// read a byte from the HDCP memory space
unsigned char read_hdcp(unsigned char addr) {
  uint32_t write_data;
  uint32_t read_result;

  reg_addr = addr;
  write_data = ((hpd_override & 1) << 31) | (i2c_snoop_addr2 << 8) | (reg_addr & 0x1F);
  GPIO2_DATA = write_data;
  msync( virt_addr, MAP_SIZE, MS_SYNC );
  read_result = GPIO2_DATA;

  return( (read_result >> 8) & 0xFF );
}

void write_km(unsigned char addr, unsigned char data) {
  uint32_t write_data;
  unsigned char write = 0;

  // write has to toggle high and low for the data to commit
  write_data = ((write & 0x1) << 31) | (data << 16) | ((addr & 0x7) << 24) | ((bypass_vid & 0x1) << 1) | (bypass & 0x1);
  GPIO1_DATA = write_data;
  msync( virt_addr, MAP_SIZE, MS_SYNC );
  write = 1;
  write_data = ((write & 0x1) << 31) | (data << 16) | ((addr & 0x7) << 24) | ((bypass_vid & 0x1) << 1) |(bypass & 0x1);
  GPIO1_DATA = write_data;
  msync( virt_addr, MAP_SIZE, MS_SYNC );
  write = 0;
  write_data = ((write & 0x1) << 31) | (data << 16) | ((addr & 0x7) << 24) | ((bypass_vid & 0x1) << 1) |(bypass & 0x1);
  GPIO1_DATA = write_data;
  msync( virt_addr, MAP_SIZE, MS_SYNC );
}

/* 
example hdcp record
    lsb        msb <-sink   ri
00: 09 74 30 d7 fa 00 00 00 e3 2b 00 00 00 00 00 00 
10: 68 f1 e6 12 76 00 00 00 9c 4d 8a 4b 46 32 82 31 
    lsb        msb <-source lsb      An         msb

example edid record
00: 00 ff ff ff ff ff ff 00 4c 2d f6 03 36 32 44 54 
10: 07 13 01 03 80 10 09 78 2a ee 91 a3 54 4c 99 26 
20: 0f 50 54 bf ef 80 a9 40 81 80 81 40 71 4f 01 01 
30: 01 01 01 01 01 01 28 3c 80 a0 70 b0 23 40 30 20 
40: 36 00 a0 5a 00 00 00 1a 01 1d 00 bc 52 d0 1e 20 
50: b8 28 55 40 a0 5a 00 00 00 1e 00 00 00 fd 00 32 
60: 4b 1b 51 11 00 0a 20 20 20 20 20 20 00 00 00 fc 
70: 00 53 79 6e 63 4d 61 73 74 65 72 0a 20 20 01 ed 
80: 02 03 1f f2 4b 93 04 12 83 14 05 20 21 22 1f 10 
90: 23 09 07 07 83 01 00 00 66 03 0c 00 10 00 80 8c 
a0: 0a d0 8a 20 e0 2d 10 10 3e 96 00 a0 5a 00 00 00 
b0: 18 01 1d 00 72 51 d0 1e 20 6e 28 55 00 a0 5a 00 
c0: 00 00 1e 01 1d 80 d0 72 1c 16 20 10 2c 25 80 a0 
d0: 5a 00 00 00 9e 01 1d 80 18 71 1c 16 20 58 2c 25 
e0: 00 a0 5a 00 00 00 9e 8c 0a d0 90 20 40 31 20 0c 
f0: 40 55 00 a0 5a 00 00 00 18 00 00 00 00 00 00 31 
*/

int main(int argc, char **argv) {
    unsigned int num;
    int i;

    unsigned long long source_ksv = 0LL;
    unsigned long long sink_ksv = 0LL;
    unsigned long long ksv_temp = 0LL;
    unsigned long long Km = 0LL;
    unsigned long long Kmp = 0LL;
    
    unsigned long long source_pkey[40];
    unsigned long long sink_pkey[40];

    if(argc != 2) {
        fprintf(stderr, "Usage: %s <pci bar filename>\n", argv[0]);
        return 1;
    }

    map_pci(argv[1]);

    for( i = 0; i < 5; i++ ) {
      sink_ksv <<= 8;
      sink_ksv |= (read_hdcp(4 - i) & 0xff);
    }

    for( i = 0; i < 5; i++ ) {
      source_ksv <<= 8;
      source_ksv |= (read_hdcp(4 - i + 0x10) & 0xff);
    }

    printf( "source public ksv: %010llx\n", source_ksv );
    printf( "sink public ksv: %010llx\n", sink_ksv );
    compute_keys( source_ksv, SOURCE, source_pkey );
    compute_keys( sink_ksv, SINK, sink_pkey );

    ksv_temp = source_ksv; // source Ksv
    num = 0;
    for( i = 0; i < 40; i++ ) {
      if( ksv_temp & 1LL ) {
	num++;
	Km += sink_pkey[i]; // used to select sink's keys
	Km %=  72057594037927936LL;
	//	printf( "Km %014llx\n", Km );
      }
      ksv_temp >>= 1LL;
    }
    //    printf( "num 1's: %d\n", num );
    // km is the sink km

    ksv_temp = sink_ksv; // sink Ksv
    num = 0;
    for( i = 0; i < 40; i++ ) {
      if( ksv_temp & 1LL ) {
	num++;
	Kmp += source_pkey[i]; // used to select source's keys
	Kmp %=  72057594037927936LL;
	//	printf( "Kmp %014llx\n", Kmp );
      }
      ksv_temp >>= 1LL;
    }
    //    printf( "num 1's: %d\n", num );
    // Kmp is the source Km
  
    Km &= 0xFFFFFFFFFFFFFFLL;
    Kmp &= 0xFFFFFFFFFFFFFFLL;
  
    printf( "\n" );
    printf( "Km : %014llx\n", Km );
    printf( "Km': %014llx\n", Kmp );

    fflush(stdout);

    if( Km != Kmp ) {
      printf( "Km is not equal to Km', can't encrypt this stream.\n" );
      exit(0);
    }

    if( Km == 0 ) {
      printf( "Km is zero. This probably means derive_km was fired spuriously on disconnect.\n" );
      printf( "Aborting without doing anything, since Km = 0 is never a correct condition\n" );
      return 0;
    } else {
      printf( "Committing Km to FPGA\n" );
      // now commit Km to the fpga
      for( i = 0; i < 7; i++ ) {
	write_km( i, Km & 0xFF );
	Km >>= 8;
      }

      printf( "Flipping Km ready\n" );
      // indicate Km ready
      write_km( 7, 1 );
    }

    printf( "Invoking HPD\n" );
    uint32_t write_data;
    hpd_override = 1;
    write_data = ((hpd_override & 1) << 31) | (i2c_snoop_addr2 << 8) | (reg_addr & 0x1F);
    GPIO2_DATA = write_data;
    msync( virt_addr, MAP_SIZE, MS_SYNC );

    sleep(1);
    
    hpd_override = 0;
    write_data = ((hpd_override & 1) << 31) | (i2c_snoop_addr2 << 8) | (reg_addr & 0x1F);
    GPIO2_DATA = write_data;
    msync( virt_addr, MAP_SIZE, MS_SYNC );

    return 0;
    
}
