/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* DLT handler framework */

#include "config.h"

#include "globalregistry.h"
#include "util.h"
#include "endian_magic.h"
#include "messagebus.h"
#include "packet.h"
#include "packetchain.h"
#include "packetsource.h"
#include "gpscore.h"

#if defined(SYS_OPENBSD) || defined(SYS_NETBSD)
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#endif // Open/Net

/* Radiotap parser and iterator functions */
extern "C" {
#include "radiotap_parser.h"
#include "radiotap_parser_iter.h"
};

#include "kis_dlt_radiotap.h"

#include "tcpdump-extract.h"

#if 0
// Extension to radiotap header not yet included in all BSD's
#ifndef IEEE80211_RADIOTAP_F_FCS
#define IEEE80211_RADIOTAP_F_FCS        0x10    /* frame includes FCS */
#endif
#endif

Kis_DLT_Radiotap::Kis_DLT_Radiotap(GlobalRegistry *in_globalreg) :
	Kis_DLT_Handler(in_globalreg) {

	dlt_name = "Radiotap";
	dlt = DLT_IEEE802_11_RADIO;

	globalreg->InsertGlobal("DLT_RADIOTAP", this);

	_MSG("Registering support for DLT_RADIOTAP packet header decoding", MSGFLAG_INFO);
}

Kis_DLT_Radiotap::~Kis_DLT_Radiotap() {
	globalreg->InsertGlobal("DLT_RADIOTAP", NULL);
}

#define ALIGN_OFFSET(offset, width) \
	    ( (((offset) + ((width) - 1)) & (~((width) - 1))) - offset )

/*
 * Useful combinations of channel characteristics.
 */
#define	IEEE80211_CHAN_FHSS \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define	IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_BPLUS \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_B \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define	IEEE80211_CHAN_PUREG \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)
#define	IEEE80211_CHAN_T \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_TURBO)

#define	IEEE80211_IS_CHAN_FHSS(_flags) \
	((_flags & IEEE80211_CHAN_FHSS) == IEEE80211_CHAN_FHSS)
#define	IEEE80211_IS_CHAN_A(_flags) \
	((_flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
#define	IEEE80211_IS_CHAN_BPLUS(_flags) \
	((_flags & IEEE80211_CHAN_BPLUS) == IEEE80211_CHAN_BPLUS)
#define	IEEE80211_IS_CHAN_B(_flags) \
	((_flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
#define	IEEE80211_IS_CHAN_PUREG(_flags) \
	((_flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
#define	IEEE80211_IS_CHAN_G(_flags) \
	((_flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
#define	IEEE80211_IS_CHAN_T(_flags) \
	((_flags & IEEE80211_CHAN_T) == IEEE80211_CHAN_T)

#define BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define BITNO_2(x) (((x) & 2) ? 1 : 0)
#define BIT(n)	(1 << n)

static const struct radiotap_align_size align_size_000000_00[] = {
        [0] = { .align = 1, .size = 4, },
        [52] = { .align = 1, .size = 4, },
};

static const struct ieee80211_radiotap_namespace vns_array[] = {
        {
                .oui = 0x000000,
                .subns = 0,
                .n_bits = sizeof(align_size_000000_00),
                .align_size = align_size_000000_00,
        },
};

static const struct ieee80211_radiotap_vendor_namespaces vns = {
        .ns = vns_array,
        .n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
};

static inline void
radiotap_flags_parse(kis_layer1_packinfo *radioheader, uint32_t flags)
{
	if (IEEE80211_IS_CHAN_FHSS(flags))
		radioheader->carrier = carrier_80211fhss;
	else if (IEEE80211_IS_CHAN_A(flags))
		radioheader->carrier = carrier_80211a;
	else if (IEEE80211_IS_CHAN_BPLUS(flags))
		radioheader->carrier = carrier_80211bplus;
	else if (IEEE80211_IS_CHAN_B(flags))
		radioheader->carrier = carrier_80211b;
	else if (IEEE80211_IS_CHAN_PUREG(flags))
		radioheader->carrier = carrier_80211g;
	else if (IEEE80211_IS_CHAN_G(flags))
		radioheader->carrier = carrier_80211g;
	else if (IEEE80211_IS_CHAN_T(flags))
		radioheader->carrier = carrier_80211a;/*XXX*/
	else
		radioheader->carrier = carrier_unknown;

	if ((flags & IEEE80211_CHAN_CCK) == IEEE80211_CHAN_CCK)
		radioheader->encoding = encoding_cck;
	else if ((flags & IEEE80211_CHAN_OFDM) == IEEE80211_CHAN_OFDM)
		radioheader->encoding = encoding_ofdm;
	else if ((flags & IEEE80211_CHAN_DYN) == IEEE80211_CHAN_DYN)
		radioheader->encoding = encoding_dynamiccck;
	else if ((flags & IEEE80211_CHAN_GFSK) == IEEE80211_CHAN_GFSK)
		radioheader->encoding = encoding_gfsk;
	else
		radioheader->encoding = encoding_unknown;
}

static inline void
parse_iterator(struct ieee80211_radiotap_iterator *iter,
    kis_layer1_packinfo *radioheader)
{
	const char *dp = (const char *) iter->this_arg;

	union {
		int8_t	i8;
		int16_t	i16;
		u_int8_t	u8;
		u_int16_t	u16;
		u_int32_t	u32;
		u_int64_t	u64;
	} u, u2, u3, u4;

	u.u64 = 0;
	u2.u64 = 0;
	u3.u64 = 0;
	u4.u64 = 0;

	switch (iter->this_arg_index) {
	case IEEE80211_RADIOTAP_FLAGS:
	case IEEE80211_RADIOTAP_RATE:
#if 0
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
#endif
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
	case IEEE80211_RADIOTAP_ANTENNA:
		u.u8 = *dp;
		break;

	case IEEE80211_RADIOTAP_DBM_TX_POWER:
		u.i8 = *dp;
		break;

	case IEEE80211_RADIOTAP_CHANNEL:
		u.u16 = EXTRACT_LE_16BITS(dp);
		dp += sizeof(u.u16);
		u2.u16 = EXTRACT_LE_16BITS(dp);
		iter += sizeof(u2.u16);
		break;

	case IEEE80211_RADIOTAP_XCHANNEL:
		u.u32 = EXTRACT_LE_32BITS(dp);	/* flags */
		dp += sizeof(u.u32);
		u2.u16 = EXTRACT_LE_16BITS(dp);	/* freq */
		dp += sizeof(u.u16);
		u3.u8 = EXTRACT_LE_8BITS(dp);	/* ieee channumber */
		dp += sizeof(u.u8);
		u4.u8 = EXTRACT_LE_8BITS(dp);	/* max power */
		dp += sizeof(u.u8);
		break;

	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
		u.u16 = EXTRACT_LE_16BITS(dp);
		dp += sizeof(u.u16);
		break;

	case IEEE80211_RADIOTAP_TSFT:
		u.u64 = EXTRACT_LE_64BITS(dp);
		dp += sizeof(u.u64);
		break;

	default:
		return;
	}

	/* Now, populate the header details */
	switch (iter->this_arg_index) {
	case IEEE80211_RADIOTAP_XCHANNEL:
		radiotap_flags_parse(radioheader, u.u32);
		radioheader->freq_mhz = u2.u16;
		radioheader->channel = u3.u8;
		break;

	case IEEE80211_RADIOTAP_CHANNEL:
		radioheader->freq_mhz = u.u16;
		radiotap_flags_parse(radioheader, ((uint32_t) u2.u16) & 0xffff);
		break;

	case IEEE80211_RADIOTAP_RATE:
		/* strip basic rate bit & convert to kismet units */
		radioheader->datarate = ((u.u8 &~ 0x80) / 2) * 10;
		break;

	/* ignore DB values, they're not helpful */
#if 0
                case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
                    radioheader->signal_dbm = u.i8;
                    break;
                case IEEE80211_RADIOTAP_DB_ANTNOISE:
                    radioheader->noise_dbm = u.i8;
                    break;
#endif

	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
		radioheader->signal_dbm = u.i8;
		break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
		radioheader->noise_dbm = u.i8;
		break;

	/* XXX TODO: fcs */
	default:
		break;
	}
}

int Kis_DLT_Radiotap::HandlePacket(kis_packet *in_pack) {
	kis_datachunk *decapchunk = 
		(kis_datachunk *) in_pack->fetch(pack_comp_decap);

	if (decapchunk != NULL) {
		// printf("debug - dltppi frame already decapped\n");
		return 1;
	}

	kis_datachunk *linkchunk = 
		(kis_datachunk *) in_pack->fetch(pack_comp_linkframe);

	if (linkchunk == NULL) {
		// printf("debug - dltppi no link\n");
		return 1;
	}

	if (linkchunk->dlt != dlt) {
		return 1;
	}

	kis_ref_capsource *capsrc =
		(kis_ref_capsource *) in_pack->fetch(pack_comp_capsrc);

	if (capsrc == NULL) {
		// printf("debug - no capsrc?\n");
		return 1;
	}

	struct ieee80211_radiotap_header *hdr;
	int fcs_cut = 0; // Is the FCS bit set?
	char errstr[STATUS_MAX];
	struct ieee80211_radiotap_iterator iter;
	int err;

	kis_layer1_packinfo *radioheader = NULL;

	if (linkchunk->length < sizeof(*hdr)) {
		snprintf(errstr, STATUS_MAX, "pcap radiotap converter got corrupted "
				 "Radiotap header length");
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		return 0;
	}

	// Assign it to the callback data
	hdr = (struct ieee80211_radiotap_header *) linkchunk->data;
	if (linkchunk->length < EXTRACT_LE_16BITS(&hdr->it_len)) {
		snprintf(errstr, STATUS_MAX, "pcap radiotap converter got corrupted "
				 "Radiotap header length");
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		return 0;
	}

	decapchunk = new kis_datachunk;
	radioheader = new kis_layer1_packinfo;
	decapchunk->dlt = KDLT_IEEE802_11;

	/* Pass to the radiotap iterator */
	err = ieee80211_radiotap_iterator_init(&iter, hdr,
	    linkchunk->length, &vns);
	if (err) {
		snprintf(errstr, STATUS_MAX,
		    "malformed radiotap header (init returns %d)\n",
		    err);
		return (0);
	}

	while (! (err = ieee80211_radiotap_iterator_next(&iter))) {
		if (! iter.is_radiotap_ns)
			continue;
		parse_iterator(&iter, radioheader);
	}

	/* XXX verify this stuff! */
	if (EXTRACT_LE_16BITS(&(hdr->it_len)) + fcs_cut > (int) linkchunk->length) {
		/*
		_MSG("Pcap Radiotap converter got corrupted Radiotap frame, not "
			 "long enough for radiotap header plus indicated FCS", MSGFLAG_ERROR);
		*/
		delete decapchunk;
		delete radioheader;
		return 0;
	}

#if 0
	decapchunk->length = linkchunk->length - 
		EXTRACT_LE_16BITS(&(hdr->it_len)) - fcs_cut;
	decapchunk->data = new uint8_t[decapchunk->length];
	memcpy(decapchunk->data, linkchunk->data + 
		   EXTRACT_LE_16BITS(&(hdr->it_len)), decapchunk->length);
#endif
	decapchunk->set_data(linkchunk->data + EXTRACT_LE_16BITS(&(hdr->it_len)),
						 (linkchunk->length - EXTRACT_LE_16BITS(&(hdr->it_len)) - 
						  fcs_cut), false);

	in_pack->insert(pack_comp_radiodata, radioheader);
	in_pack->insert(pack_comp_decap, decapchunk);

	kis_packet_checksum *fcschunk = NULL;
	if (fcs_cut && linkchunk->length > 4) {
		fcschunk = new kis_packet_checksum;

		fcschunk->set_data(&(linkchunk->data[linkchunk->length - 4]), 4);

		// Valid until proven otherwise
		fcschunk->checksum_valid = 1;

		in_pack->insert(pack_comp_checksum, fcschunk);
	}

	// If we're validating the FCS
	if (capsrc->ref_source->FetchValidateCRC() && fcschunk != NULL) {
		// Compare it and flag the packet
		uint32_t calc_crc =
			crc32_le_80211(globalreg->crc32_table, decapchunk->data, 
						   decapchunk->length);

		if (memcmp(fcschunk->checksum_ptr, &calc_crc, 4)) {
			in_pack->error = 1;
			fcschunk->checksum_valid = 0;
			// fprintf(stderr, "debug - rtap to kis, fcs invalid\n");
		} else {
			fcschunk->checksum_valid = 1;
		}
	}

	return 1;
}
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT


