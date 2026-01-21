#include <pcap.h>
#include <pmacct.h>
#include <addr.h>
#include <plugin_hooks.h>

// pmacct headers (bindings generated)
#include <bgp/bgp.h>
#include <network.h>
#include <bmp/bmp.h>
#include <bmp/bmp_logdump.h>
#include <bgp/bgp_packet.h>
#include <bgp/bgp_util.h>
#include <bgp/bgp_aspath.h>
#include <bgp/bgp_community.h>
#include <bgp/bgp_lcommunity.h>
#include <bgp/bgp_ecommunity.h>
#include <log.h>
#include <pmacct_gauze_lib.h>
#include "parsing.h"
#include <sys/time.h>

static Opaque_BgpContextCache *bgp_context_cache = NULL;

extern Opaque_BgpContextCache *bgp_context_cache_get() {
  if (!bgp_context_cache)
    bgp_context_cache = netgauze_make_Opaque_BgpContextCache();

  return bgp_context_cache;
}

Opaque_BgpParsingContext *bgp_parsing_context_get(struct bgp_peer *bgp_peer) {
  Opaque_BgpContextCache *context_cache = bgp_context_cache_get();
  Opaque_BgpParsingContext *ctx = netgauze_bgp_context_cache_get(context_cache, bgp_peer);
  if (ctx) return ctx;

  return netgauze_bgp_context_cache_set(context_cache, bgp_peer, netgauze_make_Opaque_BgpParsingContext());
}

void bgp_parsing_context_clear(struct bgp_peer *bgp_peer) {
  if (bgp_context_cache)
    netgauze_bgp_context_cache_delete(bgp_context_cache, bgp_peer);
}

/* BGP START ---------------------------------------------------------------------------- */
int bgp_parse_msg_hook(struct bgp_peer *peer, time_t now, int online) {
  struct bgp_misc_structs *bms;
  struct bgp_msg_data bmd;
  char *bgp_packet_ptr;
  int bgp_len;

  if (!peer || !peer->buf.base) return ERR;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return ERR;

  memset(&bmd, 0, sizeof(bmd));
  bmd.peer = peer;

  for (bgp_packet_ptr = peer->buf.base; peer->msglen > 0; peer->msglen -= bgp_len, bgp_packet_ptr += bgp_len) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] PARSING BGP WITH NETGAUZE.\n",
            config.name, bms->log_str, "dynlib");
    BgpParseResult parse_result = netgauze_bgp_parse_packet_with_context(bgp_packet_ptr, peer->msglen, bgp_parsing_context_get(peer));

    if (parse_result.tag == CResult_Err) {
      Log(LOG_INFO, "netgauze parse error: %s\n", netgauze_bgp_parse_error_str(parse_result.err));
      netgauze_bgp_parse_result_free(parse_result);
      return parse_result.err.netgauze_bgp_error.pmacct_error_code;
    }

    int err = SUCCESS;
    ParsedBgp *parsed_bgp = &parse_result.ok;

    struct bgp_header* bhdr = &parsed_bgp->header;
    bgp_len = bhdr->bgpo_len;

    switch (bhdr->bgpo_type) {
      case BGP_OPEN:
        if (ng_bgp_process_msg_open(&bmd, parsed_bgp->message, now, online) < 0)
          err = BGP_NOTIFY_OPEN_ERR;
        break;
      case BGP_NOTIFICATION: {
        err = ng_bgp_process_msg_notif(&bmd, parsed_bgp->message);
        break;
      }
      case BGP_KEEPALIVE:
        err = ng_bgp_process_msg_keepalive(&bmd, parsed_bgp->message, now, online);
        break;
      case BGP_UPDATE:
        err = ng_bgp_process_msg_update(&bmd, parsed_bgp->message);
        break;
      case BGP_ROUTE_REFRESH:
        /* just ignore */
        break;
      default: {
        char bgp_peer_str[INET6_ADDRSTRLEN];
        bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (unsupported message type).\n",
            config.name, bms->log_str, bgp_peer_str);
        err = BGP_NOTIFY_HEADER_ERR;
      }
    }

    netgauze_bgp_parse_result_free(parse_result);

    if (err != SUCCESS)
      return err;
  }

  return SUCCESS;
}

int ng_bgp_write_open_msg(char *msg, int buff_len, struct bgp_peer *peer, const Opaque_BgpMessage *open_rx) {
  char my_id_static[] = "1.2.3.4";
  struct host_addr my_id_addr, bgp_ip, bgp_id;

  Log(LOG_INFO, "INFO ( %s ): bgp_daemon_ip = %p sizeof = %d.\n field offsets : \n - bgp_daemon_id : %d \n - promisc : %d \n - imt_plugin_path : %d \n - writer_id_string : %d\n",
      config.name, config.bgp_daemon_ip, sizeof(config), offsetof(struct configuration, bgp_daemon_ip), offsetof(struct configuration, promisc), offsetof(struct configuration, imt_plugin_path), offsetof(struct configuration, writer_id_string));
  if (config.bgp_daemon_ip) str_to_addr(config.bgp_daemon_ip, &bgp_ip);
  else memset(&bgp_ip, 0, sizeof(bgp_ip));

  if (config.bgp_daemon_id) str_to_addr(config.bgp_daemon_id, &bgp_id);
  else memset(&bgp_id, 0, sizeof(bgp_id));

  /* set BGP router-ID trial #1 */
  memset(&my_id_addr, 0, sizeof(my_id_addr));

  if (config.bgp_daemon_id && !is_any(&bgp_id) && !my_id_addr.family) {
    str_to_addr(config.bgp_daemon_id, &my_id_addr);
    if (my_id_addr.family != AF_INET) memset(&my_id_addr, 0, sizeof(my_id_addr));
  }

  /* set BGP router-ID trial #2 */
  if (config.bgp_daemon_ip && !is_any(&bgp_ip) && !my_id_addr.family) {
    str_to_addr(config.bgp_daemon_ip, &my_id_addr);
    if (my_id_addr.family != AF_INET) memset(&my_id_addr, 0, sizeof(my_id_addr));
  }

  /* set BGP router-ID trial #3 */
  if (!my_id_addr.family) {
    str_to_addr(my_id_static, &my_id_addr);
  }

  BgpOpenWriteResult write_result = netgauze_bgp_open_write_reply(peer, open_rx, msg, buff_len, my_id_addr.address.ipv4);
  if (write_result.tag == CResult_Err) {
    Log(LOG_INFO, "netgauze error while crafting bgp open reply %s\n", netgauze_bgp_open_write_result_err_str(write_result.err));
    netgauze_bgp_open_write_result_free(write_result);
    return ERR;
  }

  return write_result.ok;
}


int ng_bgp_process_msg_open(struct bgp_msg_data *bmd, const Opaque_BgpMessage *bgp_msg, time_t now, int online) {
  struct bgp_peer *peer = bmd->peer;
  struct bgp_misc_structs *bms;
  if (!peer || !bgp_msg) return ERR;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return ERR;

  if (online && (peer->status < OpenSent)) {
    BgpOpenProcessResult proc_res = netgauze_bgp_process_open(bgp_msg);
    if (proc_res.tag == CResult_Err) {
      Log(LOG_INFO, "netgauze could not process bgp open for error code %d\n", proc_res.err.tag);
      return ERR;
    }

    char bgp_peer_str[INET6_ADDRSTRLEN];

    BgpOpenInfo open_info = proc_res.ok;

    peer->status = Active;

    if (open_info.version != BGP_VERSION4) {
      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP Open packet (unsupported version).\n",
          config.name, bms->log_str, bgp_peer_str);
      return ERR;
    }

    peer->ht = MAX(5, open_info.hold_time);
    peer->id = open_info.bgp_id;
    peer->version = open_info.version;

    Log(LOG_INFO, "GOT TO STEP 4\n");
    /* Check: duplicate Router-IDs; BGP only, ie. no BMP */
    if (!config.bgp_disable_router_id_check && bms->bgp_msg_open_router_id_check) {
      int check_ret;

      check_ret = bms->bgp_msg_open_router_id_check(bmd);
      if (check_ret) return check_ret;
    }
    Log(LOG_INFO, "GOT THROUGH STEP 4\n");

    /* Record capabilities sent by the peer */
    peer->cap_add_paths = open_info.capability_add_paths;
    for (afi_t afi = 0; afi <= open_info.capability_add_paths.afi_max; afi++)
      for (safi_t safi = 0; safi <= open_info.capability_add_paths.safi_max; safi++)
        if (online) {
          bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
          Log(LOG_INFO, "INFO ( %s/%s ): [%s] Capability: ADD-PATHs [%u] AFI [%u] SAFI [%u] SEND_RECEIVE [%u]\n",
              config.name, bms->log_str, bgp_peer_str, BGP_CAPABILITY_ADD_PATHS, afi, safi,
              open_info.capability_add_paths.cap[afi][safi]);
        }

    /* We don't really care about the details for MP CAP because it is not is_used anyway */
    for (afi_t afi = 0; afi <= open_info.capability_mp_protocol.afi_max; afi++)
      for (safi_t safi = 0; safi <= open_info.capability_mp_protocol.safi_max; safi++)
        if (open_info.capability_mp_protocol.cap[afi][safi] != 0) {
          peer->cap_mp = TRUE;
          if (online) {
            bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
            Log(LOG_INFO, "INFO ( %s/%s ): [%s] Capability: MultiProtocol [%u] AFI [%u] SAFI [%u]\n",
                config.name, bms->log_str, bgp_peer_str, BGP_CAPABILITY_MULTIPROTOCOL, afi, safi);
          }
        }

    /* This EXT NH ENC (Extended Next-Hop Encoding) is not recorded in the peer state and is only logged and sent back
    * in the BGP OPEN Reply */
    for (afi_t afi = 0; afi <= open_info.capability_ext_nh_enc_data.afi_max; afi++)
      for (safi_t safi = 0; safi <= open_info.capability_ext_nh_enc_data.safi_max; safi++)
        if (open_info.capability_ext_nh_enc_data.cap[afi][safi] != 0) {
          if (online) {
            bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
            Log(LOG_INFO, "INFO ( %s/%s ): [%s] Capability: Extended Next Hop Encoding [%u] "
                          "AFI [%u] SAFI [%u] Next Hop AFI [%u]\n",
                config.name, bms->log_str, bgp_peer_str, BGP_CAPABILITY_EXTENDED_NEXT_HOP_ENCODING,
                afi, safi, open_info.capability_ext_nh_enc_data.cap[afi][safi]);
          }
        }

    if (open_info.capability_route_refresh) {
      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Capability: Route Refresh [%u]\n",
          config.name, bms->log_str, bgp_peer_str, BGP_CAPABILITY_ROUTE_REFRESH);
    }

    /* Let's grasp the remote ASN */
    peer->cap_4as = open_info.capability_as4;
    uint16_t remote_as = open_info.asn;
    struct cap_4as remote_as4 = peer->cap_4as;
    if (remote_as4.is_used && online) {
      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Capability: 4-bytes AS [%u] ASN [%u]\n",
          config.name, bms->log_str, bgp_peer_str, BGP_CAPABILITY_4_OCTET_AS_NUMBER, remote_as4.as4);
    }

    if (remote_as == BGP_AS_TRANS) {
      if (remote_as4.is_used && remote_as4.as4 != 0 && remote_as4.as4 != BGP_AS_TRANS)
        peer->as = remote_as4.as4;
        /* It is not valid to use the transitional ASN in the BGP OPEN and
            present an ASN == 0 or ASN == 23456 in the 4AS capability */
      else {
        bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP Open packet (invalid AS4 option).\n",
            config.name, bms->log_str, bgp_peer_str);
        return ERR;
      }
    }
    else {
      if ((!remote_as4.is_used && remote_as4.as4 == 0) || (remote_as4.is_used && remote_as4.as4 == remote_as))
        peer->as = remote_as;
        /* It is not valid to not use the transitional ASN in the BGP OPEN and
          present an ASN != remote_as in the 4AS capability */
      else {
        bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP Open packet (mismatching AS4 option).\n",
            config.name, bms->log_str, bgp_peer_str);
        return ERR;
      }
    }

    peer->status = Established;

    if (online) {
      char bgp_reply_pkt[BGP_BUFFER_SIZE], *bgp_reply_ptr = bgp_reply_pkt;

      /* Replying to OPEN message */
      if (!config.bgp_daemon_as) peer->myas = peer->as;
      else peer->myas = config.bgp_daemon_as;

      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] BGP_OPEN: Local AS: %u Remote AS: %u HoldTime: %u\n", config.name,
          bms->log_str, bgp_peer_str, peer->myas, peer->as, peer->ht);
      
      /* TODO : CHANGE THE NULL POINTER TO THE CORRECT POINTER AND/OR IMPLEMENT THIS IN NETGAUZE*/
      bgp_reply_ptr += ng_bgp_write_open_msg(bgp_reply_pkt, BGP_BUFFER_SIZE, peer, bgp_msg);
      Log(LOG_INFO, "INFO ( %s/%s ): GOT THROUGH WRITE_OPEN_MSG\n", config.name,
          bms->log_str);
      /* sticking a KEEPALIVE to it */
      bgp_reply_ptr += bgp_write_keepalive_msg(bgp_reply_ptr);
      Log(LOG_INFO, "INFO ( %s/%s ): GOT THROUGH WRITING KEEPALIVE\n", config.name,
          bms->log_str);
      peer->last_keepalive = now;
      return send(peer->fd, bgp_reply_pkt, bgp_reply_ptr - bgp_reply_pkt, 0);
    }

    return SUCCESS;
  }
  return ERR;
}

/* process bgp messages */
int ng_bgp_process_msg_notif(struct bgp_msg_data *bmd, const Opaque_BgpMessage *bgp_msg) {

  struct bgp_peer *peer = bmd->peer;
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);

  BgpNotificationResult notif_result = netgauze_bgp_notification(bgp_msg);
  if (notif_result.tag == CResult_Err) {
    Log(LOG_INFO, "netgauze could not process bgp notification correctly: bad msg type %d\n",
        notif_result.err._0);
    return notif_result.err._0;
  }

  // get shutdown message
  BgpNotification *notif = &notif_result.ok;
  char shutdown_msg[notif->value_len + 1];
  memcpy(shutdown_msg, notif->value, notif->value_len);
  shutdown_msg[notif->value_len] = 0; // ensure we have a zero-terminated string

  char bgp_peer_str[INET6_ADDRSTRLEN];
  bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
  Log(LOG_INFO, "INFO ( %s/%s ): [%s] BGP_NOTIFICATION received (%u, %u). Shutdown Message: '%s'\n",
      config.name, bms->log_str, bgp_peer_str, notif->code, notif->subcode, shutdown_msg);

  return ERR;
}

int ng_bgp_process_msg_keepalive(struct bgp_msg_data *bmd, const Opaque_BgpMessage *bgp_msg, time_t now, bool online) {

  struct bgp_peer *peer = bmd->peer;
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);

  char bgp_peer_str[INET6_ADDRSTRLEN];
  bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
  Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] BGP_KEEPALIVE received\n", config.name, bms->log_str, bgp_peer_str);

  /* If we didn't pass through a successful BGP OPEN exchange just yet
     let's temporarily silently discard BGP KEEPALIVEs */
  if (peer->status >= OpenSent) {
    if (peer->status < Established) peer->status = Established;
    if (online) {
      char bgp_reply_pkt[BGP_BUFFER_SIZE], *bgp_reply_pkt_ptr;

      memset(bgp_reply_pkt, 0, BGP_BUFFER_SIZE);
      bgp_reply_pkt_ptr = bgp_reply_pkt;
      bgp_reply_pkt_ptr += bgp_write_keepalive_msg(bgp_reply_pkt_ptr);
      send(peer->fd, bgp_reply_pkt, bgp_reply_pkt_ptr - bgp_reply_pkt, 0);
      peer->last_keepalive = now;

      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] BGP_KEEPALIVE sent\n", config.name, bms->log_str, bgp_peer_str);
    }
  }

  return SUCCESS;
}

int ng_bgp_process_msg_update(struct bgp_msg_data *bmd, const Opaque_BgpMessage *bgp_msg) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer = bmd->peer;

  if (!peer || !bgp_msg) return BGP_NOTIFY_UPDATE_ERR;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return BGP_NOTIFY_UPDATE_ERR;

  if (peer->status < Established) {
    char bgp_peer_str[INET6_ADDRSTRLEN];
    bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] BGP UPDATE received (no neighbor). Discarding.\n",
        config.name, bms->log_str, bgp_peer_str);
    return BGP_NOTIFY_FSM_ERR;
  }

  BgpUpdateResult bgp_update_res = netgauze_bgp_update_get_updates(peer, bgp_msg);
  if (bgp_update_res.tag == CResult_Err) {
    Log(LOG_INFO, "netgauze bad bgp message type %d in %s\n", bgp_update_res.err._0, __func__);
    return BGP_NOTIFY_UPDATE_ERR;
  }
  ParsedBgpUpdate bgp_parsed = bgp_update_res.ok;
  process_update_packets(bmd, bms, peer, bgp_parsed);

  return SUCCESS;
}

int process_update_packets(struct bgp_msg_data *bmd, struct bgp_misc_structs *bms, struct bgp_peer *peer, ParsedBgpUpdate bgp_parsed) {
  ProcessPacket *pkt = NULL;
  for (int i = 0; i < bgp_parsed.packets.len; i += 1) {
    pkt = &bgp_parsed.packets.base_ptr[i];

    // TODO handle process_update/withdraw error ? they were not handled before...
    switch (pkt->update_type) {
      case BgpNLRIUpdateType_Update:
        bgp_process_update(bmd, &pkt->prefix, &pkt->attr, &pkt->attr_extra, pkt->afi, pkt->safi, i);
        break;
      case BgpNLRIUpdateType_Withdraw:
        bgp_process_withdraw(bmd, &pkt->prefix, &pkt->attr, &pkt->attr_extra, pkt->afi, pkt->safi, i);
        break;
      case BgpNLRIUpdateType_EOR: {
        // this is EoR
        struct bgp_info ri = { 0 };
        ri.bmed = bmd->extra;
        ri.peer = bmd->peer;
        bgp_peer_log_msg(NULL, &ri, pkt->afi, pkt->safi, bms->tag, "log", bms->msglog_output, NULL, BGP_LOG_TYPE_EOR);
        peer->eor[pkt->afi][pkt->safi] = TRUE;
        break;
      }
      default: {
        Log(LOG_INFO,
            "INFO ( %s/%s ): [%s] [bgp_parse_update] packet discarded: unknown update type received from pmacct-gauze\n",
            config.name, bms->log_str, peer->addr_str);
      }
    }
  }

  // Unintern all temporary structures
  if (pkt) {
    if (pkt->attr.community) community_unintern(peer, pkt->attr.community);
    if (pkt->attr.lcommunity) lcommunity_unintern(peer, pkt->attr.lcommunity);
    if (pkt->attr.ecommunity) ecommunity_unintern(peer, pkt->attr.ecommunity);
    if (pkt->attr.aspath) aspath_unintern(peer, pkt->attr.aspath);
  }

  CSlice_free_ProcessPacket(bgp_parsed.packets);

  return SUCCESS;
}

/* BGP END ---------------------------------------------------------------------------- */






#include "bmp/bmp.h"
#include "pmacct_gauze_lib/pmacct_gauze_lib.h"

static Opaque_BmpContextCache *bmp_context_cache = NULL;

extern Opaque_BmpContextCache *bmp_context_cache_get() {
  if (!bmp_context_cache)
    bmp_context_cache = netgauze_make_Opaque_BmpContextCache();

  return bmp_context_cache;
}

Opaque_BmpParsingContext *bmp_parsing_context_get(struct bmp_peer *bmp_peer) {
  Opaque_BmpContextCache *context_cache = bmp_context_cache_get();
  Opaque_BmpParsingContext *ctx = netgauze_bmp_context_cache_get(context_cache, bmp_peer);
  if (ctx) return ctx;

  return netgauze_bmp_context_cache_set(context_cache, bmp_peer, netgauze_make_Opaque_BmpParsingContext());
}

void bmp_parsing_context_clear(struct bmp_peer *bmp_peer) {
  if (bmp_context_cache)
    netgauze_bmp_context_cache_delete(bmp_context_cache, bmp_peer);
}


u_int32_t bmp_process_packet_hook(char *bmp_packet, u_int32_t len, struct bmp_peer *bmpp, int *do_term) {

  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  char *bmp_packet_ptr = bmp_packet;
  u_int32_t pkt_remaining_len, msg_start_len;

  struct bmp_common_hdr *bch = NULL;

  if (do_term) (*do_term) = FALSE;
  if (!bmpp) return FALSE;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return FALSE;

  for (msg_start_len = pkt_remaining_len = len; pkt_remaining_len; msg_start_len = pkt_remaining_len) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] PROCESSING BMP WITH NETGAUZE.\n",
            config.name, bms->log_str, "xxx");
    BmpParseResult parse_result = netgauze_bmp_parse_packet_with_context(bmp_packet_ptr, pkt_remaining_len,
                                                                         bmp_parsing_context_get(bmpp));

    if (parse_result.tag == CResult_Err) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] packet discarded: %s\n", config.name, bms->log_str, peer->addr_str,
          netgauze_bmp_parse_error_str(parse_result.err));
      netgauze_bmp_parse_result_free(parse_result);
      return msg_start_len;
    }

    ParsedBmp parsed_bmp = parse_result.ok;
    bch = &parsed_bmp.common_header;

    Log(LOG_INFO, "INFO ( %s/%s ): [%s] packet received version %u, length %u, type %u\n", config.name, bms->log_str,
        peer->addr_str, bch->version, bch->len, bch->type);

    peer->version = bch->version;

    if (bch->type <= BMP_MSG_TYPE_MAX) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] [common] type: %s (%u)\n",
          config.name, bms->log_str, peer->addr_str, bmp_msg_types[bch->type], bch->type);
    }

    switch (bch->type) {
      case BMP_MSG_ROUTE_MONITOR:
        ng_bmp_process_msg_route_monitor(bmpp, &parsed_bmp);
        break;
      case BMP_MSG_STATS:
        ng_bmp_process_msg_stats(bmpp, &parsed_bmp);
        break;
      case BMP_MSG_PEER_DOWN:
        ng_bmp_process_msg_peer_down(bmpp, &parsed_bmp);
        break;
      case BMP_MSG_PEER_UP:
        ng_bmp_process_msg_peer_up(bmpp, &parsed_bmp);
        break;
      case BMP_MSG_INIT:
        ng_bmp_process_msg_init(bmpp, &parsed_bmp);
        break;
      case BMP_MSG_TERM:
        ng_bmp_process_msg_term(bmpp, &parsed_bmp);
        if (do_term) (*do_term) = TRUE;
        break;
      case BMP_MSG_ROUTE_MIRROR:
        ng_bmp_process_msg_route_mirror(bmpp);
        break;

      default:
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] packet discarded: unknown message type (%u)\n",
            config.name, bms->log_str, peer->addr_str, bch->type);
        break;
    }

    /* move forward to next bmp message in the packet */
    bmp_jump_offset(&bmp_packet_ptr, &pkt_remaining_len, parsed_bmp.read_bytes);

    netgauze_bmp_parse_result_free(parse_result);
  }
  return FALSE;
}

void ng_bmp_process_msg_route_monitor(struct bmp_peer *bmpp, const ParsedBmp *netgauze_parsed) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer, *bmpp_bgp_peer;
  void *ret = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  BmpPeerHdrDataResult bdata_result = netgauze_bmp_peer_hdr_get_data(netgauze_parsed->message);
  if (bdata_result.tag == CResult_Err) {
    Log(LOG_INFO,
        "INFO ( %s/%s ): [%s] [route monitor] netgauze could not get bmp peer up header\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }
  struct bmp_data bdata = bdata_result.ok;

  if (!bdata.family) return;

  gettimeofday(&bdata.tstamp_arrival, NULL);

  /* Find the relevant BGP peer (matching peer_ip and peer_distinguisher) */
  if (bdata.family == AF_INET) {
    ret = pm_tfind(&bdata, &bmpp->bgp_peers_v4, bgp_peer_host_addr_peer_dist_cmp);
  } else if (bdata.family == AF_INET6) {
    ret = pm_tfind(&bdata, &bmpp->bgp_peers_v6, bgp_peer_host_addr_peer_dist_cmp);
  }

  /* missing BMP peer up message, ie. case of replay/replication of BMP messages */
  if (!ret) {
    if (!log_notification_isset(&bmpp->missing_peer_up, bdata.tstamp_arrival.tv_sec)) {
      char peer_ip[INET6_ADDRSTRLEN];

      addr_to_str(peer_ip, &bdata.peer_ip);

      log_notification_set(&bmpp->missing_peer_up, bdata.tstamp_arrival.tv_sec, BMP_MISSING_PEER_UP_LOG_TOUT);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route monitor] packet discarded: missing peer up BMP message for peer %s\n",
          config.name, bms->log_str, peer->addr_str, peer_ip);
    }
    return;
  }

  /* peer up found -> parse route monitoring data */

  struct bmp_chars bmed_bmp = { 0 };
  struct bgp_msg_data bmd = { 0 };

  struct cdada_list_t *tlvs = NULL;
  char **bgp_pdu_ptrptr = NULL, *bgp_pdu_ptr = NULL;
  u_int32_t *bgp_pdu_lenptr = NULL, bgp_pdu_len;

  bmpp_bgp_peer = (*(struct bgp_peer **) ret);

  bmd.peer = bmpp_bgp_peer;
  bmd.extra.id = BGP_MSG_EXTRA_DATA_BMP;
  bmd.extra.len = sizeof(bmed_bmp);
  bmd.extra.data = &bmed_bmp;
  bgp_msg_data_set_data_bmp(&bmed_bmp, &bdata);

  compose_timestamp(bms->log_tstamp_str, SRVBUFLEN, &bdata.tstamp, TRUE,
                    config.timestamps_since_epoch, config.timestamps_rfc9557,
                    config.timestamps_utc);

  encode_tstamp_arrival(bms->log_tstamp_str, SRVBUFLEN, &bdata.tstamp_arrival, TRUE);

  BmpRouteMonitorUpdateResult bmp_rm_upd_res = netgauze_bmp_route_monitor_get_bgp_update(netgauze_parsed->message);
  if (bmp_rm_upd_res.tag == CResult_Err) {
    Log(LOG_INFO,
        "INFO ( %s/%s ): [%s] [route monitor] packet discarded: bad bmp message type received %d\n",
        config.name, bms->log_str, peer->addr_str, bmp_rm_upd_res.err._0);
    return;
  }

  BgpUpdateResult bgp_result = netgauze_bgp_update_get_updates(&bmpp->self, bmp_rm_upd_res.ok);
  assert(bgp_result.tag == CResult_Ok); // assert because we know by contract that the msg gotten from the bmp_rm is a bgp_upd

  process_update_packets(&bmd, bms, peer, bgp_result.ok);

  bmp_tlv_list_destroy_v2(bmed_bmp.tlvs);
}

void ng_bmp_process_msg_stats(struct bmp_peer *bmpp, const ParsedBmp *parsed_bmp) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;

  /* unknown stats TLVs */
  char *cnt_value;
  struct cdada_list_t *tlvs = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  BmpPeerHdrDataResult bdata_result = netgauze_bmp_peer_hdr_get_data(parsed_bmp->message);
  if (bdata_result.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [stats] netgauze could not get bmp peer header data\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }
  struct bmp_data bdata = bdata_result.ok;

  BmpStatsResult stats_result = netgauze_bmp_stats_get_stats(parsed_bmp->message);
  if (stats_result.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [stats] netgauze could not get stats count\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  OwnedSlice_bmp_log_stats stats = stats_result.ok;

  if (!bdata.family) goto cleanup;

  gettimeofday(&bdata.tstamp_arrival, NULL);

  for (int index = 0; index < stats.len; index++) {
    // TODO handle tlvs when bmpv4 is supported by netgauze
    tlvs = NULL;
    struct bmp_log_stats stat = stats.base_ptr[index];

    if (bms->msglog_backend_methods)
      bmp_log_msg(peer, &bdata, tlvs, &bmp_logdump_tag, &stat, bgp_peer_log_seq_get(&bms->log_seq), "log",
                  config.bmp_daemon_msglog_output, BMP_LOG_TYPE_STATS);

    if (bms->dump_backend_methods&& !config.bmp_dump_exclude_stats) bmp_dump_se_ll_append(peer, &bdata, tlvs, &stat, BMP_LOG_TYPE_STATS);

    if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

    if (tlvs && (!cdada_list_size(tlvs) || !bms->dump_backend_methods)) bmp_tlv_list_destroy_v2(tlvs);
  }

cleanup:
  CSlice_free_bmp_log_stats(stats);
}

void ng_bmp_process_msg_peer_down(struct bmp_peer *bmpp, const ParsedBmp *parsed_bmp) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer, *bmpp_bgp_peer;
  void *ret = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  BmpPeerHdrDataResult peer_hdr_result = netgauze_bmp_peer_hdr_get_data(parsed_bmp->message);
  if (peer_hdr_result.tag == CResult_Err) {
    Log(LOG_INFO,
        "INFO ( %s/%s ): [%s] [peer down] packet discarded: pmacct-gauze could not convert peer header\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }
  struct bmp_data bdata = peer_hdr_result.ok;

  if (!bdata.family) return;

  gettimeofday(&bdata.tstamp_arrival, NULL);

  BmpPeerDownInfoResult peer_down_result = netgauze_bmp_peer_down_get_info(parsed_bmp->message);
  if (peer_down_result.tag == CResult_Err) {
    Log(LOG_INFO,
        "INFO ( %s/%s ): [%s] [peer down] packet discarded: pmacct-gauze could not get peer down info\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }
  struct bmp_log_peer_down blpd = peer_down_result.ok;

  /* TLV vars */
  struct cdada_list_t *tlvs = NULL;
  /* draft-ietf-grow-bmp-tlv */
  if (peer->version == BMP_V4) {
    // TODO handle when netgauze supports bmpv4
  }

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, tlvs, &bmp_logdump_tag, &blpd, bgp_peer_log_seq_get(&bms->log_seq), event_type,
                config.bmp_daemon_msglog_output, BMP_LOG_TYPE_PEER_DOWN);
  }

  if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, &blpd, BMP_LOG_TYPE_PEER_DOWN);

  if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

  if (tlvs && (!cdada_list_size(tlvs) || !bms->dump_backend_methods)) bmp_tlv_list_destroy_v2(tlvs);

  /* Find the relevant BGP peer (matching peer_ip and peer_distinguisher) */
  if (bdata.family == AF_INET) {
    ret = pm_tfind(&bdata, &bmpp->bgp_peers_v4, bgp_peer_host_addr_peer_dist_cmp);
  } else if (bdata.family == AF_INET6) {
    ret = pm_tfind(&bdata, &bmpp->bgp_peers_v6, bgp_peer_host_addr_peer_dist_cmp);
  }

  if (ret) {
    bmpp_bgp_peer = (*(struct bgp_peer **) ret);

    bgp_peer_info_delete(bmpp_bgp_peer);

    if (bdata.family == AF_INET) {
      pm_tdelete(&bdata, &bmpp->bgp_peers_v4, bgp_peer_host_addr_peer_dist_cmp);
    } else if (bdata.family == AF_INET6) {
      pm_tdelete(&bdata, &bmpp->bgp_peers_v6, bgp_peer_host_addr_peer_dist_cmp);
    }
  }
  /* missing BMP peer up message, ie. case of replay/replication of BMP messages */
  else {
    char peer_ip[INET6_ADDRSTRLEN];

    addr_to_str(peer_ip, &bdata.peer_ip);

    if (!log_notification_isset(&bmpp->missing_peer_up, bdata.tstamp_arrival.tv_sec)) {
      log_notification_set(&bmpp->missing_peer_up, bdata.tstamp_arrival.tv_sec, BMP_MISSING_PEER_UP_LOG_TOUT);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer down] packet discarded: missing peer up BMP message for peer %s\n",
          config.name, bms->log_str, peer->addr_str, peer_ip);

    }
  }
}

void
ng_bmp_process_msg_peer_up(struct bmp_peer *bmpp, const ParsedBmp *netgauze_parsed) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  BmpPeerHdrDataResult bdata_res = netgauze_bmp_peer_hdr_get_data(netgauze_parsed->message);
  if (bdata_res.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] netgauze could not get bmp peer header data\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }
  struct bmp_data bdata = bdata_res.ok;

  if (!bdata.family) return;

  gettimeofday(&bdata.tstamp_arrival, NULL);

  struct bgp_peer bgp_peer_loc = { 0 }, bgp_peer_rem = { 0 }, *bmpp_bgp_peer;
  struct bmp_chars bmed_bmp = { 0 };
  void *ret = NULL;

  BmpPeerUpHdrResult peer_up_hdr_res = netgauze_bmp_peer_up_get_hdr(netgauze_parsed->message);
  if (peer_up_hdr_res.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] netgauze could not get bmp peer up header\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }
  struct bmp_log_peer_up blpu = peer_up_hdr_res.ok;

  bgp_peer_loc.type = FUNC_TYPE_BMP;
  struct bgp_msg_data bmd = {
          .peer = &bgp_peer_loc,
          .extra = {
                  .id = BGP_MSG_EXTRA_DATA_BMP,
                  .len = sizeof(bmed_bmp),
                  .data = &bmed_bmp
          }
  };
  bgp_msg_data_set_data_bmp(&bmed_bmp, &bdata);

  BmpPeerUpOpenResult peer_up_open_tx = netgauze_bmp_peer_up_get_open_tx(netgauze_parsed->message);
  if (peer_up_open_tx.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] netgauze could not get bmp open tx\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  if (ng_bgp_process_msg_open(&bmd, peer_up_open_tx.ok.message, 5, FALSE)) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] Could not process the BGP OPEN TX\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  memcpy(&bmpp->self.id, &bgp_peer_loc.id, sizeof(struct host_addr));
  memcpy(&bgp_peer_loc.addr, &blpu.local_ip, sizeof(struct host_addr));

  bgp_peer_rem.type = FUNC_TYPE_BMP;
  bmd.peer = &bgp_peer_rem;

  BmpPeerUpOpenResult peer_up_open_rx = netgauze_bmp_peer_up_get_open_rx(netgauze_parsed->message);
  if (peer_up_open_rx.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] netgauze could not get bmp open rx\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  if (ng_bgp_process_msg_open(&bmd, peer_up_open_rx.ok.message, 5, FALSE)) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] Could not process the BGP OPEN RX\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  memcpy(&bgp_peer_rem.addr, &bdata.peer_ip, sizeof(struct host_addr));

  /* sync capabilities between loc/rem and remote->id becomes remote->addr */
  bmpp_bgp_peer = bmp_sync_loc_rem_peers(&bgp_peer_loc, &bgp_peer_rem);
  bmpp_bgp_peer->log = bmpp->self.log;
  bmpp_bgp_peer->bmp_se = bmpp; /* using bmp_se field to back-point a BGP peer to its parent BMP peer */
  bmpp_bgp_peer->peer_distinguisher = bdata.chars.pd;

  /* Search (or create if not existing) the BGP peer structure for this peer_up msg */if (bdata.family == AF_INET) {
    ret = pm_tsearch(bmpp_bgp_peer, &bmpp->bgp_peers_v4, bgp_peer_cmp_bmp, sizeof(struct bgp_peer));
  } else if (bdata.family == AF_INET6) {
    ret = pm_tsearch(bmpp_bgp_peer, &bmpp->bgp_peers_v6, bgp_peer_cmp_bmp, sizeof(struct bgp_peer));
  }

  if (!ret)
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] [peer up] tsearch() unable to insert.\n", config.name, bms->log_str,
            peer->addr_str);

  BmpTlvListResult tlv_result = netgauze_bmp_get_tlvs(netgauze_parsed->message);
  if (tlv_result.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] netgauze could not get bmp peer up tlvs\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  struct cdada_list_t *tlvs = bmp_tlv_list_new_v2();
  if (!tlvs) return;

  OwnedSlice_bmp_log_tlv tlv_list = tlv_result.ok;
  for (struct bmp_log_tlv *tlv = tlv_list.base_ptr; tlv && tlv < tlv_list.end_ptr; tlv += 1) {
      if (bmp_tlv_list_add_v2(tlvs, tlv->pen, tlv->type, tlv->len, tlv->index, tlv->val) == ERR) {
        Log(LOG_ERR, "INFO ( %s/%s ): [%s] [peer up] bmp_tlv_list_add failed\n",
            config.name, bms->log_str, peer->addr_str);
        bmp_tlv_list_destroy_v2(tlvs);
        return;
      }
  }

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, tlvs, &bmp_logdump_tag, &blpu, bgp_peer_log_seq_get(&bms->log_seq), event_type,
                    config.bmp_daemon_msglog_output, BMP_LOG_TYPE_PEER_UP);
  }

  if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, &blpu, BMP_LOG_TYPE_PEER_UP);

  if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

  if (!cdada_list_size(tlvs) || !bms->dump_backend_methods) bmp_tlv_list_destroy_v2(tlvs);
}

void ng_bmp_process_msg_init(struct bmp_peer *bmpp, ParsedBmp *parsed_bmp) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  struct bmp_data bdata = { 0 };

  /* TLV vars */
  struct bmp_tlv_hdr *bth;
  u_int16_t bmp_tlv_type, bmp_tlv_len;
  char *bmp_tlv_value;
  struct cdada_list_t *tlvs = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));

  tlvs = bmp_tlv_list_new_v2();
  if (!tlvs) return;

  BmpTlvListResult tlv_result = netgauze_bmp_get_tlvs(parsed_bmp->message);
  if (tlv_result.tag == CResult_Err) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [init] netgauze_bmp_get_tlvs failed.\n", config.name, bms->log_str,
        peer->addr_str);
    return;
  }

  OwnedSlice_bmp_log_tlv tlv_slice = tlv_result.ok;

  for (struct bmp_log_tlv *tlv = tlv_slice.base_ptr; tlv && tlv < tlv_slice.end_ptr; tlv += 1) {
    if (bmp_tlv_list_add_v2(tlvs, tlv->pen, tlv->type, tlv->len, tlv->index, tlv->val) == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [init] bmp_tlv_list_add() failed.\n", config.name, bms->log_str,
          peer->addr_str);
      exit_gracefully(1);
    }
  }

  /* Init message does not contain a timestamp */
  gettimeofday(&bdata.tstamp_arrival, NULL);
  memset(&bdata.tstamp, 0, sizeof(struct timeval));

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, tlvs, &bmp_logdump_tag, NULL, bgp_peer_log_seq_get(&bms->log_seq), event_type,
                config.bmp_daemon_msglog_output, BMP_LOG_TYPE_INIT);
  }

  if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, NULL, BMP_LOG_TYPE_INIT);

  if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

  if (!cdada_list_size(tlvs) || !bms->dump_backend_methods) bmp_tlv_list_destroy_v2(tlvs);
}

void ng_bmp_process_msg_term(struct bmp_peer *bmpp, const ParsedBmp *parsed_bmp) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  struct bmp_data bdata = { 0 };

  /* TLV vars */
  struct bmp_tlv_hdr *bth;
  u_int16_t bmp_tlv_type, bmp_tlv_len;
  char *bmp_tlv_value;
  struct cdada_list_t *tlvs = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));

  tlvs = bmp_tlv_list_new_v2();
  if (!tlvs) return;

  /* Term message does not contain a timestamp */
  gettimeofday(&bdata.tstamp_arrival, NULL);
  memset(&bdata.tstamp, 0, sizeof(struct timeval));

  tlvs = bmp_tlv_list_new_v2();
  if (!tlvs) return;

  BmpTlvListResult tlv_result = netgauze_bmp_get_tlvs(parsed_bmp->message);
  if (tlv_result.tag == CResult_Err) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [init] netgauze_bmp_get_tlvs failed.\n", config.name, bms->log_str,
        peer->addr_str);
    return;
  }

  OwnedSlice_bmp_log_tlv tlv_slice = tlv_result.ok;

  for (struct bmp_log_tlv *tlv = tlv_slice.base_ptr; tlv && tlv < tlv_slice.end_ptr; tlv += 1) {
    if (bmp_tlv_list_add_v2(tlvs, tlv->pen, tlv->type, tlv->len, tlv->index, tlv->val) == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [init] bmp_tlv_list_add() failed.\n", config.name, bms->log_str,
          peer->addr_str);
      exit_gracefully(1);
    }
  }

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, tlvs, &bmp_logdump_tag, NULL, bgp_peer_log_seq_get(&bms->log_seq), event_type,
                config.bmp_daemon_msglog_output, BMP_LOG_TYPE_TERM);
  }

  if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, NULL, BMP_LOG_TYPE_TERM);

  if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

  if (!cdada_list_size(tlvs) || !bms->dump_backend_methods) bmp_tlv_list_destroy_v2(tlvs);

  CSlice_free_bmp_log_tlv(tlv_slice);

  /* BGP peers are deleted as part of bmp_peer_close() */
}

void ng_bmp_process_msg_route_mirror(struct bmp_peer *bmpp) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  Log(LOG_INFO,
      "INFO ( %s/%s ): [%s] [route mirror] packet discarded: Unicorn! Message type currently not supported.\n",
      config.name, bms->log_str, peer->addr_str);

  // XXX: maybe support route mirroring
}

int bmp_peer_init_hook(struct bmp_peer *bmpp, int type)
{
  Log(LOG_INFO, "INFO ( %s/%s ): [%s] INITIALIZING BMP WITH NETGAUZE.\n",
            config.name, "xxx", "dynlib");
  int ret;

  if (!bmpp) return ERR;
  // TODO : CHECK IF THE NEXT 2 LINES CAN BE REMOVED SAFELY
  Opaque_BmpParsingContext *bpc = bmp_parsing_context_get(bmpp);
  if (!bpc) return ERR;

  ret = bgp_peer_init(&bmpp->self, type, BGP_BUFFER_SIZE);
  log_notification_init(&bmpp->missing_peer_up);

  
  return ret;
}



void bmp_peer_close_hook(struct bmp_peer *bmpp, int type)
{
  Log(LOG_INFO, "INFO ( %s/%s ): [%s] CLOSING BMP WITH NETGAUZE.\n",
            config.name, "xxx", "yyy");
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  bmp_parsing_context_clear(bmpp);

  pm_twalk(bmpp->bgp_peers_v4, bgp_peers_bintree_walk_delete, NULL);
  pm_twalk(bmpp->bgp_peers_v6, bgp_peers_bintree_walk_delete, NULL);

  pm_tdestroy(&bmpp->bgp_peers_v4, bgp_peer_free);
  pm_tdestroy(&bmpp->bgp_peers_v6, bgp_peer_free);

  if (bms->dump_file || bms->dump_amqp_routing_key || bms->dump_kafka_topic) {
    bmp_dump_close_peer(peer);
  }

  bgp_peer_close(peer, type, FALSE, FALSE, FALSE, FALSE, NULL);
}