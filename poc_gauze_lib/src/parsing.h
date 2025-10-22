


extern int bgp_parse_msg(struct bgp_peer *, time_t, int);

extern u_int32_t bmp_process_packet(char *, u_int32_t, struct bmp_peer *, int *);
extern int bmp_peer_init(struct bmp_peer *, int);
extern void bmp_peer_close(struct bmp_peer *, int);

int ng_bgp_process_msg_open(struct bgp_msg_data *bmd, const Opaque_BgpMessage *bgp_msg, time_t now, int online);
int ng_bgp_process_msg_notif(struct bgp_msg_data *bmd, const Opaque_BgpMessage *bgp_msg);
int ng_bgp_process_msg_keepalive(struct bgp_msg_data *bmd, const Opaque_BgpMessage *bgp_msg, time_t now, bool online);
int ng_bgp_process_msg_update(struct bgp_msg_data *bmd, const Opaque_BgpMessage *bgp_msg);
int process_update_packets(struct bgp_msg_data *bmd, struct bgp_misc_structs *bms, struct bgp_peer *peer, ParsedBgpUpdate bgp_parsed);
void bmp_parsing_context_clear(struct bmp_peer *bmp_peer);
Opaque_BmpParsingContext *bmp_parsing_context_get(struct bmp_peer *bmp_peer);
Opaque_BmpContextCache *bmp_context_cache_get();
void ng_bmp_process_msg_route_monitor(struct bmp_peer *bmpp, const ParsedBmp *netgauze_parsed);
void ng_bmp_process_msg_stats(struct bmp_peer *bmpp, const ParsedBmp *parsed_bmp);
void ng_bmp_process_msg_peer_down(struct bmp_peer *bmpp, const ParsedBmp *parsed_bmp);
void ng_bmp_process_msg_peer_up(struct bmp_peer *bmpp, const ParsedBmp *netgauze_parsed);
void ng_bmp_process_msg_init(struct bmp_peer *bmpp, ParsedBmp *parsed_bmp);
void ng_bmp_process_msg_term(struct bmp_peer *bmpp, const ParsedBmp *parsed_bmp);
void ng_bmp_process_msg_route_mirror(struct bmp_peer *bmpp); 