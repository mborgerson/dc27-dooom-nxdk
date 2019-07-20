#include "lwip/debug.h"
#include "lwip/dhcp.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"
#include "lwip/timers.h"
#include "netif/etharp.h"
#include "pktdrv.h"
#include <hal/input.h>
#include <hal/xbox.h>
#include <pbkit/pbkit.h>
#include <xboxkrnl/xboxkrnl.h>
#include <debug.h>
#include <string.h>
#include <lwip/opt.h>
#include <lwip/arch.h>
#include <lwip/api.h>
// #include <stdio.h>
#include <assert.h>

#define USE_DHCP     0
#define DEBUGGING    0
#define HTTPD_DEBUG  LWIP_DBG_OFF

struct netif nforce_netif, *g_pnetif;
err_t nforceif_init(struct netif *netif);

static void tcpip_init_done(void *arg)
{
    sys_sem_t *init_complete = arg;
    sys_sem_signal(init_complete);
}

static void init_networking(void)
{
    sys_sem_t init_complete;
    const ip4_addr_t *ip;
    static ip4_addr_t ipaddr, netmask, gw;

#if DEBUGGING
    // asm volatile ("jmp .");
    debug_flags = LWIP_DBG_ON;
#else
    debug_flags = 0;
#endif

#if USE_DHCP
    IP4_ADDR(&gw, 0,0,0,0);
    IP4_ADDR(&ipaddr, 0,0,0,0);
    IP4_ADDR(&netmask, 0,0,0,0);
#else
    IP4_ADDR(&gw, 192,168,1,1);
    IP4_ADDR(&ipaddr, 192,168,1,2);
    IP4_ADDR(&netmask, 255,255,255,0);
#endif

    /* Initialize the TCP/IP stack. Wait for completion. */
    sys_sem_new(&init_complete, 0);
    tcpip_init(tcpip_init_done, &init_complete);
    sys_sem_wait(&init_complete);
    sys_sem_free(&init_complete);

    g_pnetif = netif_add(&nforce_netif, &ipaddr, &netmask, &gw,
                         NULL, nforceif_init, ethernet_input);
    if (!g_pnetif) {
        debugPrint("netif_add failed\n");
        return;
    }

    netif_set_default(g_pnetif);
    netif_set_up(g_pnetif);

#if USE_DHCP
    dhcp_start(g_pnetif);
    debugPrint("Waiting for DHCP...\n");
    while (g_pnetif->dhcp->state != DHCP_STATE_BOUND) {
        NtYieldExecution();
    }
    debugPrint("DHCP bound!\n");
#endif

    debugPrint("IP address.. %s\n", ip4addr_ntoa(netif_ip4_addr(g_pnetif)));
    debugPrint("Mask........ %s\n", ip4addr_ntoa(netif_ip4_netmask(g_pnetif)));
    debugPrint("Gateway..... %s\n", ip4addr_ntoa(netif_ip4_gw(g_pnetif)));
}

static int send_packet(struct netconn *conn, void *data, size_t len, const ip_addr_t *addr, u16_t port)
{
    err_t err;
    struct netbuf *outbuf = NULL;
    int status = 0;

    outbuf = netbuf_new();
    assert(outbuf != NULL);

    char *intermediate = netbuf_alloc(outbuf, len + 10);
    assert(intermediate != NULL);

    memcpy(intermediate, "You Said: ", 10);
    memcpy(intermediate+10, data, len);

    err = netconn_sendto(conn, outbuf, addr, port);
    if(err != ERR_OK) {
        status = 1;
    }

    netbuf_delete(outbuf);
    return status;
}

static int recv_packet(struct netconn *conn)
{
    struct netbuf *buf = NULL;
    char *data;
    u16_t data_len;
    err_t err;
    ip_addr_t *naddr;
    u16_t port;

    int status = 0;

    err = netconn_recv(conn, &buf);
    if (err != ERR_OK) goto exit;

    err = netbuf_data(buf, (void**)&data, &data_len);
    if (err != ERR_OK) goto exit;

    naddr = netbuf_fromaddr(buf);
    port = netbuf_fromport(buf);

    debugPrint("[from %s, %d bytes] ", ip4addr_ntoa(ip_2_ip4(naddr)), data_len);
    for (int i = 0; i < data_len; i++) {
        debugPrint("%c", data[i]);
    }

    if (memcmp("quit", data, 4) == 0) {
        HalReturnToFirmware(HalQuickRebootRoutine);
    }

    send_packet(conn, data, data_len, naddr, port);
    status = 1;

exit:
    if (buf) netbuf_delete(buf);
    return status;
}

static void service(void *arg)
{
    struct netconn *conn, *newconn;
    err_t err;
    LWIP_UNUSED_ARG(arg);

    /* Create a new TCP connection handle */
    conn = netconn_new(NETCONN_UDP);
    LWIP_ERROR("http_server: invalid conn", (conn != NULL), return;);

    netconn_bind(conn, NULL, 5555);

    // Apparently non-blocking recv is broke. Use 1ms timeout instead
    netconn_set_recvtimeout(conn, 1);
    // netconn_set_nonblocking(conn, 1);

    do {
        Pktdrv_ReceivePackets();
        recv_packet(conn);
    } while(1);

    netconn_close(conn);
    netconn_delete(conn);
}

void main(void)
{

    pb_init();
    pb_show_debug_screen();
    init_networking();
    service(NULL);
    Pktdrv_Quit();
    return;
}
